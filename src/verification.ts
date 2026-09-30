import {
  importSPKI,
  importJWK,
  jwtVerify,
  decodeJwt,
  decodeProtectedHeader,
  createLocalJWKSet,
  calculateJwkThumbprint,
  SignJWT,
  type JWK,
  type KeyLike,
} from 'jose';
import { DEFAULT_BROKER_URL } from './constants.js';
import { extractConsentToken, type ReadParafeOptions } from './message.js';
import {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  WrongAudienceError,
  InvalidProofError,
} from './errors.js';
import type {
  A2AMessageLike,
  BrokerKeys,
  JsonWebKeyLike,
  ParafeConsentClaims,
  ScopeRequirement,
  VerifyConsentOptions,
  VerifyMessageOptions,
  VerifyOnlineOptions,
} from './types.js';

/**
 * Verifies a Parafe consent token offline against the broker's keys.
 * No network call required — verification uses only the keys and the token.
 *
 * This is the recommended verification path for most A2A agents. Fetch the
 * broker's keys once at startup (or cache them) via fetchBrokerKeys(), then call
 * this function on every incoming request. Since 2026-09-30 the broker signs
 * ES256 and names its key (`kid`); a PEM Ed25519 key from fetchBrokerPublicKey()
 * still verifies tokens issued before that.
 *
 * Validates:
 * - The broker's signature is valid (ES256 by kid, or EdDSA)
 * - Token has not expired
 * - Issuer is "parafe-trust-broker"
 * - Token type is "consent"
 * - With options: token issued for `agentId`, belongs to `sessionId`, permits `action`,
 *   and fits `scopeRequirements` (see VerifyConsentOptions)
 *
 * @param token - The consent token JWT string
 * @param brokerPublicKey - The broker's Ed25519 public key in PEM format (from fetchBrokerPublicKey)
 * @param options - Extra checks, or just the action that must be permitted
 */
export async function verifyConsentTokenOffline(
  token: string,
  brokerKeys: BrokerKeys | string,
  options: VerifyConsentOptions | string = {}
): Promise<ParafeConsentClaims> {
  const checks: VerifyConsentOptions = typeof options === 'string' ? { action: options } : options;
  let claims: ParafeConsentClaims;

  try {
    let payload: Record<string, unknown>;
    if (typeof brokerKeys === 'string') {
      // Legacy: the broker's Ed25519 key as PEM. Tokens since 2026-09-30 are ES256.
      if (safeHeaderAlg(token) === 'ES256') {
        throw new Error('this token is ES256 (broker 2026-09-30+); pass fetchBrokerKeys() instead of a PEM public key');
      }
      const publicKey = await importSPKI(brokerKeys, 'EdDSA');
      ({ payload } = await jwtVerify(token, publicKey, { algorithms: ['EdDSA'], issuer: 'parafe-trust-broker' }));
    } else {
      const keySet = createLocalJWKSet(brokerKeys as unknown as { keys: JWK[] });
      ({ payload } = await jwtVerify(token, keySet, { algorithms: ['ES256', 'EdDSA'], issuer: 'parafe-trust-broker' }));
    }
    claims = payload as unknown as ParafeConsentClaims;
  } catch (err) {
    if (err instanceof Error) {
      if (err.name === 'JWTExpired') {
        const decoded = decodeJwt(token);
        throw new ExpiredConsentTokenError(new Date((decoded['exp'] as number) * 1000));
      }
      throw new InvalidConsentTokenError(err.message);
    }
    throw new InvalidConsentTokenError();
  }

  // N-04: Runtime type guards — validate critical claim types before trusting the cast.
  if (typeof claims.scope !== 'string') {
    throw new InvalidConsentTokenError(
      `Expected "scope" claim to be a string, got ${typeof claims.scope}`
    );
  }
  if (!Array.isArray(claims.permissions)) {
    throw new InvalidConsentTokenError(
      `Expected "permissions" claim to be an array, got ${typeof claims.permissions}`
    );
  }
  if (typeof claims.session_id !== 'string') {
    throw new InvalidConsentTokenError(
      `Expected "session_id" claim to be a string, got ${typeof claims.session_id}`
    );
  }
  if (claims.token_type !== 'consent') {
    throw new InvalidConsentTokenError(
      `Expected token_type "consent", got "${String(claims.token_type)}"`
    );
  }

  // Consent token v2 names the claim `exclusions`; older tokens `excluded`. Set both.
  const exclusions: unknown = claims.exclusions ?? claims.excluded ?? [];
  if (!Array.isArray(exclusions)) {
    throw new InvalidConsentTokenError(
      `Expected "exclusions" claim to be an array, got ${typeof exclusions}`
    );
  }
  claims.exclusions = exclusions as string[];
  claims.excluded = (claims.excluded ?? exclusions) as string[];

  if (checks.agentId !== undefined && claims.target_agent_id !== checks.agentId) {
    throw new WrongAudienceError(checks.agentId, claims.target_agent_id ?? null);
  }
  if (checks.sessionId !== undefined && claims.session_id !== checks.sessionId) {
    throw new InvalidConsentTokenError(
      `token belongs to session "${claims.session_id}", but the message says "${checks.sessionId}"`
    );
  }
  if (checks.scopeRequirements !== undefined) {
    assertWithinPolicy(claims, checks.scopeRequirements);
  }
  if (checks.action !== undefined) {
    assertPermission(checks.action, claims.permissions, claims.exclusions);
  }

  return claims;
}

function safeHeaderAlg(token: string): string | undefined {
  try {
    return decodeProtectedHeader(token).alg;
  } catch {
    return undefined;
  }
}

/**
 * Verifies a Parafe consent token online via the Parafe broker's /consent/verify endpoint.
 * Use this when you need real-time confirmation from the broker (e.g., for high-value actions).
 *
 * The broker's /consent/verify endpoint requires consent_token, action, and session_id.
 * If sessionId is not provided in options, it is extracted from the token's claims.
 */
export async function verifyConsentTokenOnline(
  token: string,
  options: VerifyOnlineOptions
): Promise<ConsentVerifyResult> {
  const brokerUrl = options.brokerUrl ?? DEFAULT_BROKER_URL;

  // N-06: Warn when broker URL is not HTTPS (except localhost for dev).
  if (
    !brokerUrl.startsWith('https://') &&
    !brokerUrl.startsWith('http://localhost') &&
    !brokerUrl.startsWith('http://127.0.0.1')
  ) {
    console.warn(
      `[parafe] Broker URL "${brokerUrl}" does not use HTTPS. ` +
        'Online consent verification is being sent over an unencrypted connection.'
    );
  }

  let sessionId = options.sessionId;
  if (sessionId === undefined) {
    try {
      const decoded = decodeJwt(token);
      sessionId = decoded['session_id'] as string | undefined;
    } catch {
      // If we can't decode, let the broker reject it
    }
  }

  if (sessionId === undefined) {
    throw new InvalidConsentTokenError(
      'session_id is required for online verification. Provide it in options or ensure the token contains a session_id claim.'
    );
  }

  let response: Response;
  try {
    response = await fetch(`${brokerUrl}/consent/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        consent_token: token,
        action: options.action,
        session_id: sessionId,
        ...(options.proof ? { proof: options.proof } : {}),
      }),
    });
  } catch (err) {
    throw new InvalidConsentTokenError(
      `Could not reach Parafe broker at ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  const body = await response.json().catch(() => ({})) as Record<string, unknown>;

  if (!response.ok) {
    const reason = typeof body['reason'] === 'string' ? body['reason'] : response.statusText;
    if (body['error'] === 'proof_invalid') throw new InvalidProofError(reason);
    if (reason.toLowerCase().includes('expired')) {
      throw new ExpiredConsentTokenError(new Date());
    }
    throw new InvalidConsentTokenError(body['error'] === 'agent_revoked' ? `agent revoked: ${reason}` : reason);
  }

  if (body['valid'] === true && body['permitted'] === false) {
    const reason = typeof body['reason'] === 'string' ? body['reason'] : 'Action not permitted';
    throw new ScopeViolationError(options.action, [reason]);
  }

  // Validate required fields in broker response
  if (typeof body['valid'] !== 'boolean' || typeof body['permitted'] !== 'boolean' || typeof body['action'] !== 'string') {
    throw new InvalidConsentTokenError(
      `Unexpected response from broker /consent/verify — missing or invalid fields (valid: ${typeof body['valid']}, permitted: ${typeof body['permitted']}, action: ${typeof body['action']})`
    );
  }

  if (options.agentId !== undefined) {
    let target: unknown;
    try {
      target = decodeJwt(token)['target_agent_id'];
    } catch {
      target = undefined;
    }
    if (target !== options.agentId) {
      throw new WrongAudienceError(options.agentId, typeof target === 'string' ? target : null);
    }
  }

  return {
    valid: body['valid'],
    permitted: body['permitted'],
    action: body['action'],
    sessionId: typeof body['session_id'] === 'string' ? body['session_id'] : sessionId,
    expiresAt: typeof body['expires_at'] === 'string' ? body['expires_at'] : undefined,
    keyBound: body['key_bound'] === true,
    proofVerified: body['proof_verified'] === true,
  };
}

/** Result from the broker's /consent/verify endpoint. */
export interface ConsentVerifyResult {
  valid: boolean;
  permitted: boolean;
  action: string;
  sessionId: string;
  expiresAt?: string | undefined;
  /** The token is bound to the initiator's key (cnf.jkt). */
  keyBound?: boolean;
  /** A presentation proof was sent and the broker checked it. */
  proofVerified?: boolean;
}

/**
 * Fetches the broker's signing keys (its JWKS, at /.well-known/jwks.json) for
 * verifyConsentTokenOffline() and verifyMessageConsentToken(). Call once at
 * startup and cache. On a broker from before 2026-09-30 (no JWKS) it returns
 * that broker's single Ed25519 key.
 */
export async function fetchBrokerKeys(brokerUrl: string = DEFAULT_BROKER_URL): Promise<BrokerKeys> {
  let response: Response;
  try {
    response = await fetch(`${brokerUrl}/.well-known/jwks.json`);
  } catch (err) {
    throw new Error(`Could not fetch Parafe broker keys from ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (response.status === 404) {
    const pem = await fetchBrokerPublicKey(brokerUrl);
    const spki = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s/g, '');
    const raw = Uint8Array.from(atob(spki), (c) => c.charCodeAt(0)).slice(-32);
    const x = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { keys: [{ kty: 'OKP', crv: 'Ed25519', x, kid: 'legacy-ed25519', alg: 'EdDSA' }] };
  }
  if (!response.ok) {
    throw new Error(`Parafe broker returned ${response.status} when fetching its keys from ${brokerUrl}`);
  }
  const body = (await response.json()) as BrokerKeys;
  if (!body || !Array.isArray(body.keys)) {
    throw new Error('Unexpected response shape from Parafe broker /.well-known/jwks.json — expected "keys"');
  }
  return body;
}

/**
 * Fetches the Parafe broker's legacy Ed25519 public key (PEM). It verifies tokens
 * issued before 2026-09-30. For current tokens use fetchBrokerKeys().
 *
 * The broker returns the key as base64-encoded SPKI DER. This function converts it
 * to PEM format, which is what jose's importSPKI() expects.
 */
export async function fetchBrokerPublicKey(
  brokerUrl: string = DEFAULT_BROKER_URL
): Promise<string> {
  let response: Response;
  try {
    response = await fetch(`${brokerUrl}/public-key`);
  } catch (err) {
    throw new Error(
      `Could not fetch Parafe broker public key from ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!response.ok) {
    throw new Error(
      `Parafe broker returned ${response.status} when fetching public key from ${brokerUrl}`
    );
  }

  const body = await response.json() as Record<string, unknown>;
  const publicKeyBase64 = body['public_key'];

  if (typeof publicKeyBase64 !== 'string') {
    throw new Error(
      'Unexpected response shape from Parafe broker /public-key endpoint — expected "public_key" field'
    );
  }

  return derBase64ToPem(publicKeyBase64);
}

/**
 * Extracts and verifies the consent token from an A2A message in one step:
 * reads the Parafe data (see readParafe), verifies the token offline, and checks that
 * it was issued for `agentId`, belongs to the session the message names, and permits
 * `action` (if given).
 *
 * Throws MissingParafeExtensionError if the message carries no consent token.
 *
 * @example
 * const { claims, sessionId } = await verifyMessageConsentToken(ctx.userMessage, brokerPublicKey, {
 *   agentId: MY_AGENT_ID,
 *   action: 'create_order',
 *   scopeRequirements: MY_SCOPES,
 * });
 */
export async function verifyMessageConsentToken(
  message: A2AMessageLike & { messageId?: unknown },
  brokerKeys: BrokerKeys | string,
  options: VerifyMessageOptions & ReadParafeOptions
): Promise<{ claims: ParafeConsentClaims; sessionId: string; proofVerified: boolean }> {
  const { acceptV1, requireProof, initiatorKey, brokerUrl, ...checks } = options;
  const consent = extractConsentToken(message, acceptV1 === undefined ? {} : { acceptV1 });
  if (consent === null) {
    throw new MissingParafeExtensionError('No Parafe consent token found in the message.');
  }

  const claims = await verifyConsentTokenOffline(consent.token, brokerKeys, {
    ...checks,
    sessionId: consent.session_id,
  });

  // Key binding (2.1): the token must be presented by the key it names.
  let proofVerified = false;
  if (consent.proof !== undefined) {
    await verifyPresentationProof(consent.proof, consent.token, claims, {
      ...(initiatorKey ? { initiatorKey } : {}),
      ...(brokerUrl ? { brokerUrl } : {}),
      ...(typeof message.messageId === 'string' ? { messageId: message.messageId } : {}),
    });
    proofVerified = true;
  } else if (requireProof) {
    throw new InvalidProofError('this agent requires a presentation proof with the consent token');
  }

  return { claims, sessionId: consent.session_id, proofVerified };
}

// ---------------------------------------------------------------------------
// Presentation proofs (key-bound consent tokens, 2.1)
// ---------------------------------------------------------------------------

const POP_TYP = 'parafe-pop+jwt';
const PROOF_MAX_AGE_SECONDS = 5 * 60;

/** Proof jtis seen in the last few minutes (per process): a proof is single-use. */
const seenProofs = new Map<string, number>();
function claimProofJti(jti: string): boolean {
  const now = Date.now();
  if (seenProofs.size > 10_000) for (const [k, exp] of seenProofs) if (exp <= now) seenProofs.delete(k);
  const exp = seenProofs.get(jti);
  if (exp !== undefined && exp > now) return false;
  seenProofs.set(jti, now + (PROOF_MAX_AGE_SECONDS + 60) * 1000);
  return true;
}

/** Initiator keys fetched from DID documents, by agent ID (10 minutes). */
const didKeyCache = new Map<string, { jwk: JsonWebKeyLike; at: number }>();
async function initiatorJwk(agentId: string, brokerUrl: string): Promise<JsonWebKeyLike> {
  const cached = didKeyCache.get(agentId);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.jwk;
  let res: Response;
  try {
    res = await fetch(`${brokerUrl}/agents/${encodeURIComponent(agentId)}/did.json`);
  } catch (err) {
    throw new InvalidProofError(`could not fetch the initiator's DID document: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!res.ok) throw new InvalidProofError(`the initiator's DID document is unavailable (${res.status}); is the agent revoked?`);
  const doc = (await res.json()) as { verificationMethod?: Array<{ publicKeyJwk?: JsonWebKeyLike }> };
  const jwk = doc.verificationMethod?.[0]?.publicKeyJwk;
  if (!jwk) throw new InvalidProofError("the initiator's DID document has no public key");
  didKeyCache.set(agentId, { jwk, at: Date.now() });
  return jwk;
}

function b64url(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Checks a presentation proof against a verified consent token: signed by the
 * key in `cnf.jkt`, for this token (`ath`), for the token's audience (`aud`),
 * fresh (5 minutes), not seen before, and for this message (`mid`, when given).
 * Throws InvalidProofError.
 */
export async function verifyPresentationProof(
  proof: string,
  token: string,
  claims: ParafeConsentClaims,
  options: { initiatorKey?: JsonWebKeyLike; brokerUrl?: string; messageId?: string } = {}
): Promise<void> {
  const jkt = claims.cnf?.jkt;
  if (!jkt) throw new InvalidProofError('the consent token is not key-bound (issued before 2026-09-30)');
  const initiator = claims.sub ?? claims.initiator_agent_id;
  if (!initiator) throw new InvalidProofError('the consent token names no initiator');
  const jwk = options.initiatorKey ?? (await initiatorJwk(initiator, options.brokerUrl ?? DEFAULT_BROKER_URL));
  if ((await calculateJwkThumbprint(jwk as JWK)) !== jkt) {
    throw new InvalidProofError("the initiator's key is not the one the token is bound to");
  }
  const alg = jwk.kty === 'EC' ? 'ES256' : 'EdDSA';
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(proof, await importJWK(jwk as JWK, alg), {
      typ: POP_TYP,
      algorithms: [alg],
      maxTokenAge: PROOF_MAX_AGE_SECONDS,
      clockTolerance: 60,
    }));
  } catch (err) {
    throw new InvalidProofError(err instanceof Error ? err.message : String(err));
  }
  const ath = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  if (payload['ath'] !== ath) throw new InvalidProofError('the proof is for a different token');
  if (payload['aud'] !== claims.aud) throw new InvalidProofError('the proof is for a different audience');
  if (options.messageId !== undefined && payload['mid'] !== undefined && payload['mid'] !== options.messageId) {
    throw new InvalidProofError('the proof is for a different message');
  }
  if (typeof payload['jti'] !== 'string' || (payload['jti'] as string).length < 16) {
    throw new InvalidProofError('the proof needs a random jti');
  }
  if (!claimProofJti(`${initiator}:${payload['jti'] as string}`)) {
    throw new InvalidProofError('the proof was already used');
  }
}

/**
 * Initiator side: the presentation proof to send with a consent token
 * (`withConsentToken(message, token, sessionId, proof)`). Signed with the
 * agent's private key (a Node KeyObject or WebCrypto CryptoKey; Ed25519 or
 * P-256), bound to this token, its audience and optionally the A2A message ID.
 */
export async function createPresentationProof(
  token: string,
  privateKey: KeyLike,
  options: { messageId?: string } = {}
): Promise<string> {
  const aud = decodeJwt(token).aud;
  if (typeof aud !== 'string') {
    throw new InvalidConsentTokenError('this token has no audience (issued before 2026-09-30); no proof applies');
  }
  const k = privateKey as unknown as { asymmetricKeyType?: string; algorithm?: { name?: string } };
  const alg = k.asymmetricKeyType === 'ec' || k.algorithm?.name === 'ECDSA' ? 'ES256' : 'EdDSA';
  const ath = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  return new SignJWT({ ath, aud, jti: crypto.randomUUID(), ...(options.messageId ? { mid: options.messageId } : {}) })
    .setProtectedHeader({ alg, typ: POP_TYP })
    .setIssuedAt()
    .sign(privateKey);
}

function derBase64ToPem(base64: string): string {
  if (!/^[A-Za-z0-9+/]+=*$/.test(base64)) {
    throw new Error('Invalid base64 encoding in public key');
  }
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

function assertPermission(
  action: string,
  permissions: string[],
  excluded: string[]
): void {
  if (excluded.includes(action)) {
    throw new ScopeViolationError(action, permissions);
  }
  if (!permissions.includes(action)) {
    throw new ScopeViolationError(action, permissions);
  }
}

const MODALITY_RANK = { autonomous: 0, attested: 1, verified: 2 } as const;

function assertWithinPolicy(
  claims: ParafeConsentClaims,
  scopeRequirements: Record<string, ScopeRequirement>
): void {
  const scope = Object.prototype.hasOwnProperty.call(scopeRequirements, claims.scope)
    ? scopeRequirements[claims.scope]
    : undefined;
  if (scope === undefined) {
    throw new ScopeViolationError(claims.scope, Object.keys(scopeRequirements),
      `Consent token is for scope "${claims.scope}", which this agent does not declare.`);
  }
  const outside = claims.permissions.filter((p) => !scope.permissions.includes(p));
  if (outside.length > 0) {
    throw new ScopeViolationError(outside, scope.permissions,
      `Consent token grants permissions outside scope "${claims.scope}": ${outside.join(', ')}.`);
  }
  const have = MODALITY_RANK[claims.authorization_modality];
  const need = MODALITY_RANK[scope.minimum_authorization_modality];
  if (have === undefined || have < need) {
    throw new ScopeViolationError(claims.scope, claims.permissions,
      `Scope "${claims.scope}" requires "${scope.minimum_authorization_modality}" authorization, token has "${String(claims.authorization_modality)}".`);
  }
  if (scope.minimum_initiator_proof === 'pop' && claims.initiator_proof !== 'pop') {
    throw new ScopeViolationError(claims.scope, claims.permissions,
      `Scope "${claims.scope}" requires the initiator to have proved it holds its key, token says "${String(claims.initiator_proof ?? 'unknown')}".`);
  }
}
