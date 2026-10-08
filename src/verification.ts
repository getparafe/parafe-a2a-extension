import {
  importJWK,
  jwtVerify,
  decodeJwt,
  createLocalJWKSet,
  calculateJwkThumbprint,
  SignJWT,
  type JWK,
  type KeyLike,
} from 'jose';
import { DEFAULT_BROKER_URL } from './constants.js';
import { extractConsentToken } from './message.js';
import type { ActionReceiptInput, RecordedActionReceipt } from './action-receipts.js';
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
 * this function on every incoming request. The broker signs ES256 and names its
 * key (`kid`).
 *
 * Validates:
 * - The broker's signature is valid (ES256, by kid)
 * - Token has not expired
 * - Issuer is "parafe-trust-broker"
 * - Token type is "consent"
 * - With options: token issued for `agentId`, belongs to `sessionId`, permits `action`,
 *   and fits `scopeRequirements` (see VerifyConsentOptions)
 *
 * @param token - The consent token JWT string
 * @param brokerKeys - The broker's JWKS (fetchBrokerKeys()) or a key cache (createBrokerKeyCache())
 * @param options - Extra checks, or just the action that must be permitted
 */
export async function verifyConsentTokenOffline(
  token: string,
  brokerKeys: BrokerKeys | BrokerKeyCache,
  options: VerifyConsentOptions | string = {}
): Promise<ParafeConsentClaims> {
  const checks: VerifyConsentOptions = typeof options === 'string' ? { action: options } : options;
  let claims: ParafeConsentClaims;

  try {
    let payload: Record<string, unknown>;
    if (isBrokerKeyCache(brokerKeys)) {
      // Keys that refresh themselves: a token naming a key the cache doesn't
      // have yet (the broker added one) triggers one refetch, then a retry.
      const verifyWith = async (keys: BrokerKeys) =>
        jwtVerify(token, createLocalJWKSet(keys as unknown as { keys: JWK[] }), { algorithms: ['ES256'], issuer: 'parafe-trust-broker' });
      try {
        ({ payload } = await verifyWith(await brokerKeys.get()));
      } catch (err) {
        const refreshed = (err as { code?: string }).code === 'ERR_JWKS_NO_MATCHING_KEY' ? await brokerKeys.refresh() : null;
        if (!refreshed) throw err;
        ({ payload } = await verifyWith(refreshed));
      }
    } else {
      if (typeof brokerKeys !== 'object' || brokerKeys === null || !Array.isArray((brokerKeys as BrokerKeys).keys)) {
        throw new TypeError('brokerKeys must be the broker JWKS (fetchBrokerKeys()) or createBrokerKeyCache()');
      }
      const keySet = createLocalJWKSet(brokerKeys as unknown as { keys: JWK[] });
      ({ payload } = await jwtVerify(token, keySet, { algorithms: ['ES256'], issuer: 'parafe-trust-broker' }));
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

  if (!Array.isArray(claims.exclusions)) {
    throw new InvalidConsentTokenError(
      `Expected "exclusions" claim to be an array, got ${typeof claims.exclusions}`
    );
  }

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
    response = await fetch(`${trimSlash(brokerUrl)}/consent/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        consent_token: token,
        action: options.action,
        session_id: sessionId,
        // The verifying agent: the broker refuses a token issued for another one (wrong_audience).
        ...(options.agentId !== undefined ? { agent_id: options.agentId } : {}),
        ...(options.proof ? { proof: options.proof } : {}),
      }),
    });
  } catch (err) {
    throw new InvalidConsentTokenError(
      `Could not reach Parafe broker at ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`,
      ''
    );
  }

  const body = await response.json().catch(() => ({})) as Record<string, unknown>;

  if (!response.ok) {
    throw onlineRefusal(token, body, response, options.agentId);
  }

  if (body['valid'] === true && body['permitted'] === false) {
    const reason = typeof body['reason'] === 'string' ? body['reason'] : 'Action not permitted';
    throw new ScopeViolationError(options.action, [reason]);
  }

  // Validate required fields in broker response
  if (typeof body['valid'] !== 'boolean' || typeof body['permitted'] !== 'boolean' || typeof body['action'] !== 'string') {
    throw new InvalidConsentTokenError(
      `Unexpected response from broker /consent/verify — missing or invalid fields (valid: ${typeof body['valid']}, permitted: ${typeof body['permitted']}, action: ${typeof body['action']})`,
      ''
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

/**
 * The error for a refusal from POST /consent/verify, from the code the broker
 * names it with (`error`, on every refusal since 2026-10-08).
 */
function onlineRefusal(token: string, body: Record<string, unknown>, response: Response, agentId: string | undefined): Error {
  const reason = typeof body['reason'] === 'string' ? body['reason']
    : typeof body['message'] === 'string' ? body['message']
    : response.statusText || `HTTP ${response.status}`;
  const code = typeof body['error'] === 'string' ? body['error'] : undefined;
  const sentence = reason.replace(/\.?$/, '.');
  const claim = (name: string): unknown => {
    try {
      return decodeJwt(token)[name];
    } catch {
      return undefined;
    }
  };
  const expired = () => {
    const exp = claim('exp');
    return new ExpiredConsentTokenError(typeof exp === 'number' ? new Date(exp * 1000) : new Date());
  };

  switch (code) {
    case 'token_expired':
      return expired();
    case 'wrong_audience': {
      const target = claim('target_agent_id');
      return new WrongAudienceError(agentId ?? '(not given)', typeof target === 'string' ? target : null);
    }
    case 'proof_invalid':
      return new InvalidProofError(reason);
    case 'token_invalid': // bad signature, malformed, not a consent token
      return new InvalidConsentTokenError(sentence);
    case 'agent_revoked':
      return new InvalidConsentTokenError(`an agent in this session was revoked or suspended (${reason}).`, '');
    case 'session_inactive':
      return new InvalidConsentTokenError(`its session is closed or expired (${reason}).`, 'Start a new handshake.');
    case 'session_not_found':
      return new InvalidConsentTokenError(`the broker has no such session (${reason}).`, '');
    case 'session_mismatch':
      return new InvalidConsentTokenError(`it belongs to another session (${reason}).`, '');
    default: // validation_error, rate limits, internal errors
      return new InvalidConsentTokenError(`the broker refused to verify it (${response.status} ${code ?? 'no code'}: ${reason}).`, '');
  }
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

/** Broker keys that refresh themselves; from createBrokerKeyCache(). */
export interface BrokerKeyCache {
  /**
   * The broker the keys come from. verifyMessageConsentToken() fetches DID
   * documents from it when `brokerUrl` isn't given.
   */
  readonly brokerUrl?: string;
  /** The cached keys, fetched on first use. */
  get(): Promise<BrokerKeys>;
  /** Refetch now, unless the last fetch was under `minRefetchIntervalMs` ago (then null). */
  refresh(): Promise<BrokerKeys | null>;
}

function isBrokerKeyCache(value: unknown): value is BrokerKeyCache {
  return typeof value === 'object' && value !== null && typeof (value as BrokerKeyCache).refresh === 'function';
}

const trimSlash = (url: string) => url.replace(/\/+$/, '');

/** The broker a key set or key cache came from (fetchBrokerKeys / createBrokerKeyCache), when known. */
function brokerUrlOf(keys: BrokerKeys | BrokerKeyCache): string | undefined {
  const url = (keys as { brokerUrl?: unknown } | null)?.brokerUrl;
  return typeof url === 'string' && url !== '' ? url : undefined;
}

/**
 * The recommended way to hold the broker's keys in a long-running agent. Pass
 * it wherever broker keys are accepted. It fetches the JWKS on first use and,
 * when a token names a key it doesn't have (the broker rotated or added a key),
 * refetches once and retries, at most once per `minRefetchIntervalMs`
 * (default 60 s). A plain fetchBrokerKeys() result never updates.
 *
 * The cache remembers its broker (`brokerUrl`): verifyMessageConsentToken()
 * fetches initiators' DID documents from it unless told otherwise.
 */
export function createBrokerKeyCache(
  brokerUrl: string = DEFAULT_BROKER_URL,
  options: { minRefetchIntervalMs?: number } = {}
): BrokerKeyCache {
  brokerUrl = trimSlash(brokerUrl);
  const minInterval = options.minRefetchIntervalMs ?? 60_000;
  let keys: Promise<BrokerKeys> | null = null;
  let fetchedAt = 0;
  const load = () => {
    fetchedAt = Date.now();
    const p = fetchBrokerKeys(brokerUrl);
    p.catch(() => { if (keys === p) keys = null; }); // a failed fetch is retried next time
    keys = p;
    return p;
  };
  return {
    brokerUrl,
    get: () => keys ?? load(),
    async refresh() {
      if (Date.now() - fetchedAt < minInterval) return null;
      return load();
    },
  };
}

/**
 * Fetches the broker's signing keys (its JWKS, at /.well-known/jwks.json), once.
 * For a long-running agent prefer createBrokerKeyCache(), which also picks up
 * keys the broker adds later. The result remembers its broker (`brokerUrl`, not
 * enumerable), for verifyMessageConsentToken() to fetch DID documents from.
 */
export async function fetchBrokerKeys(brokerUrl: string = DEFAULT_BROKER_URL): Promise<BrokerKeys> {
  brokerUrl = trimSlash(brokerUrl);
  let response: Response;
  try {
    response = await fetch(`${brokerUrl}/.well-known/jwks.json`);
  } catch (err) {
    throw new Error(`Could not fetch Parafe broker keys from ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!response.ok) {
    throw new Error(`Parafe broker returned ${response.status} when fetching its keys from ${brokerUrl}`);
  }
  const body = (await response.json()) as BrokerKeys;
  if (!body || !Array.isArray(body.keys)) {
    throw new Error('Unexpected response shape from Parafe broker /.well-known/jwks.json — expected "keys"');
  }
  Object.defineProperty(body, 'brokerUrl', { value: brokerUrl, enumerable: false, configurable: true });
  return body;
}

/**
 * Extracts and verifies the consent token from an A2A message in one step:
 * reads the Parafe data (see readParafe), verifies the token offline, and checks that
 * it was issued for `agentId`, belongs to the session the message names, and permits
 * `action` (if given).
 *
 * The initiator's DID document (for the presentation proof) is fetched from
 * `options.brokerUrl`, else from the broker the keys came from
 * (fetchBrokerKeys(url) / createBrokerKeyCache(url)), else DEFAULT_BROKER_URL.
 *
 * Throws MissingParafeExtensionError if the message carries no consent token.
 *
 * @example
 * const { claims, sessionId } = await verifyMessageConsentToken(ctx.userMessage, brokerKeys, {
 *   agentId: MY_AGENT_ID,
 *   action: 'create_order',
 *   scopeRequirements: MY_SCOPES,
 * });
 */
export async function verifyMessageConsentToken(
  message: A2AMessageLike & { messageId?: unknown },
  brokerKeys: BrokerKeys | BrokerKeyCache,
  options: VerifyMessageOptions
): Promise<{
  claims: ParafeConsentClaims;
  sessionId: string;
  proofVerified: boolean;
  /** The consent token the message carried. */
  consentToken: string;
  /**
   * 2.2, with `receipts`: sign (and file) the action receipt for what you did.
   * Defaults: the checked `action`, result 'success'.
   */
  completeAction: (outcome?: Partial<Omit<ActionReceiptInput, 'sessionId' | 'consentToken'>>) => Promise<RecordedActionReceipt>;
}> {
  const { requireProof = true, initiatorKey, brokerUrl: brokerUrlOption, receipts, ...checks } = options;
  // DID documents come from the broker the keys came from, unless told otherwise.
  const brokerUrl = brokerUrlOption ?? brokerUrlOf(brokerKeys);
  if (receipts) warnOnBrokerMismatch(receipts, brokerUrl);
  const consent = extractConsentToken(message);
  if (consent === null) {
    throw new MissingParafeExtensionError('No Parafe consent token found in the message.');
  }

  let claims: ParafeConsentClaims;
  let proofVerified = false;
  try {
    claims = await verifyConsentTokenOffline(consent.token, brokerKeys, {
      ...checks,
      sessionId: consent.session_id,
    });

    // Key binding: the token must be presented by the key it names (required unless requireProof: false).
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
  } catch (err) {
    // 2.2: a refusal gets a receipt too, signed by the agent that refused.
    if (receipts && checks.action !== undefined && err instanceof Error) {
      const refused = await receipts.refuse(consent, checks.action, err).catch(() => null);
      if (refused) (err as Error & { actionReceipt?: string }).actionReceipt = refused.receipt;
    }
    throw err;
  }

  const completeAction = async (outcome: Partial<Omit<ActionReceiptInput, 'sessionId' | 'consentToken'>> = {}) => {
    if (!receipts) throw new TypeError('completeAction() needs the `receipts` option (createActionReceiptSigner())');
    const action = outcome.action ?? checks.action;
    if (!action) throw new TypeError('completeAction() needs an action');
    return receipts.record({ ...outcome, action, sessionId: consent.session_id, consentToken: consent.token });
  };

  return { claims, sessionId: consent.session_id, proofVerified, consentToken: consent.token, completeAction };
}

/** Signers already warned about filing with another broker than the keys came from. */
const warnedSigners = new WeakSet<object>();
function warnOnBrokerMismatch(receipts: { brokerUrl?: string | undefined }, brokerUrl: string | undefined): void {
  if (receipts.brokerUrl === undefined || brokerUrl === undefined || warnedSigners.has(receipts)) return;
  if (trimSlash(receipts.brokerUrl) === trimSlash(brokerUrl)) return;
  warnedSigners.add(receipts);
  console.warn(
    `[parafe] action receipts are filed with ${receipts.brokerUrl}, but this agent verifies consent against ${brokerUrl}. ` +
      'Pass the same brokerUrl to createActionReceiptSigner().'
  );
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

/** Initiator keys fetched from DID documents, by broker and agent ID (10 minutes). */
const didKeyCache = new Map<string, { jwk: JsonWebKeyLike; at: number }>();
async function initiatorJwk(agentId: string, brokerUrl: string): Promise<JsonWebKeyLike> {
  brokerUrl = trimSlash(brokerUrl);
  const cacheKey = `${brokerUrl}|${agentId}`;
  const cached = didKeyCache.get(cacheKey);
  if (cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.jwk;
  let res: Response;
  try {
    res = await fetch(`${brokerUrl}/agents/${encodeURIComponent(agentId)}/did.json`);
  } catch (err) {
    throw new InvalidProofError(`could not fetch the initiator's DID document: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!res.ok) throw new InvalidProofError(`the initiator's DID document is unavailable at ${brokerUrl} (${res.status}); is the agent revoked, or registered with another broker?`);
  const doc = (await res.json()) as { verificationMethod?: Array<{ publicKeyJwk?: JsonWebKeyLike }> };
  const jwk = doc.verificationMethod?.[0]?.publicKeyJwk;
  if (!jwk) throw new InvalidProofError("the initiator's DID document has no public key");
  didKeyCache.set(cacheKey, { jwk, at: Date.now() });
  return jwk;
}

function b64url(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Checks a presentation proof against a verified consent token: signed by the
 * key in `cnf.jkt`, for this token (`ath`), for the token's audience (`aud`),
 * fresh (5 minutes), not seen before, and for this message (`mid`, when given).
 * Without `initiatorKey`, the key is read from the initiator's DID document at
 * `brokerUrl` (default DEFAULT_BROKER_URL). Throws InvalidProofError.
 */
export async function verifyPresentationProof(
  proof: string,
  token: string,
  claims: ParafeConsentClaims,
  options: { initiatorKey?: JsonWebKeyLike; brokerUrl?: string; messageId?: string } = {}
): Promise<void> {
  const jkt = claims.cnf?.jkt;
  if (!jkt) throw new InvalidProofError('the consent token is not key-bound (no cnf.jkt)');
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
    throw new InvalidConsentTokenError('this token has no audience (aud); no proof applies');
  }
  const k = privateKey as unknown as { asymmetricKeyType?: string; algorithm?: { name?: string } };
  const alg = k.asymmetricKeyType === 'ec' || k.algorithm?.name === 'ECDSA' ? 'ES256' : 'EdDSA';
  const ath = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
  return new SignJWT({ ath, aud, jti: crypto.randomUUID(), ...(options.messageId ? { mid: options.messageId } : {}) })
    .setProtectedHeader({ alg, typ: POP_TYP })
    .setIssuedAt()
    .sign(privateKey);
}

function assertPermission(
  action: string,
  permissions: string[],
  exclusions: string[]
): void {
  if (exclusions.includes(action)) {
    throw new ScopeViolationError(action, permissions);
  }
  if (!permissions.includes(action)) {
    throw new ScopeViolationError(action, permissions);
  }
}

// Broker B8: 'delegated' (an AP2 open-mandate chain the broker checked) sits between attested and verified.
const MODALITY_RANK: Record<string, number> = { autonomous: 0, attested: 1, delegated: 2, verified: 3 };

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
  if (have === undefined || need === undefined || have < need) {
    throw new ScopeViolationError(claims.scope, claims.permissions,
      `Scope "${claims.scope}" requires "${scope.minimum_authorization_modality}" authorization, token has "${String(claims.authorization_modality)}".`);
  }
  if (scope.minimum_initiator_proof === 'pop' && claims.initiator_proof !== 'pop') {
    throw new ScopeViolationError(claims.scope, claims.permissions,
      `Scope "${claims.scope}" requires the initiator to have proved it holds its key, token says "${String(claims.initiator_proof ?? 'unknown')}".`);
  }
}
