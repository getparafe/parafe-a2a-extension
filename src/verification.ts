import { importSPKI, jwtVerify, decodeJwt } from 'jose';
import { DEFAULT_BROKER_URL } from './constants.js';
import { extractConsentToken, type ReadParafeOptions } from './message.js';
import {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  WrongAudienceError,
} from './errors.js';
import type {
  A2AMessageLike,
  ParafeConsentClaims,
  ScopeRequirement,
  VerifyConsentOptions,
  VerifyMessageOptions,
  VerifyOnlineOptions,
} from './types.js';

/**
 * Verifies a Parafe consent token offline using the broker's Ed25519 public key.
 * No network call required — verification uses only the public key and the token.
 *
 * This is the recommended verification path for most A2A agents. Fetch the broker's
 * public key once at startup (or cache it) via fetchBrokerPublicKey(), then call
 * this function on every incoming request.
 *
 * Validates:
 * - Ed25519 signature is valid
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
  brokerPublicKey: string,
  options: VerifyConsentOptions | string = {}
): Promise<ParafeConsentClaims> {
  const checks: VerifyConsentOptions = typeof options === 'string' ? { action: options } : options;
  let claims: ParafeConsentClaims;

  try {
    const publicKey = await importSPKI(brokerPublicKey, 'EdDSA');
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
      issuer: 'parafe-trust-broker',
    });
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

  if (claims.excluded !== undefined && !Array.isArray(claims.excluded)) {
    throw new InvalidConsentTokenError(
      `Expected "excluded" claim to be an array, got ${typeof claims.excluded}`
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
    assertPermission(checks.action, claims.permissions, claims.excluded ?? []);
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
    response = await fetch(`${brokerUrl}/consent/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        consent_token: token,
        action: options.action,
        session_id: sessionId,
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
    if (reason.toLowerCase().includes('expired')) {
      throw new ExpiredConsentTokenError(new Date());
    }
    throw new InvalidConsentTokenError(reason);
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
  };
}

/** Result from the broker's /consent/verify endpoint. */
export interface ConsentVerifyResult {
  valid: boolean;
  permitted: boolean;
  action: string;
  sessionId: string;
  expiresAt?: string | undefined;
}

/**
 * Fetches the Parafe broker's Ed25519 public key for use with verifyConsentTokenOffline().
 * Call this once at agent startup and cache the result — the key changes infrequently.
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
  message: A2AMessageLike,
  brokerPublicKey: string,
  options: VerifyMessageOptions & ReadParafeOptions
): Promise<{ claims: ParafeConsentClaims; sessionId: string }> {
  const { acceptV1, ...checks } = options;
  const consent = extractConsentToken(message, acceptV1 === undefined ? {} : { acceptV1 });
  if (consent === null) {
    throw new MissingParafeExtensionError('No Parafe consent token found in the message.');
  }

  const claims = await verifyConsentTokenOffline(consent.token, brokerPublicKey, {
    ...checks,
    sessionId: consent.session_id,
  });

  return { claims, sessionId: consent.session_id };
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
}
