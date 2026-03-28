import { importSPKI, jwtVerify, decodeJwt } from 'jose';
import {
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
  DEFAULT_BROKER_URL,
} from './constants.js';
import {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
} from './errors.js';
import type {
  ParafeExtensionMetadata,
  ParafeConsentClaims,
  VerifyOnlineOptions,
} from './types.js';

/**
 * Extracts and validates the presence of Parafe fields from A2A request metadata.
 * Throws MissingParafeExtensionError if required fields are absent.
 *
 * @example
 * const parafe = extractExtensionMetadata(task.params.metadata);
 * // parafe.agentId, parafe.consentToken, parafe.sessionId
 */
export function extractExtensionMetadata(
  metadata: Record<string, unknown>
): ParafeExtensionMetadata {
  const missing: string[] = [];

  const agentId = metadata[PARAFE_AGENT_ID_FIELD];
  const consentToken = metadata[PARAFE_CONSENT_TOKEN_FIELD];

  if (typeof agentId !== 'string' || agentId.length === 0) {
    missing.push(PARAFE_AGENT_ID_FIELD);
  }
  if (typeof consentToken !== 'string' || consentToken.length === 0) {
    missing.push(PARAFE_CONSENT_TOKEN_FIELD);
  }

  if (missing.length > 0) {
    throw new MissingParafeExtensionError(missing);
  }

  const sessionId = metadata[PARAFE_SESSION_ID_FIELD];

  const result: ParafeExtensionMetadata = {
    agentId: agentId as string,
    consentToken: consentToken as string,
  };
  if (typeof sessionId === 'string' && sessionId.length > 0) {
    result.sessionId = sessionId;
  }
  return result;
}

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
 * - Requested action is in permissions and not in excluded list (if requiredAction provided)
 *
 * Throws:
 * - InvalidConsentTokenError — signature invalid, JWT malformed, wrong issuer, or wrong token_type
 * - ExpiredConsentTokenError — token has expired
 * - ScopeViolationError — action is excluded or not in permissions list
 *
 * @param token - The consent token JWT from params.metadata
 * @param brokerPublicKey - The broker's Ed25519 public key in PEM format (from fetchBrokerPublicKey)
 * @param requiredAction - Optional action that must be permitted by this token
 *
 * @example
 * const claims = await verifyConsentTokenOffline(parafe.consentToken, brokerPublicKey);
 * console.log(claims.scope);                 // "flight-rebooking"
 * console.log(claims.permissions);            // ["read_bookings", "search_alternatives"]
 * console.log(claims.initiator_agent_id);     // "prf_agent_..."
 */
export async function verifyConsentTokenOffline(
  token: string,
  brokerPublicKey: string,
  requiredAction?: string
): Promise<ParafeConsentClaims> {
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

  if (claims.token_type !== 'consent') {
    throw new InvalidConsentTokenError(
      `Expected token_type "consent", got "${String(claims.token_type)}"`
    );
  }

  if (requiredAction !== undefined) {
    assertPermission(requiredAction, claims.permissions ?? [], claims.excluded ?? []);
  }

  return claims;
}

/**
 * Verifies a Parafe consent token online via the Parafe broker's /consent/verify endpoint.
 * Use this when you need real-time confirmation from the broker (e.g., for high-value actions).
 * For most A2A agents, verifyConsentTokenOffline() is sufficient and faster.
 *
 * The broker's /consent/verify endpoint requires consent_token, action, and session_id.
 * If sessionId is not provided in options, it is extracted from the token's claims.
 *
 * Throws:
 * - InvalidConsentTokenError — broker rejected the token (invalid signature, wrong session, etc.)
 * - ExpiredConsentTokenError — token has expired
 * - ScopeViolationError — action is not permitted or is excluded
 *
 * @example
 * const result = await verifyConsentTokenOnline(parafe.consentToken, {
 *   action: 'read_bookings',
 *   sessionId: parafe.sessionId,
 * });
 */
export async function verifyConsentTokenOnline(
  token: string,
  options: VerifyOnlineOptions
): Promise<ConsentVerifyResult> {
  const brokerUrl = options.brokerUrl ?? DEFAULT_BROKER_URL;

  // Extract session_id from the token if not provided
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

  // Broker returns 401 for invalid/expired tokens or session mismatch
  if (!response.ok) {
    const reason = typeof body['reason'] === 'string' ? body['reason'] : response.statusText;
    if (reason.toLowerCase().includes('expired')) {
      throw new ExpiredConsentTokenError(new Date());
    }
    throw new InvalidConsentTokenError(reason);
  }

  // Broker returns 200 with valid: true for all verified tokens.
  // permitted: false means the action is excluded or not in the permissions list.
  if (body['valid'] === true && body['permitted'] === false) {
    const reason = typeof body['reason'] === 'string' ? body['reason'] : 'Action not permitted';
    throw new ScopeViolationError(options.action, [reason]);
  }

  return {
    valid: body['valid'] as boolean,
    permitted: body['permitted'] as boolean,
    action: body['action'] as string,
    sessionId: body['session_id'] as string,
    expiresAt: typeof body['expires_at'] === 'string' ? body['expires_at'] : undefined,
  };
}

/**
 * Result from the broker's /consent/verify endpoint when the action is permitted.
 */
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
 *
 * @example
 * const brokerPublicKey = await fetchBrokerPublicKey();
 * // Then on each request:
 * const claims = await verifyConsentTokenOffline(token, brokerPublicKey);
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

  // Convert base64-encoded SPKI DER to PEM format for jose's importSPKI()
  return derBase64ToPem(publicKeyBase64);
}

/**
 * Converts a base64-encoded DER public key to PEM format.
 * The broker returns SPKI DER as base64; jose's importSPKI() expects PEM with headers.
 */
function derBase64ToPem(base64: string): string {
  // Wrap at 64 characters per line per PEM spec
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

/**
 * Checks that the requested action is permitted by the consent token.
 * Mirrors the broker's /consent/verify logic: check excluded first, then check permissions.
 */
function assertPermission(
  action: string,
  permissions: string[],
  excluded: string[]
): void {
  if (excluded.includes(action)) {
    throw new ScopeViolationError(
      action,
      permissions,
    );
  }
  if (!permissions.includes(action)) {
    throw new ScopeViolationError(
      action,
      permissions,
    );
  }
}
