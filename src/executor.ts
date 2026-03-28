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
 * Throws:
 * - InvalidConsentTokenError — signature invalid or JWT malformed
 * - ExpiredConsentTokenError — token has expired
 * - ScopeViolationError — token does not cover requiredScope (if provided)
 *
 * @param token - The consent token JWT from params.metadata
 * @param brokerPublicKey - The broker's Ed25519 public key in PEM or JWK string format
 * @param requiredScope - Optional scope(s) that must be present in the token
 *
 * @example
 * const claims = await verifyConsentTokenOffline(parafe.consentToken, brokerPublicKey);
 * console.log(claims.sub);    // agent ID
 * console.log(claims.scope);  // granted scopes
 */
export async function verifyConsentTokenOffline(
  token: string,
  brokerPublicKey: string,
  requiredScope?: string | string[]
): Promise<ParafeConsentClaims> {
  let claims: ParafeConsentClaims;

  try {
    const publicKey = await importSPKI(brokerPublicKey, 'EdDSA');
    const { payload } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
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

  if (requiredScope !== undefined) {
    assertScope(claims.scope ?? [], requiredScope);
  }

  return claims;
}

/**
 * Verifies a Parafe consent token online via the Parafe broker's /consent/verify endpoint.
 * Use this when you need real-time confirmation from the broker (e.g., for high-value actions).
 * For most A2A agents, verifyConsentTokenOffline() is sufficient and faster.
 *
 * Throws:
 * - InvalidConsentTokenError — broker rejected the token
 * - ExpiredConsentTokenError — token has expired
 * - ScopeViolationError — token does not cover requiredScope (if provided)
 *
 * @example
 * const claims = await verifyConsentTokenOnline(parafe.consentToken, {
 *   brokerUrl: 'https://api.parafe.ai',
 *   requiredScope: 'read:data',
 * });
 */
export async function verifyConsentTokenOnline(
  token: string,
  options: VerifyOnlineOptions = {}
): Promise<ParafeConsentClaims> {
  const brokerUrl = options.brokerUrl ?? DEFAULT_BROKER_URL;

  let response: Response;
  try {
    response = await fetch(`${brokerUrl}/consent/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
  } catch (err) {
    throw new InvalidConsentTokenError(
      `Could not reach Parafe broker at ${brokerUrl}: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    const message = typeof body['error'] === 'string' ? body['error'] : response.statusText;
    throw new InvalidConsentTokenError(message);
  }

  const body = await response.json() as Record<string, unknown>;
  const claims = body['claims'] as ParafeConsentClaims;

  if (options.requiredScope !== undefined) {
    assertScope(claims.scope ?? [], options.requiredScope);
  }

  return claims;
}

/**
 * Fetches the Parafe broker's Ed25519 public key for use with verifyConsentTokenOffline().
 * Call this once at agent startup and cache the result — the key changes infrequently.
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
  const publicKey = body['publicKey'];

  if (typeof publicKey !== 'string') {
    throw new Error('Unexpected response shape from Parafe broker /public-key endpoint');
  }

  return publicKey;
}

function assertScope(granted: string[], required: string | string[]): void {
  const requiredArr = Array.isArray(required) ? required : [required];
  const missing = requiredArr.filter((s) => !granted.includes(s));
  if (missing.length > 0) {
    throw new ScopeViolationError(missing.length === 1 ? (missing[0] as string) : missing, granted);
  }
}
