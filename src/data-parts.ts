import {
  PARAFE_HANDSHAKE_CHALLENGE,
  PARAFE_HANDSHAKE_COMPLETE,
  PARAFE_TRUST_CONSENT_TOKEN,
} from './constants.js';
import { MalformedDataPartError } from './errors.js';
import type {
  A2AMessagePart,
  HandshakeChallengePayload,
  HandshakeChallengeDataPart,
  HandshakeCompletePayload,
  HandshakeCompleteDataPart,
  ConsentTokenPayload,
  ConsentTokenDataPart,
} from './types.js';

// ---------------------------------------------------------------------------
// Builders — pure functions, no I/O. Wrap payloads into A2A DataPart shapes.
// ---------------------------------------------------------------------------

/**
 * Builds a `parafe.handshake.Challenge` DataPart for an outgoing A2A message.
 * The initiating agent includes this in its first message to the target.
 *
 * @example
 * const challengePart = buildHandshakeChallenge({
 *   handshake_id: 'hs_abc123',
 *   challenge: '9f4a2c8e1b3d7f0a...',
 *   initiator_agent_id: 'prf_agent_sofia01',
 *   broker_url: 'https://api.parafe.ai',
 *   requested_scope: 'order-donuts',
 * });
 * message.parts.push(challengePart);
 */
export function buildHandshakeChallenge(
  payload: HandshakeChallengePayload
): HandshakeChallengeDataPart {
  return {
    kind: 'data',
    data: { [PARAFE_HANDSHAKE_CHALLENGE]: payload },
  } as HandshakeChallengeDataPart;
}

/**
 * Builds a `parafe.handshake.Complete` DataPart for an outgoing A2A message.
 * The target agent includes this in its response after completing the handshake with Parafe.
 *
 * @example
 * const completePart = buildHandshakeComplete({
 *   handshake_id: 'hs_abc123',
 *   status: 'authenticated',
 *   consent_token: '<signed-JWT>',
 * });
 * response.parts.push(completePart);
 */
export function buildHandshakeComplete(
  payload: HandshakeCompletePayload
): HandshakeCompleteDataPart {
  return {
    kind: 'data',
    data: { [PARAFE_HANDSHAKE_COMPLETE]: payload },
  } as HandshakeCompleteDataPart;
}

/**
 * Builds a `parafe.trust.ConsentToken` DataPart for an outgoing A2A message.
 * Include this in every message during the direct exchange between agents.
 *
 * @example
 * const tokenPart = buildConsentTokenPart(consentToken.token, sessionId);
 * message.parts = [tokenPart, { kind: 'text', text: 'Show me flights...' }];
 */
export function buildConsentTokenPart(
  token: string,
  sessionId: string
): ConsentTokenDataPart {
  return {
    kind: 'data',
    data: {
      [PARAFE_TRUST_CONSENT_TOKEN]: { token, session_id: sessionId },
    },
  } as ConsentTokenDataPart;
}

// ---------------------------------------------------------------------------
// Parsers — extract payloads from A2A message parts arrays.
// Return null if the DataPart type is not present.
// Throw MalformedDataPartError if the key is present but payload is invalid.
// ---------------------------------------------------------------------------

/**
 * Extracts a `parafe.handshake.Challenge` payload from A2A message parts.
 * Returns null if no challenge DataPart is present.
 * Throws MalformedDataPartError if the key is present but required fields are missing.
 */
export function extractHandshakeChallenge(
  parts: A2AMessagePart[]
): HandshakeChallengePayload | null {
  const raw = findDataPartPayload(parts, PARAFE_HANDSHAKE_CHALLENGE);
  if (raw === null) return null;

  const payload = raw as Record<string, unknown>;
  const missing: string[] = [];
  if (typeof payload['handshake_id'] !== 'string') missing.push('handshake_id');
  if (typeof payload['challenge'] !== 'string') missing.push('challenge');
  if (typeof payload['initiator_agent_id'] !== 'string') missing.push('initiator_agent_id');
  if (typeof payload['broker_url'] !== 'string') missing.push('broker_url');
  if (typeof payload['requested_scope'] !== 'string') missing.push('requested_scope');

  if (missing.length > 0) {
    throw new MalformedDataPartError(
      PARAFE_HANDSHAKE_CHALLENGE,
      `missing fields: ${missing.join(', ')}`
    );
  }

  // N-05: Validate challenge nonce format — broker generates 64-character hex strings.
  const challenge = payload['challenge'] as string;
  if (!/^[0-9a-f]{64}$/i.test(challenge)) {
    throw new MalformedDataPartError(
      PARAFE_HANDSHAKE_CHALLENGE,
      `challenge nonce must be a 64-character hex string, got "${challenge.length > 128 ? challenge.slice(0, 128) + '...' : challenge}"`
    );
  }

  return payload as unknown as HandshakeChallengePayload;
}

/**
 * Extracts a `parafe.handshake.Complete` payload from A2A message parts.
 * Returns null if no complete DataPart is present.
 * Throws MalformedDataPartError if the key is present but required fields are missing.
 */
export function extractHandshakeComplete(
  parts: A2AMessagePart[]
): HandshakeCompletePayload | null {
  const raw = findDataPartPayload(parts, PARAFE_HANDSHAKE_COMPLETE);
  if (raw === null) return null;

  const payload = raw as Record<string, unknown>;
  const missing: string[] = [];
  if (typeof payload['handshake_id'] !== 'string') missing.push('handshake_id');
  if (typeof payload['status'] !== 'string') missing.push('status');

  if (missing.length > 0) {
    throw new MalformedDataPartError(
      PARAFE_HANDSHAKE_COMPLETE,
      `missing fields: ${missing.join(', ')}`
    );
  }

  return payload as unknown as HandshakeCompletePayload;
}

/**
 * Extracts a `parafe.trust.ConsentToken` payload from A2A message parts.
 * Returns null if no consent token DataPart is present.
 * Throws MalformedDataPartError if the key is present but required fields are missing.
 */
export function extractConsentToken(
  parts: A2AMessagePart[]
): ConsentTokenPayload | null {
  const raw = findDataPartPayload(parts, PARAFE_TRUST_CONSENT_TOKEN);
  if (raw === null) return null;

  const payload = raw as Record<string, unknown>;
  const missing: string[] = [];
  if (typeof payload['token'] !== 'string') missing.push('token');
  if (typeof payload['session_id'] !== 'string') missing.push('session_id');

  if (missing.length > 0) {
    throw new MalformedDataPartError(
      PARAFE_TRUST_CONSENT_TOKEN,
      `missing fields: ${missing.join(', ')}`
    );
  }

  return payload as unknown as ConsentTokenPayload;
}

/**
 * Returns true if any Parafe DataPart (challenge, complete, or consent token) is present.
 */
export function hasParafeDataPart(parts: A2AMessagePart[]): boolean {
  const keys = [PARAFE_HANDSHAKE_CHALLENGE, PARAFE_HANDSHAKE_COMPLETE, PARAFE_TRUST_CONSENT_TOKEN];
  return parts.some(
    (part) =>
      part.kind === 'data' &&
      typeof (part as { data?: Record<string, unknown> }).data === 'object' &&
      keys.some((key) => key in ((part as { data: Record<string, unknown> }).data))
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function findDataPartPayload(
  parts: A2AMessagePart[],
  key: string
): unknown | null {
  for (const part of parts) {
    if (part.kind !== 'data') continue;
    const data = (part as { data?: Record<string, unknown> }).data;
    if (typeof data === 'object' && data !== null && key in data) {
      return data[key];
    }
  }
  return null;
}
