import {
  PARAFE_EXTENSION_URI,
  PARAFE_V1_HANDSHAKE_CHALLENGE,
  PARAFE_V1_HANDSHAKE_COMPLETE,
  PARAFE_V1_CONSENT_TOKEN,
} from './constants.js';
import { MalformedParafeDataError, isParafeError } from './errors.js';
import type {
  A2AMessageLike,
  ConsentTokenPayload,
  SessionClosedPayload,
  HandshakeChallengePayload,
  HandshakeCompletePayload,
  ParafeErrorPayload,
  ParafeMessageData,
  ParafeMessageMember,
} from './types.js';

// ---------------------------------------------------------------------------
// Writing — Parafe data lives at message.metadata[PARAFE_EXTENSION_URI], and the
// URI is listed in message.extensions. Never in parts: agents feed parts to
// language models and store them in logs.
// ---------------------------------------------------------------------------

/**
 * Returns a copy of `message` carrying Parafe data: sets
 * `metadata[PARAFE_EXTENSION_URI]` and adds the URI to `extensions`.
 * Other metadata and extensions are kept. Works with @a2a-js/sdk `Message`
 * objects and raw A2A 1.0 / 0.3 JSON.
 *
 * @example
 * const message = withParafe(
 *   { messageId, role: 'ROLE_USER', parts: [{ text: 'Two dozen glazed, please.' }] },
 *   { consent: { token: consentToken, session_id: sessionId } },
 * );
 */
export function withParafe<M extends A2AMessageLike>(message: M, data: ParafeMessageData): M {
  const extensions = [...(message.extensions ?? [])];
  if (!extensions.includes(PARAFE_EXTENSION_URI)) extensions.push(PARAFE_EXTENSION_URI);
  // Action receipts already attached stay, unless `data` brings its own.
  const prior = message.metadata?.[PARAFE_EXTENSION_URI];
  const keep = isObject(prior) && Array.isArray(prior['action_receipts']) && !('action_receipts' in data)
    ? { action_receipts: prior['action_receipts'] as string[] }
    : {};
  return {
    ...message,
    extensions,
    metadata: { ...(message.metadata ?? {}), [PARAFE_EXTENSION_URI]: { ...data, ...keep } },
  };
}

/**
 * Shorthand for `withParafe(message, { consent: { token, session_id, proof } })`.
 * Pass the presentation proof from createPresentationProof() (2.1).
 */
export function withConsentToken<M extends A2AMessageLike>(
  message: M,
  token: string,
  sessionId: string,
  proof?: string
): M {
  return withParafe(message, { consent: { token, session_id: sessionId, ...(proof ? { proof } : {}) } });
}

/** Shorthand for `withParafe(message, { session_closed: { session_id, receipt } })` (2.1). */
export function withSessionClosed<M extends A2AMessageLike>(message: M, sessionId: string, receipt: string): M {
  return withParafe(message, { session_closed: { session_id: sessionId, receipt } });
}

/**
 * Attach action receipts (2.2) to a message: the receipts you signed for what
 * you did or refused in this turn. They go beside any other Parafé data in the
 * message (e.g. `error`), or alone. Call it after withParafe().
 */
export function withActionReceipts<M extends A2AMessageLike>(message: M, receipts: string[]): M {
  if (receipts.length === 0) return message;
  const prior = message.metadata?.[PARAFE_EXTENSION_URI];
  const base = isObject(prior) ? prior : {};
  const existing = Array.isArray(base['action_receipts']) ? (base['action_receipts'] as string[]) : [];
  const action_receipts = [...new Set([...existing, ...receipts])];
  const extensions = [...(message.extensions ?? [])];
  if (!extensions.includes(PARAFE_EXTENSION_URI)) extensions.push(PARAFE_EXTENSION_URI);
  return {
    ...message,
    extensions,
    metadata: { ...(message.metadata ?? {}), [PARAFE_EXTENSION_URI]: { ...base, action_receipts } },
  };
}

/**
 * Parafe `error` data for a refused request. Pass one of this package's errors
 * (e.g. from verifyMessageConsentToken) to report it the way the specification
 * describes. Any other error is reported as INVALID_CONSENT_TOKEN without its message.
 *
 * @example
 * catch (err) {
 *   reply = withParafe(reply, parafeErrorData(err));
 * }
 */
export function parafeErrorData(err: unknown): { error: ParafeErrorPayload; action_receipts?: string[] } {
  if (isParafeError(err)) {
    // 2.2: the refusal's signed action receipt, when verifyMessageConsentToken made one.
    return { error: { code: err.code, message: err.message }, ...(err.actionReceipt ? { action_receipts: [err.actionReceipt] } : {}) };
  }
  return { error: { code: 'INVALID_CONSENT_TOKEN', message: 'Parafe consent could not be verified.' } };
}

// ---------------------------------------------------------------------------
// Reading — accepts v2 metadata, and (until 2027-03-31) v1 data parts in any of
// their three shapes: A2A 0.3 `{ kind: 'data', data }`, A2A 1.0 wire
// `{ data }`, and @a2a-js/sdk `{ content: { $case: 'data', value } }`.
// ---------------------------------------------------------------------------

export interface ReadParafeOptions {
  /**
   * Also accept v1-style Parafe data parts. Defaults to true.
   * v1 support is planned until 2027-03-31.
   */
  acceptV1?: boolean;
}

/**
 * Reads the Parafe data from an A2A message. Returns null if the message has none.
 * Throws MalformedParafeDataError if Parafe data is present but invalid.
 *
 * Pass the whole message (not `message.parts`).
 */
export function readParafe(
  message: A2AMessageLike,
  options: ReadParafeOptions = {}
): ParafeMessageData | null {
  if (Array.isArray(message)) {
    throw new TypeError(
      'readParafe() takes the whole A2A message, not its parts array. Parafe data lives in message.metadata.'
    );
  }

  const fromMetadata = message.metadata?.[PARAFE_EXTENSION_URI];
  if (fromMetadata !== undefined && fromMetadata !== null) {
    return validateParafeData(fromMetadata);
  }

  if (options.acceptV1 ?? true) {
    return readV1DataParts(message.parts ?? []);
  }
  return null;
}

/** The `handshake_challenge` in a message, or null. */
export function extractHandshakeChallenge(
  message: A2AMessageLike,
  options?: ReadParafeOptions
): HandshakeChallengePayload | null {
  const data = readParafe(message, options);
  return data && 'handshake_challenge' in data ? data.handshake_challenge : null;
}

/** The `handshake_complete` in a message, or null. */
export function extractHandshakeComplete(
  message: A2AMessageLike,
  options?: ReadParafeOptions
): HandshakeCompletePayload | null {
  const data = readParafe(message, options);
  return data && 'handshake_complete' in data ? data.handshake_complete : null;
}

/** The `consent` (token + session ID) in a message, or null. */
export function extractConsentToken(
  message: A2AMessageLike,
  options?: ReadParafeOptions
): ConsentTokenPayload | null {
  const data = readParafe(message, options);
  return data && 'consent' in data ? data.consent : null;
}

/** The `error` an agent reported, or null. */
export function extractParafeError(
  message: A2AMessageLike,
  options?: ReadParafeOptions
): ParafeErrorPayload | null {
  const data = readParafe(message, options);
  return data && 'error' in data ? data.error : null;
}

/** The `session_closed` (session ID + receipt JWS) in a message, or null. */
export function extractSessionClosed(
  message: A2AMessageLike,
  options?: ReadParafeOptions
): SessionClosedPayload | null {
  const data = readParafe(message, options);
  return data && 'session_closed' in data ? data.session_closed : null;
}

/** The action receipts attached to a message (2.2), or an empty list. */
export function extractActionReceipts(message: A2AMessageLike, options?: ReadParafeOptions): string[] {
  const data = readParafe(message, options);
  return data?.action_receipts ?? [];
}

/** True if the message carries any Parafe data (without validating it). */
export function hasParafeData(message: A2AMessageLike, options: ReadParafeOptions = {}): boolean {
  const fromMetadata = message.metadata?.[PARAFE_EXTENSION_URI];
  if (fromMetadata !== undefined && fromMetadata !== null) return true;
  if (!(options.acceptV1 ?? true)) return false;
  return (message.parts ?? []).some((part) => {
    const data = dataPartValue(part);
    return data !== null && V1_KEYS.some((key) => key in data);
  });
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const MEMBERS = ['handshake_challenge', 'handshake_complete', 'consent', 'session_closed', 'error'] as const;
const MAX_ACTION_RECEIPTS = 50;

function validateParafeData(raw: unknown): ParafeMessageData | null {
  if (!isObject(raw)) {
    throw new MalformedParafeDataError('metadata', 'expected an object');
  }
  const receipts = raw['action_receipts'] === undefined ? undefined : validateActionReceipts(raw['action_receipts']);
  const present = MEMBERS.filter((m) => raw[m] !== undefined);
  if (present.length === 0 && receipts) return { action_receipts: receipts };
  // Forward compatibility (2.2): members this version doesn't know are ignored;
  // data with only such members reads as no Parafé data we understand.
  const known: readonly string[] = [...MEMBERS, 'action_receipts'];
  if (present.length === 0 && Object.keys(raw).some((k) => !known.includes(k))) return null;
  if (present.length !== 1) {
    throw new MalformedParafeDataError(
      'metadata',
      present.length === 0
        ? `expected one of ${MEMBERS.join(', ')}, or action_receipts`
        : `expected exactly one member, got ${present.join(', ')}`
    );
  }
  const member = validateMember(present[0]!, raw[present[0]!]);
  return receipts ? { ...member, action_receipts: receipts } : member;
}

function validateActionReceipts(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ACTION_RECEIPTS) {
    throw new MalformedParafeDataError('action_receipts', `expected an array of 1-${MAX_ACTION_RECEIPTS} action receipt JWSs`);
  }
  for (const r of value) {
    if (typeof r !== 'string' || r.split('.').length !== 3) {
      throw new MalformedParafeDataError('action_receipts', 'each entry must be an action receipt JWS');
    }
  }
  return value as string[];
}

function validateMember(member: (typeof MEMBERS)[number], value: unknown): ParafeMessageMember {
  switch (member) {
    case 'handshake_challenge':
      return { handshake_challenge: validateChallenge(value, member) };
    case 'handshake_complete':
      return { handshake_complete: validateComplete(value, member) };
    case 'consent':
      return { consent: validateConsent(value, member) };
    case 'session_closed':
      return { session_closed: validateSessionClosed(value) };
    case 'error':
      return { error: validateError(value) };
  }
}

function validateChallenge(value: unknown, label: string): HandshakeChallengePayload {
  const payload = requireObject(value, label);
  requireStrings(payload, label, ['handshake_id', 'challenge', 'initiator_agent_id', 'broker_url', 'requested_scope']);
  const perms = payload['requested_permissions'];
  if (perms !== undefined && !(Array.isArray(perms) && perms.every((p) => typeof p === 'string'))) {
    throw new MalformedParafeDataError(label, 'requested_permissions must be an array of strings');
  }
  // Broker challenge nonces are 32 random bytes, hex-encoded.
  const challenge = payload['challenge'] as string;
  if (!/^[0-9a-f]{64}$/i.test(challenge)) {
    throw new MalformedParafeDataError(
      label,
      `challenge nonce must be a 64-character hex string, got "${challenge.length > 128 ? challenge.slice(0, 128) + '...' : challenge}"`
    );
  }
  return payload as unknown as HandshakeChallengePayload;
}

function validateComplete(value: unknown, label: string): HandshakeCompletePayload {
  const payload = requireObject(value, label);
  requireStrings(payload, label, ['handshake_id', 'status']);
  const status = payload['status'];
  if (status !== 'authenticated' && status !== 'rejected' && status !== 'error') {
    throw new MalformedParafeDataError(label, `status must be authenticated, rejected or error, got "${String(status)}"`);
  }
  if (status === 'authenticated' && typeof payload['consent_token'] !== 'string') {
    throw new MalformedParafeDataError(label, 'consent_token is required when status is authenticated');
  }
  return payload as unknown as HandshakeCompletePayload;
}

function validateConsent(value: unknown, label: string): ConsentTokenPayload {
  const payload = requireObject(value, label);
  requireStrings(payload, label, ['token', 'session_id']);
  if (payload['proof'] !== undefined && typeof payload['proof'] !== 'string') {
    throw new MalformedParafeDataError(label, 'proof must be a string');
  }
  return payload as unknown as ConsentTokenPayload;
}

function validateSessionClosed(value: unknown): SessionClosedPayload {
  const payload = requireObject(value, 'session_closed');
  requireStrings(payload, 'session_closed', ['session_id', 'receipt']);
  if ((payload['receipt'] as string).split('.').length !== 3) {
    throw new MalformedParafeDataError('session_closed', 'receipt must be the receipt JWS');
  }
  return payload as unknown as SessionClosedPayload;
}

function validateError(value: unknown): ParafeErrorPayload {
  const payload = requireObject(value, 'error');
  requireStrings(payload, 'error', ['code', 'message']);
  return payload as unknown as ParafeErrorPayload;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!isObject(value)) throw new MalformedParafeDataError(label, 'expected an object');
  return value;
}

function requireStrings(payload: Record<string, unknown>, label: string, fields: string[]): void {
  const missing = fields.filter((f) => typeof payload[f] !== 'string');
  if (missing.length > 0) {
    throw new MalformedParafeDataError(label, `missing fields: ${missing.join(', ')}`);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// v1 data parts
// ---------------------------------------------------------------------------

const V1_KEYS = [PARAFE_V1_HANDSHAKE_CHALLENGE, PARAFE_V1_HANDSHAKE_COMPLETE, PARAFE_V1_CONSENT_TOKEN];

/** The `data` object of a data part in any of its three shapes, or null. */
function dataPartValue(part: unknown): Record<string, unknown> | null {
  if (!isObject(part)) return null;
  // @a2a-js/sdk: { content: { $case: 'data', value } }
  const content = part['content'];
  if (isObject(content)) {
    return content['$case'] === 'data' && isObject(content['value']) ? content['value'] : null;
  }
  // A2A 0.3: { kind: 'data', data }. A2A 1.0 wire: { data } (no kind).
  if (part['kind'] !== undefined && part['kind'] !== 'data') return null;
  return isObject(part['data']) ? part['data'] : null;
}

function readV1DataParts(parts: readonly unknown[]): ParafeMessageData | null {
  for (const part of parts) {
    const data = dataPartValue(part);
    if (data === null) continue;
    if (PARAFE_V1_HANDSHAKE_CHALLENGE in data) {
      return { handshake_challenge: validateChallenge(data[PARAFE_V1_HANDSHAKE_CHALLENGE], PARAFE_V1_HANDSHAKE_CHALLENGE) };
    }
    if (PARAFE_V1_HANDSHAKE_COMPLETE in data) {
      return { handshake_complete: validateComplete(data[PARAFE_V1_HANDSHAKE_COMPLETE], PARAFE_V1_HANDSHAKE_COMPLETE) };
    }
    if (PARAFE_V1_CONSENT_TOKEN in data) {
      return { consent: validateConsent(data[PARAFE_V1_CONSENT_TOKEN], PARAFE_V1_CONSENT_TOKEN) };
    }
  }
  return null;
}
