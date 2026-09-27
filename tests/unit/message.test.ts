import { describe, it, expect } from 'vitest';
import {
  withParafe,
  withConsentToken,
  parafeErrorData,
  readParafe,
  extractHandshakeChallenge,
  extractHandshakeComplete,
  extractConsentToken,
  extractParafeError,
  hasParafeData,
  MalformedParafeDataError,
  ExpiredConsentTokenError,
  PARAFE_EXTENSION_URI,
  type HandshakeChallengePayload,
} from '../../src/index.js';

const CHALLENGE: HandshakeChallengePayload = {
  handshake_id: 'hs_abc123',
  challenge: 'a'.repeat(64),
  initiator_agent_id: 'prf_agent_sofia01',
  broker_url: 'https://api.parafe.ai',
  requested_scope: 'order-donuts',
};

const baseMessage = () => ({
  messageId: 'm1',
  role: 'ROLE_USER',
  parts: [{ text: 'Two dozen glazed, please.' }],
});

describe('withParafe', () => {
  it('puts Parafe data in metadata under the extension URI and lists the URI', () => {
    const message = withParafe(baseMessage(), { handshake_challenge: CHALLENGE });

    expect(message.metadata).toEqual({ [PARAFE_EXTENSION_URI]: { handshake_challenge: CHALLENGE } });
    expect(message.extensions).toEqual([PARAFE_EXTENSION_URI]);
    expect(message.parts).toEqual([{ text: 'Two dozen glazed, please.' }]);
  });

  it('keeps other metadata and extensions, and does not duplicate the URI', () => {
    const start = {
      ...baseMessage(),
      metadata: { 'https://example.com/ext/geo/v1': { lat: 1 } },
      extensions: ['https://example.com/ext/geo/v1', PARAFE_EXTENSION_URI],
    };
    const message = withConsentToken(start, 'tok', 'sess_1');

    expect(message.metadata['https://example.com/ext/geo/v1']).toEqual({ lat: 1 });
    expect(message.metadata[PARAFE_EXTENSION_URI]).toEqual({ consent: { token: 'tok', session_id: 'sess_1' } });
    expect(message.extensions).toEqual(['https://example.com/ext/geo/v1', PARAFE_EXTENSION_URI]);
  });

  it('does not mutate the input message', () => {
    const start = baseMessage();
    withConsentToken(start, 'tok', 'sess_1');
    expect(start).toEqual(baseMessage());
  });

  it('never touches parts', () => {
    const message = withConsentToken(baseMessage(), 'tok', 'sess_1');
    expect(JSON.stringify(message.parts)).not.toContain('tok');
  });
});

describe('readParafe (v2 metadata)', () => {
  it('reads each kind of Parafe data', () => {
    expect(extractHandshakeChallenge(withParafe(baseMessage(), { handshake_challenge: CHALLENGE }))).toEqual(CHALLENGE);

    const complete = { handshake_id: 'hs_abc123', status: 'authenticated' as const, session_id: 's', consent_token: 'jwt' };
    expect(extractHandshakeComplete(withParafe(baseMessage(), { handshake_complete: complete }))).toEqual(complete);

    expect(extractConsentToken(withConsentToken(baseMessage(), 'jwt', 's'))).toEqual({ token: 'jwt', session_id: 's' });

    const error = { code: 'EXPIRED_CONSENT_TOKEN' as const, message: 'expired' };
    expect(extractParafeError(withParafe(baseMessage(), { error }))).toEqual(error);
  });

  it('extractors return null for a different kind of Parafe data', () => {
    const message = withConsentToken(baseMessage(), 'jwt', 's');
    expect(extractHandshakeChallenge(message)).toBeNull();
    expect(extractHandshakeComplete(message)).toBeNull();
    expect(extractParafeError(message)).toBeNull();
  });

  it('returns null for a message without Parafe data', () => {
    expect(readParafe(baseMessage())).toBeNull();
    expect(readParafe({ ...baseMessage(), metadata: { other: 1 } })).toBeNull();
    expect(readParafe({})).toBeNull();
  });

  it('works on @a2a-js/sdk-shaped messages (metadata undefined, extensions [])', () => {
    const sdkMessage = {
      messageId: 'm1', contextId: '', taskId: '', role: 1,
      parts: [{ content: { $case: 'text', value: 'hi' }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
      metadata: undefined, extensions: [] as string[], referenceTaskIds: [] as string[],
    };
    expect(readParafe(sdkMessage)).toBeNull();
    expect(extractConsentToken(withConsentToken(sdkMessage, 'jwt', 's'))).toEqual({ token: 'jwt', session_id: 's' });
  });

  it('throws a TypeError when given a parts array instead of a message', () => {
    expect(() => readParafe([] as never)).toThrow(TypeError);
  });

  it('throws MalformedParafeDataError for invalid data', () => {
    const bad = (data: unknown) => ({ ...baseMessage(), metadata: { [PARAFE_EXTENSION_URI]: data } });

    expect(() => readParafe(bad('a string'))).toThrow(MalformedParafeDataError);
    expect(() => readParafe(bad({}))).toThrow(/expected one of/);
    expect(() => readParafe(bad({ consent: { token: 't', session_id: 's' }, error: { code: 'X', message: 'y' } }))).toThrow(/exactly one/);
    expect(() => readParafe(bad({ consent: { token: 't' } }))).toThrow(/session_id/);
    expect(() => readParafe(bad({ handshake_challenge: { ...CHALLENGE, challenge: 'short' } }))).toThrow(/64-character hex/);
    expect(() => readParafe(bad({ handshake_challenge: { ...CHALLENGE, requested_permissions: [1] } }))).toThrow(/requested_permissions/);
    expect(() => readParafe(bad({ handshake_complete: { handshake_id: 'h', status: 'maybe' } }))).toThrow(/status/);
    expect(() => readParafe(bad({ handshake_complete: { handshake_id: 'h', status: 'authenticated' } }))).toThrow(/consent_token/);
  });
});

describe('readParafe (v1 data parts)', () => {
  const v1Consent = { 'parafe.trust.ConsentToken': { token: 'jwt', session_id: 's' } };

  it('reads A2A 0.3 parts: { kind: "data", data }', () => {
    const message = { parts: [{ kind: 'text', text: 'hi' }, { kind: 'data', data: v1Consent }] };
    expect(extractConsentToken(message)).toEqual({ token: 'jwt', session_id: 's' });
  });

  it('reads A2A 1.0 wire parts: { data } with no kind', () => {
    const message = { parts: [{ text: 'hi' }, { data: v1Consent, mediaType: 'application/json' }] };
    expect(extractConsentToken(message)).toEqual({ token: 'jwt', session_id: 's' });
  });

  it('reads @a2a-js/sdk parts: { content: { $case: "data", value } }', () => {
    const message = { parts: [{ content: { $case: 'data', value: { 'parafe.handshake.Challenge': CHALLENGE } } }] };
    expect(extractHandshakeChallenge(message)).toEqual(CHALLENGE);
  });

  it('reads a v1 handshake complete', () => {
    const complete = { handshake_id: 'hs_1', status: 'authenticated', consent_token: 'jwt' };
    expect(extractHandshakeComplete({ parts: [{ data: { 'parafe.handshake.Complete': complete } }] })).toEqual(complete);
  });

  it('ignores v1 parts when acceptV1 is false', () => {
    const message = { parts: [{ kind: 'data', data: v1Consent }] };
    expect(extractConsentToken(message, { acceptV1: false })).toBeNull();
    expect(hasParafeData(message, { acceptV1: false })).toBe(false);
  });

  it('prefers v2 metadata over v1 parts', () => {
    const message = withConsentToken({ parts: [{ kind: 'data', data: v1Consent }] }, 'v2jwt', 's2');
    expect(extractConsentToken(message)).toEqual({ token: 'v2jwt', session_id: 's2' });
  });

  it('validates v1 payloads too', () => {
    const message = { parts: [{ kind: 'data', data: { 'parafe.trust.ConsentToken': { token: 'jwt' } } }] };
    expect(() => extractConsentToken(message)).toThrow(MalformedParafeDataError);
  });

  it('ignores non-Parafe and non-data parts', () => {
    const message = { parts: [{ kind: 'file', file: { uri: 'x' } }, { data: { other: 1 } }, { content: { $case: 'text', value: 'x' } }, null, 'junk'] };
    expect(readParafe(message)).toBeNull();
  });
});

describe('hasParafeData', () => {
  it('is true for v2 metadata and for v1 parts', () => {
    expect(hasParafeData(withConsentToken(baseMessage(), 'jwt', 's'))).toBe(true);
    expect(hasParafeData({ parts: [{ data: { 'parafe.trust.ConsentToken': {} } }] })).toBe(true);
  });

  it('is false otherwise', () => {
    expect(hasParafeData(baseMessage())).toBe(false);
  });
});

describe('parafeErrorData', () => {
  it('reports this package\'s errors by code and message', () => {
    const err = new ExpiredConsentTokenError(new Date('2026-09-27T20:00:00Z'));
    expect(parafeErrorData(err)).toEqual({ error: { code: 'EXPIRED_CONSENT_TOKEN', message: err.message } });
  });

  it('does not leak other errors\' messages', () => {
    expect(parafeErrorData(new Error('db password is hunter2'))).toEqual({
      error: { code: 'INVALID_CONSENT_TOKEN', message: 'Parafe consent could not be verified.' },
    });
  });

  it('round-trips through withParafe and extractParafeError', () => {
    const reply = withParafe(baseMessage(), parafeErrorData(new MalformedParafeDataError('consent')));
    expect(extractParafeError(reply)?.code).toBe('MALFORMED_PARAFE_DATA');
  });
});
