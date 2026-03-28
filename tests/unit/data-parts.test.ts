import { describe, it, expect } from 'vitest';
import {
  buildHandshakeChallenge,
  buildHandshakeComplete,
  buildConsentTokenPart,
  extractHandshakeChallenge,
  extractHandshakeComplete,
  extractConsentToken,
  hasParafeDataPart,
  MalformedDataPartError,
  PARAFE_HANDSHAKE_CHALLENGE,
  PARAFE_HANDSHAKE_COMPLETE,
  PARAFE_TRUST_CONSENT_TOKEN,
} from '../../src/index.js';
import type { A2AMessagePart } from '../../src/index.js';

describe('buildHandshakeChallenge', () => {
  it('builds a correctly structured DataPart', () => {
    const part = buildHandshakeChallenge({
      handshake_id: 'hs_abc123',
      challenge: '9f4a2c8e1b3d7f0a',
      initiator_agent_id: 'prf_agent_sofia01',
      broker_url: 'https://api.parafe.ai',
      requested_scope: 'order-donuts',
    });

    expect(part.kind).toBe('data');
    expect(part.data[PARAFE_HANDSHAKE_CHALLENGE]).toEqual({
      handshake_id: 'hs_abc123',
      challenge: '9f4a2c8e1b3d7f0a',
      initiator_agent_id: 'prf_agent_sofia01',
      broker_url: 'https://api.parafe.ai',
      requested_scope: 'order-donuts',
    });
  });
});

describe('buildHandshakeComplete', () => {
  it('builds authenticated DataPart with consent token', () => {
    const part = buildHandshakeComplete({
      handshake_id: 'hs_abc123',
      status: 'authenticated',
      consent_token: 'eyJ.test.token',
    });

    expect(part.kind).toBe('data');
    expect(part.data[PARAFE_HANDSHAKE_COMPLETE].status).toBe('authenticated');
    expect(part.data[PARAFE_HANDSHAKE_COMPLETE].consent_token).toBe('eyJ.test.token');
  });

  it('builds error DataPart', () => {
    const part = buildHandshakeComplete({
      handshake_id: 'hs_abc123',
      status: 'rejected',
      error_code: 'authorization_insufficient',
      error_message: 'Requires verified modality',
    });

    expect(part.data[PARAFE_HANDSHAKE_COMPLETE].status).toBe('rejected');
    expect(part.data[PARAFE_HANDSHAKE_COMPLETE].error_code).toBe('authorization_insufficient');
  });
});

describe('buildConsentTokenPart', () => {
  it('builds a consent token DataPart', () => {
    const part = buildConsentTokenPart('eyJ.token.here', 'sess_xyz789');

    expect(part.kind).toBe('data');
    expect(part.data[PARAFE_TRUST_CONSENT_TOKEN]).toEqual({
      token: 'eyJ.token.here',
      session_id: 'sess_xyz789',
    });
  });
});

describe('extractHandshakeChallenge', () => {
  it('extracts challenge from parts array', () => {
    const parts: A2AMessagePart[] = [
      buildHandshakeChallenge({
        handshake_id: 'hs_abc123',
        challenge: '9f4a',
        initiator_agent_id: 'prf_agent_1',
        broker_url: 'https://api.parafe.ai',
        requested_scope: 'test',
      }),
    ];

    const payload = extractHandshakeChallenge(parts);
    expect(payload).not.toBeNull();
    expect(payload!.handshake_id).toBe('hs_abc123');
    expect(payload!.requested_scope).toBe('test');
  });

  it('returns null when no challenge DataPart is present', () => {
    const parts: A2AMessagePart[] = [{ kind: 'text', text: 'hello' }];
    expect(extractHandshakeChallenge(parts)).toBeNull();
  });

  it('returns null for empty parts array', () => {
    expect(extractHandshakeChallenge([])).toBeNull();
  });

  it('throws MalformedDataPartError when fields are missing', () => {
    const parts: A2AMessagePart[] = [
      { kind: 'data', data: { [PARAFE_HANDSHAKE_CHALLENGE]: { handshake_id: 'hs_1' } } },
    ];

    expect(() => extractHandshakeChallenge(parts)).toThrow(MalformedDataPartError);
  });
});

describe('extractHandshakeComplete', () => {
  it('extracts complete from parts array', () => {
    const parts: A2AMessagePart[] = [
      buildHandshakeComplete({
        handshake_id: 'hs_abc123',
        status: 'authenticated',
        consent_token: 'eyJ.test',
      }),
    ];

    const payload = extractHandshakeComplete(parts);
    expect(payload).not.toBeNull();
    expect(payload!.status).toBe('authenticated');
    expect(payload!.consent_token).toBe('eyJ.test');
  });

  it('returns null when not present', () => {
    expect(extractHandshakeComplete([{ kind: 'text', text: 'hi' }])).toBeNull();
  });

  it('throws MalformedDataPartError when required fields are missing', () => {
    const parts: A2AMessagePart[] = [
      { kind: 'data', data: { [PARAFE_HANDSHAKE_COMPLETE]: {} } },
    ];

    expect(() => extractHandshakeComplete(parts)).toThrow(MalformedDataPartError);
  });
});

describe('extractConsentToken', () => {
  it('extracts consent token from parts array', () => {
    const parts: A2AMessagePart[] = [
      buildConsentTokenPart('eyJ.jwt', 'sess_123'),
      { kind: 'text', text: 'Show me flights' },
    ];

    const payload = extractConsentToken(parts);
    expect(payload).not.toBeNull();
    expect(payload!.token).toBe('eyJ.jwt');
    expect(payload!.session_id).toBe('sess_123');
  });

  it('returns null when not present', () => {
    expect(extractConsentToken([{ kind: 'text', text: 'hi' }])).toBeNull();
  });

  it('throws MalformedDataPartError when fields are missing', () => {
    const parts: A2AMessagePart[] = [
      { kind: 'data', data: { [PARAFE_TRUST_CONSENT_TOKEN]: { token: 'eyJ' } } },
    ];

    expect(() => extractConsentToken(parts)).toThrow(MalformedDataPartError);
  });
});

describe('hasParafeDataPart', () => {
  it('returns true when a challenge is present', () => {
    const parts: A2AMessagePart[] = [
      buildHandshakeChallenge({
        handshake_id: 'hs_1',
        challenge: 'abc',
        initiator_agent_id: 'prf_1',
        broker_url: 'https://api.parafe.ai',
        requested_scope: 'test',
      }),
    ];
    expect(hasParafeDataPart(parts)).toBe(true);
  });

  it('returns true when a consent token is present', () => {
    const parts: A2AMessagePart[] = [buildConsentTokenPart('eyJ', 'sess_1')];
    expect(hasParafeDataPart(parts)).toBe(true);
  });

  it('returns false for text-only parts', () => {
    expect(hasParafeDataPart([{ kind: 'text', text: 'hello' }])).toBe(false);
  });

  it('returns false for empty parts', () => {
    expect(hasParafeDataPart([])).toBe(false);
  });

  it('returns false for non-Parafe data parts', () => {
    const parts: A2AMessagePart[] = [
      { kind: 'data', data: { 'some.other.extension': {} } },
    ];
    expect(hasParafeDataPart(parts)).toBe(false);
  });
});
