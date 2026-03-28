import { describe, it, expect } from 'vitest';
import {
  PARAFE_EXTENSION_URI,
  PARAFE_HANDSHAKE_CHALLENGE,
  PARAFE_HANDSHAKE_COMPLETE,
  PARAFE_TRUST_CONSENT_TOKEN,
  DEFAULT_BROKER_URL,
} from '../../src/index.js';

describe('constants', () => {
  it('extension URI is the canonical v1 URI', () => {
    expect(PARAFE_EXTENSION_URI).toBe(
      'https://github.com/getparafe/parafe-a2a-extension/v1'
    );
  });

  it('DataPart type keys use parafe namespace', () => {
    expect(PARAFE_HANDSHAKE_CHALLENGE).toBe('parafe.handshake.Challenge');
    expect(PARAFE_HANDSHAKE_COMPLETE).toBe('parafe.handshake.Complete');
    expect(PARAFE_TRUST_CONSENT_TOKEN).toBe('parafe.trust.ConsentToken');
  });

  it('default broker URL is api.parafe.ai', () => {
    expect(DEFAULT_BROKER_URL).toBe('https://api.parafe.ai');
  });
});
