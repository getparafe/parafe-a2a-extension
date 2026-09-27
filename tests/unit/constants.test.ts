import { describe, it, expect } from 'vitest';
import {
  PARAFE_EXTENSION_URI,
  PARAFE_EXTENSION_URI_V1,
  A2A_EXTENSIONS_HEADER,
  A2A_EXTENSIONS_HEADER_V0_3,
  A2A_VERSION_HEADER,
  PARAFE_V1_HANDSHAKE_CHALLENGE,
  PARAFE_V1_HANDSHAKE_COMPLETE,
  PARAFE_V1_CONSENT_TOKEN,
  DEFAULT_BROKER_URL,
} from '../../src/index.js';

describe('constants', () => {
  it('extension URI is the v2 URI, where the specification is hosted', () => {
    expect(PARAFE_EXTENSION_URI).toBe('https://parafe.ai/extensions/a2a/v2');
  });

  it('keeps the v1 URI for reading older cards', () => {
    expect(PARAFE_EXTENSION_URI_V1).toBe('https://github.com/getparafe/parafe-a2a-extension/v1');
  });

  it('A2A header names match the A2A 1.0 and 0.3 specs', () => {
    expect(A2A_EXTENSIONS_HEADER).toBe('A2A-Extensions');
    expect(A2A_EXTENSIONS_HEADER_V0_3).toBe('X-A2A-Extensions');
    expect(A2A_VERSION_HEADER).toBe('A2A-Version');
  });

  it('v1 data part keys are unchanged', () => {
    expect(PARAFE_V1_HANDSHAKE_CHALLENGE).toBe('parafe.handshake.Challenge');
    expect(PARAFE_V1_HANDSHAKE_COMPLETE).toBe('parafe.handshake.Complete');
    expect(PARAFE_V1_CONSENT_TOKEN).toBe('parafe.trust.ConsentToken');
  });

  it('default broker URL is api.parafe.ai', () => {
    expect(DEFAULT_BROKER_URL).toBe('https://api.parafe.ai');
  });
});
