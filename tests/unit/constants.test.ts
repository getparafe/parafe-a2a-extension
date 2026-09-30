import { describe, it, expect } from 'vitest';
import {
  PARAFE_EXTENSION_URI,
  A2A_EXTENSIONS_HEADER,
  A2A_EXTENSIONS_HEADER_V0_3,
  A2A_VERSION_HEADER,
  DEFAULT_BROKER_URL,
} from '../../src/index.js';

describe('constants', () => {
  it('extension URI is the v2 URI, where the specification is hosted', () => {
    expect(PARAFE_EXTENSION_URI).toBe('https://parafe.ai/extensions/a2a/v2');
  });

  it('A2A header names match the A2A 1.0 and 0.3 specs', () => {
    expect(A2A_EXTENSIONS_HEADER).toBe('A2A-Extensions');
    expect(A2A_EXTENSIONS_HEADER_V0_3).toBe('X-A2A-Extensions');
    expect(A2A_VERSION_HEADER).toBe('A2A-Version');
  });

  it('default broker URL is api.parafe.ai', () => {
    expect(DEFAULT_BROKER_URL).toBe('https://api.parafe.ai');
  });
});
