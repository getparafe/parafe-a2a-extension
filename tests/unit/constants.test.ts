import { describe, it, expect } from 'vitest';
import {
  PARAFE_EXTENSION_URI,
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
  PARAFE_ACTIVATION_HEADER_VALUE,
  DEFAULT_BROKER_URL,
} from '../../src/index.js';

describe('constants', () => {
  it('extension URI is the canonical v1 URI', () => {
    expect(PARAFE_EXTENSION_URI).toBe(
      'https://github.com/getparafe/parafe-a2a-extension/v1'
    );
  });

  it('metadata field keys are namespaced under the extension URI', () => {
    expect(PARAFE_AGENT_ID_FIELD).toBe(`${PARAFE_EXTENSION_URI}/agent-id`);
    expect(PARAFE_CONSENT_TOKEN_FIELD).toBe(`${PARAFE_EXTENSION_URI}/consent-token`);
    expect(PARAFE_SESSION_ID_FIELD).toBe(`${PARAFE_EXTENSION_URI}/session-id`);
  });

  it('activation header value matches extension URI', () => {
    expect(PARAFE_ACTIVATION_HEADER_VALUE).toBe(PARAFE_EXTENSION_URI);
  });

  it('default broker URL is api.parafe.ai', () => {
    expect(DEFAULT_BROKER_URL).toBe('https://api.parafe.ai');
  });
});
