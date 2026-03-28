import { describe, it, expect } from 'vitest';
import {
  buildExtensionMetadata,
  getAgentCardExtension,
  activationHeaderValue,
  PARAFE_EXTENSION_URI,
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
} from '../../src/index.js';

describe('buildExtensionMetadata', () => {
  it('builds metadata with agent ID and consent token', () => {
    const metadata = buildExtensionMetadata({
      agentId: 'prf_agent_abc123',
      consentToken: 'eyJ.test.token',
    });

    expect(metadata[PARAFE_AGENT_ID_FIELD]).toBe('prf_agent_abc123');
    expect(metadata[PARAFE_CONSENT_TOKEN_FIELD]).toBe('eyJ.test.token');
    expect(metadata[PARAFE_SESSION_ID_FIELD]).toBeUndefined();
  });

  it('includes session ID when provided', () => {
    const metadata = buildExtensionMetadata({
      agentId: 'prf_agent_abc123',
      consentToken: 'eyJ.test.token',
      sessionId: 'sess_xyz789',
    });

    expect(metadata[PARAFE_SESSION_ID_FIELD]).toBe('sess_xyz789');
  });

  it('returns only namespaced keys', () => {
    const metadata = buildExtensionMetadata({
      agentId: 'prf_agent_abc123',
      consentToken: 'eyJ.test.token',
    });

    const keys = Object.keys(metadata);
    for (const key of keys) {
      expect(key).toContain(PARAFE_EXTENSION_URI);
    }
  });
});

describe('getAgentCardExtension', () => {
  it('returns an extension entry with the correct URI', () => {
    const ext = getAgentCardExtension();
    expect(ext.uri).toBe(PARAFE_EXTENSION_URI);
  });

  it('sets required to false by default', () => {
    const ext = getAgentCardExtension();
    expect(ext.required).toBe(false);
  });

  it('includes a description', () => {
    const ext = getAgentCardExtension();
    expect(ext.description).toBeTruthy();
    expect(ext.description.length).toBeGreaterThan(20);
  });
});

describe('activationHeaderValue', () => {
  it('matches the extension URI', () => {
    expect(activationHeaderValue).toBe(PARAFE_EXTENSION_URI);
  });
});
