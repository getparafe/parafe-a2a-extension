import { describe, it, expect } from 'vitest';
import {
  buildAgentCardExtension,
  parseAgentCardExtension,
  PARAFE_EXTENSION_URI,
  DEFAULT_BROKER_URL,
} from '../../src/index.js';

describe('buildAgentCardExtension', () => {
  const scopeRequirements = {
    'check-menu': {
      permissions: ['read_menu', 'read_availability'] as string[],
      minimum_authorization_modality: 'autonomous' as const,
    },
    'order-donuts': {
      permissions: ['read_menu', 'create_order', 'process_payment'] as string[],
      minimum_authorization_modality: 'attested' as const,
    },
  };

  it('builds a complete extension entry with defaults', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_donuts01',
      scopeRequirements,
    });

    expect(ext.uri).toBe(PARAFE_EXTENSION_URI);
    expect(ext.required).toBe(true);
    expect(ext.params.agent_id).toBe('prf_agent_donuts01');
    expect(ext.params.broker_url).toBe(DEFAULT_BROKER_URL);
    expect(ext.params.minimum_identity_assurance).toBe('self_registered');
    expect(ext.params.scope_requirements).toEqual(scopeRequirements);
  });

  it('respects custom broker URL', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      brokerUrl: 'https://custom-broker.example.com',
    });

    expect(ext.params.broker_url).toBe('https://custom-broker.example.com');
  });

  it('respects custom identity assurance', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      minimumIdentityAssurance: 'registered',
    });

    expect(ext.params.minimum_identity_assurance).toBe('registered');
  });

  it('respects required: false', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      required: false,
    });

    expect(ext.required).toBe(false);
  });

  it('includes description when provided', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      description: 'Custom description',
    });

    expect(ext.description).toBe('Custom description');
  });

  it('omits description when not provided', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
    });

    expect(ext.description).toBeUndefined();
  });
});

describe('parseAgentCardExtension', () => {
  it('finds and parses a Parafe extension from mixed extensions array', () => {
    const extensions = [
      { uri: 'https://other.extension/v1', required: false },
      {
        uri: PARAFE_EXTENSION_URI,
        required: true,
        params: {
          agent_id: 'prf_agent_donuts01',
          broker_url: 'https://api.parafe.ai',
          minimum_identity_assurance: 'self_registered',
          scope_requirements: {
            'check-menu': {
              permissions: ['read_menu'],
              minimum_authorization_modality: 'autonomous',
            },
          },
        },
      },
    ];

    const result = parseAgentCardExtension(extensions);
    expect(result).not.toBeNull();
    expect(result!.uri).toBe(PARAFE_EXTENSION_URI);
    expect(result!.required).toBe(true);
    expect(result!.params.agent_id).toBe('prf_agent_donuts01');
    expect(Object.keys(result!.params.scope_requirements)).toEqual(['check-menu']);
  });

  it('returns null when no Parafe extension is present', () => {
    const extensions = [{ uri: 'https://other.extension/v1', required: false }];
    expect(parseAgentCardExtension(extensions)).toBeNull();
  });

  it('returns null for empty extensions array', () => {
    expect(parseAgentCardExtension([])).toBeNull();
  });

  it('returns null when params block is missing', () => {
    const extensions = [{ uri: PARAFE_EXTENSION_URI, required: true }];
    expect(parseAgentCardExtension(extensions)).toBeNull();
  });

  it('returns null when agent_id is missing from params', () => {
    const extensions = [
      {
        uri: PARAFE_EXTENSION_URI,
        required: true,
        params: {
          broker_url: 'https://api.parafe.ai',
          minimum_identity_assurance: 'self_registered',
          scope_requirements: {},
        },
      },
    ];
    expect(parseAgentCardExtension(extensions)).toBeNull();
  });

  it('returns null when identity assurance is invalid', () => {
    const extensions = [
      {
        uri: PARAFE_EXTENSION_URI,
        required: true,
        params: {
          agent_id: 'prf_1',
          broker_url: 'https://api.parafe.ai',
          minimum_identity_assurance: 'invalid_value',
          scope_requirements: {},
        },
      },
    ];
    expect(parseAgentCardExtension(extensions)).toBeNull();
  });

  it('preserves description when present', () => {
    const extensions = [
      {
        uri: PARAFE_EXTENSION_URI,
        required: true,
        description: 'Requires Parafe trust',
        params: {
          agent_id: 'prf_1',
          broker_url: 'https://api.parafe.ai',
          minimum_identity_assurance: 'registered',
          scope_requirements: {},
        },
      },
    ];

    const result = parseAgentCardExtension(extensions);
    expect(result!.description).toBe('Requires Parafe trust');
  });
});
