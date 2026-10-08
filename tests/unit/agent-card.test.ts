import { describe, it, expect } from 'vitest';
import { calculateJwkThumbprint } from 'jose';
import {
  buildAgentCardExtension,
  parseAgentCardExtension,
  scopeRequirementsFromPolicies,
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
      required: true,
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
      required: true,
      brokerUrl: 'https://custom-broker.example.com',
    });

    expect(ext.params.broker_url).toBe('https://custom-broker.example.com');
  });

  it('respects custom identity assurance', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      required: true,
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
      required: true,
      description: 'Custom description',
    });

    expect(ext.description).toBe('Custom description');
  });

  it('omits description when not provided', () => {
    const ext = buildAgentCardExtension({
      agentId: 'prf_agent_1',
      scopeRequirements,
      required: true,
    });

    expect(ext.description).toBeUndefined();
  });
});

describe('parseAgentCardExtension', () => {
  const params = {
    agent_id: 'prf_agent_donuts01',
    broker_url: 'https://api.parafe.ai',
    minimum_identity_assurance: 'self_registered',
    scope_requirements: { 'check-menu': { permissions: ['read_menu'], minimum_authorization_modality: 'autonomous' } },
  };

  it('3.0: ignores a v1 card', () => {
    expect(parseAgentCardExtension([{ uri: 'https://github.com/getparafe/parafe-a2a-extension/v1', required: true, params }])).toBeNull();
  });

  it("accepts minimum_identity_assurance 'claimed' (an agent its principal approved)", () => {
    const result = parseAgentCardExtension([{ uri: PARAFE_EXTENSION_URI, required: true, params: { ...params, minimum_identity_assurance: 'claimed' } }]);
    expect(result?.params.minimum_identity_assurance).toBe('claimed');
  });

  it("B8: accepts a scope that requires 'delegated'; still refuses an unknown modality", () => {
    const withDelegated = { ...params, scope_requirements: { pay: { permissions: ['pay'], minimum_authorization_modality: 'delegated' } } };
    expect(parseAgentCardExtension([{ uri: PARAFE_EXTENSION_URI, required: true, params: withDelegated }])?.params.scope_requirements.pay?.minimum_authorization_modality).toBe('delegated');
    const bogus = { ...params, scope_requirements: { pay: { permissions: ['pay'], minimum_authorization_modality: 'supervised' } } };
    expect(parseAgentCardExtension([{ uri: PARAFE_EXTENSION_URI, required: true, params: bogus }])).toBeNull();
  });

  it('finds the v2 entry beside a v1 one', () => {
    const result = parseAgentCardExtension([
      { uri: 'https://github.com/getparafe/parafe-a2a-extension/v1', required: true, params: { ...params, agent_id: 'prf_agent_v1' } },
      { uri: PARAFE_EXTENSION_URI, required: false, params: { ...params, agent_id: 'prf_agent_v2' } },
    ]);
    expect(result?.uri).toBe(PARAFE_EXTENSION_URI);
    expect(result?.params.agent_id).toBe('prf_agent_v2');
  });

  it('accepts a missing extensions list', () => {
    expect(parseAgentCardExtension(undefined)).toBeNull();
  });


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

describe('scopeRequirementsFromPolicies (broker scope policies to card scope requirements)', () => {
  const issuerJwk = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
  const policies = {
    'check-menu': { permissions: ['read_menu'], exclusions: [] },
    'place-order': {
      permissions: ['create_order', 'pay'],
      exclusions: ['refund'],
      minimum_authorization_modality: 'verified',
      minimum_identity_assurance: 'claimed',
      minimum_verification_tier: 'email_verified',
      minimum_initiator_proof: 'pop',
      minimum_tenure_days: 7,
      ap2_trusted_issuers: [{ jwk: issuerJwk, kid: 'wallet-1', iss: 'https://wallet.example', name: 'Example Wallet' }],
      description: 'Orders',
    },
  };

  it('copies the rules and names trusted issuers by thumbprint, without their keys', async () => {
    const reqs = await scopeRequirementsFromPolicies(policies);
    expect(reqs['check-menu']).toEqual({ permissions: ['read_menu'], minimum_authorization_modality: 'autonomous', exclusions: [] });
    expect(reqs['place-order']).toEqual({
      permissions: ['create_order', 'pay'],
      exclusions: ['refund'],
      minimum_authorization_modality: 'verified',
      minimum_identity_assurance: 'claimed',
      minimum_verification_tier: 'email_verified',
      minimum_initiator_proof: 'pop',
      minimum_tenure_days: 7,
      trusted_issuers: [{ name: 'Example Wallet', iss: 'https://wallet.example', kid: 'wallet-1', jkt: await calculateJwkThumbprint(issuerJwk) }],
    });
    expect(JSON.stringify(reqs)).not.toContain(issuerJwk.x);
  });

  it('builds a card whose scope requirements parse back unchanged', async () => {
    const scopeRequirements = await scopeRequirementsFromPolicies(policies);
    const ext = buildAgentCardExtension({ agentId: 'prf_agent_shop', required: false, scopeRequirements });
    const parsed = parseAgentCardExtension([ext as unknown as { uri: string }]);
    expect(parsed?.params.scope_requirements).toEqual(scopeRequirements);
  });

  it('parse refuses a card with an unknown tier or a trusted issuer without a thumbprint', () => {
    const card = (req: Record<string, unknown>) => [{ uri: PARAFE_EXTENSION_URI, required: false, params: { agent_id: 'a', broker_url: DEFAULT_BROKER_URL, minimum_identity_assurance: 'self_registered', scope_requirements: { s: { permissions: [], ...req } } } }];
    expect(parseAgentCardExtension(card({ minimum_verification_tier: 'gold' }))).toBeNull();
    expect(parseAgentCardExtension(card({ minimum_identity_assurance: 'very' }))).toBeNull();
    expect(parseAgentCardExtension(card({ trusted_issuers: [{ name: 'x' }] }))).toBeNull();
    expect(parseAgentCardExtension(card({ minimum_verification_tier: 'email_verified', trusted_issuers: [{ jkt: 'abc' }] }))).not.toBeNull();
  });
});
