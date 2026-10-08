import { calculateJwkThumbprint, type JWK } from 'jose';
import { PARAFE_EXTENSION_URI, DEFAULT_BROKER_URL } from './constants.js';
import type {
  ParafeAgentCardExtension,
  ParafeExtensionParams,
  BuildAgentCardOptions,
  ScopeRequirement,
  ScopePolicyLike,
  TrustedIssuerRef,
} from './types.js';

const NUMERIC_FLOORS = [
  'minimum_tenure_days',
  'minimum_session_completion_rate',
  'maximum_denied_requests_30d',
  'minimum_unique_counterparties',
  'minimum_handshake_success_rate',
] as const;
const ASSURANCES = new Set(['self_registered', 'registered', 'claimed']);
const TIERS = new Set(['unverified', 'email_verified', 'domain_verified', 'org_verified']);

/**
 * 3.2: builds the card's `scope_requirements` from the agent's broker scope
 * policies (the `scope_policies` of `GET /agents/{id}/scope-policies`), so the
 * card says exactly what the broker enforces and can't drift from it. Trusted
 * AP2 issuers are named by key thumbprint, not by key. Issuers the broker trusts
 * for every agent (its own list) aren't in a scope policy, so not here either.
 *
 * @example
 * const { scope_policies } = await (await fetch(`${broker}/agents/${agentId}/scope-policies`)).json();
 * const ext = buildAgentCardExtension({ agentId, required: false, scopeRequirements: await scopeRequirementsFromPolicies(scope_policies) });
 */
export async function scopeRequirementsFromPolicies(
  scopePolicies: Record<string, ScopePolicyLike>
): Promise<Record<string, ScopeRequirement>> {
  const out: Record<string, ScopeRequirement> = {};
  for (const [scope, policy] of Object.entries(scopePolicies ?? {})) {
    const req: ScopeRequirement = {
      permissions: Array.isArray(policy.permissions) ? [...policy.permissions] : [],
      minimum_authorization_modality: policy.minimum_authorization_modality ?? 'autonomous',
    };
    if (Array.isArray(policy.exclusions)) req.exclusions = [...policy.exclusions];
    if (policy.minimum_identity_assurance) req.minimum_identity_assurance = policy.minimum_identity_assurance;
    if (policy.minimum_verification_tier) req.minimum_verification_tier = policy.minimum_verification_tier;
    if (policy.minimum_initiator_proof) req.minimum_initiator_proof = policy.minimum_initiator_proof;
    for (const k of NUMERIC_FLOORS) {
      const v = policy[k];
      if (typeof v === 'number') req[k] = v;
    }
    if (Array.isArray(policy.ap2_trusted_issuers) && policy.ap2_trusted_issuers.length) {
      req.trusted_issuers = await Promise.all(policy.ap2_trusted_issuers.map(async (i): Promise<TrustedIssuerRef> => ({
        ...(i.name ? { name: i.name } : {}),
        ...(i.iss ? { iss: i.iss } : {}),
        ...(i.kid ? { kid: i.kid } : {}),
        jkt: await calculateJwkThumbprint(i.jwk as JWK),
      })));
    }
    out[scope] = req;
  }
  return out;
}

/**
 * Builds a Parafe extension entry for an AgentCard's capabilities.extensions array.
 * The result declares what scopes this agent supports and what policy requirements
 * must be met, so discovering agents know what to expect before initiating a handshake.
 *
 * `required` is an explicit choice: `true` turns away every caller that doesn't use
 * Parafe (A2A 1.0 SDKs enforce this before your code runs); `false` also serves
 * callers without Parafe, and you check consent per scoped action.
 *
 * @example
 * const ext = buildAgentCardExtension({
 *   agentId: 'prf_agent_donuts01',
 *   required: false,
 *   scopeRequirements: {
 *     'check-menu': {
 *       permissions: ['read_menu', 'read_availability'],
 *       minimum_authorization_modality: 'autonomous',
 *     },
 *     'order-donuts': {
 *       permissions: ['read_menu', 'create_order', 'process_payment'],
 *       minimum_authorization_modality: 'attested',
 *     },
 *   },
 * });
 *
 * const agentCard = {
 *   name: 'Agent Donuts',
 *   capabilities: { extensions: [ext] },
 * };
 */
export function buildAgentCardExtension(
  options: BuildAgentCardOptions
): ParafeAgentCardExtension {
  return {
    uri: PARAFE_EXTENSION_URI,
    required: options.required,
    ...(options.description !== undefined ? { description: options.description } : {}),
    params: {
      agent_id: options.agentId,
      broker_url: options.brokerUrl ?? DEFAULT_BROKER_URL,
      minimum_identity_assurance: options.minimumIdentityAssurance ?? 'self_registered',
      scope_requirements: options.scopeRequirements,
    },
  };
}

/**
 * Finds and parses a Parafe extension entry from an AgentCard's capabilities.extensions array.
 * Returns null if no valid Parafe extension is found.
 *
 * Use this when your agent fetches another agent's AgentCard and wants to determine
 * whether Parafe trust is required and what scopes are available.
 *
 * @example
 * const agentCard = await fetchAgentCard('https://agentdonuts.com/.well-known/agent-card.json');
 * const parafe = parseAgentCardExtension(agentCard.capabilities.extensions);
 * if (parafe) {
 *   console.log('Parafe required:', parafe.required);
 *   console.log('Broker URL:', parafe.params.broker_url);
 *   console.log('Available scopes:', Object.keys(parafe.params.scope_requirements));
 * }
 */
export function parseAgentCardExtension(
  extensions: ReadonlyArray<{ uri: string; [key: string]: unknown }> | null | undefined
): ParafeAgentCardExtension | null {
  const list = extensions ?? [];
  const entry = list.find((ext) => ext?.uri === PARAFE_EXTENSION_URI);
  if (!entry) return null;

  const params = entry['params'] as Record<string, unknown> | undefined;
  if (!params || typeof params !== 'object') return null;

  // Validate required params fields
  if (typeof params['agent_id'] !== 'string') return null;
  if (typeof params['broker_url'] !== 'string') return null;

  const identityAssurance = params['minimum_identity_assurance'];
  if (identityAssurance !== 'self_registered' && identityAssurance !== 'registered' && identityAssurance !== 'claimed') return null;

  const scopeReqs = params['scope_requirements'];
  if (!scopeReqs || typeof scopeReqs !== 'object') return null;

  // Validate scope requirements have valid modality values
  const validModalities = new Set(['autonomous', 'attested', 'delegated', 'verified']);
  for (const [, req] of Object.entries(scopeReqs as Record<string, Record<string, unknown>>)) {
    if (!req || typeof req !== 'object') return null;
    if (!Array.isArray(req['permissions'])) return null;
    const modality = req['minimum_authorization_modality'];
    if (modality !== undefined && !validModalities.has(modality as string)) return null;
    const assurance = req['minimum_identity_assurance'];
    if (assurance !== undefined && !ASSURANCES.has(assurance as string)) return null;
    const tier = req['minimum_verification_tier'];
    if (tier !== undefined && !TIERS.has(tier as string)) return null;
    const exclusions = req['exclusions'];
    if (exclusions !== undefined && !Array.isArray(exclusions)) return null;
    const issuers = req['trusted_issuers'];
    if (issuers !== undefined) {
      if (!Array.isArray(issuers)) return null;
      for (const i of issuers as Array<Record<string, unknown>>) {
        if (!i || typeof i !== 'object' || typeof i['jkt'] !== 'string' || !i['jkt']) return null;
      }
    }
  }

  return {
    uri: entry.uri,
    required: entry['required'] === true,
    ...(typeof entry['description'] === 'string' ? { description: entry['description'] } : {}),
    params: {
      agent_id: params['agent_id'] as string,
      broker_url: params['broker_url'] as string,
      minimum_identity_assurance: identityAssurance,
      scope_requirements: scopeReqs as Record<string, ScopeRequirement>,
    },
  };
}
