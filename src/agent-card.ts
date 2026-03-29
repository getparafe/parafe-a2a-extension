import { PARAFE_EXTENSION_URI, DEFAULT_BROKER_URL } from './constants.js';
import type {
  ParafeAgentCardExtension,
  ParafeExtensionParams,
  BuildAgentCardOptions,
  ScopeRequirement,
} from './types.js';

/**
 * Builds a Parafe extension entry for an AgentCard's capabilities.extensions array.
 * The result declares what scopes this agent supports and what policy requirements
 * must be met, so discovering agents know what to expect before initiating a handshake.
 *
 * @example
 * const ext = buildAgentCardExtension({
 *   agentId: 'prf_agent_donuts01',
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
    required: options.required ?? true,
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
 * Returns null if no Parafe extension is found.
 *
 * Use this when your agent fetches another agent's AgentCard and wants to determine
 * whether Parafe trust is required and what scopes are available.
 *
 * @example
 * const agentCard = await fetchAgentCard('https://agentdonuts.com/.well-known/agent.json');
 * const parafe = parseAgentCardExtension(agentCard.capabilities.extensions);
 * if (parafe) {
 *   console.log('Parafe required:', parafe.required);
 *   console.log('Broker URL:', parafe.params.broker_url);
 *   console.log('Available scopes:', Object.keys(parafe.params.scope_requirements));
 * }
 */
export function parseAgentCardExtension(
  extensions: Array<{ uri: string; [key: string]: unknown }>
): ParafeAgentCardExtension | null {
  const entry = extensions.find((ext) => ext.uri === PARAFE_EXTENSION_URI);
  if (!entry) return null;

  const params = entry['params'] as Record<string, unknown> | undefined;
  if (!params || typeof params !== 'object') return null;

  // Validate required params fields
  if (typeof params['agent_id'] !== 'string') return null;
  if (typeof params['broker_url'] !== 'string') return null;

  const identityAssurance = params['minimum_identity_assurance'];
  if (identityAssurance !== 'registered' && identityAssurance !== 'self_registered') return null;

  const scopeReqs = params['scope_requirements'];
  if (!scopeReqs || typeof scopeReqs !== 'object') return null;

  // Validate scope requirements have valid modality values
  const validModalities = new Set(['autonomous', 'attested', 'verified']);
  for (const [, req] of Object.entries(scopeReqs as Record<string, Record<string, unknown>>)) {
    if (!req || typeof req !== 'object') return null;
    if (!Array.isArray(req['permissions'])) return null;
    const modality = req['minimum_authorization_modality'];
    if (modality !== undefined && !validModalities.has(modality as string)) return null;
  }

  return {
    uri: PARAFE_EXTENSION_URI,
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
