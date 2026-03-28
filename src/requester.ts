import {
  PARAFE_EXTENSION_URI,
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
  PARAFE_ACTIVATION_HEADER_VALUE,
} from './constants.js';
import type { BuildMetadataOptions, ParafeAgentCardExtension } from './types.js';

/**
 * Builds the params.metadata fields for an outgoing A2A request.
 * Merge the result into your task's params.metadata before sending.
 *
 * @example
 * const metadata = buildExtensionMetadata({ agentId, consentToken, sessionId });
 * await a2aClient.sendTask({ params: { metadata, ...rest } });
 */
export function buildExtensionMetadata(
  options: BuildMetadataOptions
): Record<string, string> {
  const metadata: Record<string, string> = {
    [PARAFE_AGENT_ID_FIELD]: options.agentId,
    [PARAFE_CONSENT_TOKEN_FIELD]: options.consentToken,
  };

  if (options.sessionId !== undefined) {
    metadata[PARAFE_SESSION_ID_FIELD] = options.sessionId;
  }

  return metadata;
}

/**
 * Returns the extension entry to include in your AgentCard's capabilities.extensions array.
 * Agents that advertise this entry signal that they send Parafe trust metadata on requests.
 *
 * @example
 * const agentCard = {
 *   capabilities: {
 *     extensions: [getAgentCardExtension()],
 *   },
 * };
 */
export function getAgentCardExtension(): ParafeAgentCardExtension {
  return {
    uri: PARAFE_EXTENSION_URI,
    required: false,
    description:
      'Parafe trust extension — cryptographic agent identity and scoped consent verification. ' +
      'Requests include a broker-signed consent token verifiable offline via the Parafe public key.',
  };
}

/**
 * The value to set on the X-A2A-Extensions request header.
 * Including this header signals to the receiving agent that Parafe extension data is present.
 *
 * @example
 * headers['X-A2A-Extensions'] = activationHeaderValue;
 */
export const activationHeaderValue = PARAFE_ACTIVATION_HEADER_VALUE;
