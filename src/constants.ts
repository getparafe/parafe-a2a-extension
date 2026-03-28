/**
 * The canonical URI identifying this extension.
 * Declared in AgentCard and sent in the X-A2A-Extensions header.
 * This URI is stable — changing it is a breaking change for all agents that advertise it.
 */
export const PARAFE_EXTENSION_URI =
  'https://github.com/getparafe/parafe-a2a-extension/v1';

/**
 * Metadata field names — namespaced under the extension URI per A2A spec.
 * These are the keys used in params.metadata on A2A requests.
 */
export const PARAFE_AGENT_ID_FIELD = `${PARAFE_EXTENSION_URI}/agent-id`;
export const PARAFE_CONSENT_TOKEN_FIELD = `${PARAFE_EXTENSION_URI}/consent-token`;
export const PARAFE_SESSION_ID_FIELD = `${PARAFE_EXTENSION_URI}/session-id`;

/**
 * The value for the X-A2A-Extensions header that activates this extension.
 */
export const PARAFE_ACTIVATION_HEADER_VALUE = PARAFE_EXTENSION_URI;

/**
 * Default Parafe broker URL.
 */
export const DEFAULT_BROKER_URL = 'https://api.parafe.ai';
