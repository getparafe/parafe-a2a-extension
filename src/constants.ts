/**
 * The canonical URI identifying this extension.
 * Declared in AgentCard and sent in the X-A2A-Extensions header.
 * This URI is stable — changing it is a breaking change for all agents that advertise it.
 */
export const PARAFE_EXTENSION_URI =
  'https://github.com/getparafe/parafe-a2a-extension/v1';

/**
 * A2A DataPart type keys — these are the keys inside the `data` object of DataParts.
 * Used when building and parsing Parafe-specific DataParts in A2A messages.
 */
export const PARAFE_HANDSHAKE_CHALLENGE = 'parafe.handshake.Challenge';
export const PARAFE_HANDSHAKE_COMPLETE = 'parafe.handshake.Complete';
export const PARAFE_TRUST_CONSENT_TOKEN = 'parafe.trust.ConsentToken';

/**
 * Default Parafe broker URL.
 */
export const DEFAULT_BROKER_URL = 'https://api.parafe.ai';
