/**
 * The canonical URI identifying this extension (v2).
 * Declared in the AgentCard, listed in `message.extensions`, used as the key of the
 * Parafe entry in `message.metadata`, and sent in the A2A-Extensions header.
 * The specification is hosted at this URI.
 * This URI is stable — changing it is a breaking change for all agents that advertise it.
 */
export const PARAFE_EXTENSION_URI = 'https://parafe.ai/extensions/a2a/v2';

/**
 * The v1 extension URI. v1 carried Parafe data in A2A data parts.
 * Recognized when reading AgentCards and messages; never written.
 */
export const PARAFE_EXTENSION_URI_V1 =
  'https://github.com/getparafe/parafe-a2a-extension/v1';

/**
 * A2A service parameter (HTTP header) names.
 * A2A 1.0 uses `A2A-Extensions`; A2A 0.3 used `X-A2A-Extensions`.
 * A request without `A2A-Version` is treated as A2A 0.3.
 */
export const A2A_EXTENSIONS_HEADER = 'A2A-Extensions';
export const A2A_EXTENSIONS_HEADER_V0_3 = 'X-A2A-Extensions';
export const A2A_VERSION_HEADER = 'A2A-Version';

/**
 * v1 data part keys — the keys inside the `data` object of v1 Parafe data parts.
 * Only used to read messages from v1 senders.
 */
export const PARAFE_V1_HANDSHAKE_CHALLENGE = 'parafe.handshake.Challenge';
export const PARAFE_V1_HANDSHAKE_COMPLETE = 'parafe.handshake.Complete';
export const PARAFE_V1_CONSENT_TOKEN = 'parafe.trust.ConsentToken';

/**
 * Default Parafe broker URL.
 */
export const DEFAULT_BROKER_URL = 'https://api.parafe.ai';
