// Constants
export {
  PARAFE_EXTENSION_URI,
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
  PARAFE_ACTIVATION_HEADER_VALUE,
  DEFAULT_BROKER_URL,
} from './constants.js';

// Types
export type {
  ParafeExtensionMetadata,
  ParafeConsentClaims,
  ParafeAgentCardExtension,
  VerifyOnlineOptions,
  BuildMetadataOptions,
} from './types.js';

// Errors
export {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
} from './errors.js';

// Requester helpers (use when sending A2A requests)
export {
  buildExtensionMetadata,
  getAgentCardExtension,
  activationHeaderValue,
} from './requester.js';

// Executor helpers (use when receiving A2A requests)
export {
  extractExtensionMetadata,
  verifyConsentTokenOffline,
  verifyConsentTokenOnline,
  fetchBrokerPublicKey,
} from './executor.js';
