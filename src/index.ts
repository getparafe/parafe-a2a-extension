// Constants
export {
  PARAFE_EXTENSION_URI,
  PARAFE_HANDSHAKE_CHALLENGE,
  PARAFE_HANDSHAKE_COMPLETE,
  PARAFE_TRUST_CONSENT_TOKEN,
  DEFAULT_BROKER_URL,
} from './constants.js';

// Types — A2A base
export type {
  A2ADataPart,
  A2ATextPart,
  A2AMessagePart,
} from './types.js';

// Types — DataPart payloads
export type {
  HandshakeChallengePayload,
  HandshakeCompletePayload,
  ConsentTokenPayload,
  HandshakeChallengeDataPart,
  HandshakeCompleteDataPart,
  ConsentTokenDataPart,
} from './types.js';

// Types — AgentCard
export type {
  ScopeRequirement,
  ParafeExtensionParams,
  ParafeAgentCardExtension,
  BuildAgentCardOptions,
} from './types.js';

// Types — Verification
export type {
  ParafeConsentClaims,
  VerifyOnlineOptions,
} from './types.js';

// Errors
export {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MalformedDataPartError,
} from './errors.js';

// DataPart builders and parsers
export {
  buildHandshakeChallenge,
  buildHandshakeComplete,
  buildConsentTokenPart,
  extractHandshakeChallenge,
  extractHandshakeComplete,
  extractConsentToken,
  hasParafeDataPart,
} from './data-parts.js';

// AgentCard builder and parser
export {
  buildAgentCardExtension,
  parseAgentCardExtension,
} from './agent-card.js';

// Verification
export {
  verifyConsentTokenOffline,
  verifyConsentTokenOnline,
  fetchBrokerPublicKey,
  verifyMessageConsentToken,
} from './verification.js';
export type { ConsentVerifyResult } from './verification.js';
