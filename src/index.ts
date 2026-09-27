// Constants
export {
  PARAFE_EXTENSION_URI,
  PARAFE_EXTENSION_URI_V1,
  A2A_EXTENSIONS_HEADER,
  A2A_EXTENSIONS_HEADER_V0_3,
  A2A_VERSION_HEADER,
  PARAFE_V1_HANDSHAKE_CHALLENGE,
  PARAFE_V1_HANDSHAKE_COMPLETE,
  PARAFE_V1_CONSENT_TOKEN,
  DEFAULT_BROKER_URL,
} from './constants.js';

// Types — A2A message shape and Parafe message data
export type {
  A2AMessageLike,
  HandshakeChallengePayload,
  HandshakeCompletePayload,
  ConsentTokenPayload,
  ParafeErrorCode,
  ParafeErrorPayload,
  ParafeMessageData,
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
  VerifyConsentOptions,
  VerifyMessageOptions,
  VerifyOnlineOptions,
} from './types.js';

// Errors
export {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MalformedParafeDataError,
  WrongAudienceError,
  isParafeError,
} from './errors.js';

// Message data: write and read
export {
  withParafe,
  withConsentToken,
  parafeErrorData,
  readParafe,
  extractHandshakeChallenge,
  extractHandshakeComplete,
  extractConsentToken,
  extractParafeError,
  hasParafeData,
} from './message.js';
export type { ReadParafeOptions } from './message.js';

// Activation headers
export { activationHeaders, isParafeActivated } from './headers.js';

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
