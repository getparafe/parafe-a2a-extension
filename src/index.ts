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
  SessionClosedPayload,
  ParafeErrorCode,
  ParafeErrorPayload,
  ParafeMessageData,
  ParafeMessageMember,
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
  BrokerKeys,
  JsonWebKeyLike,
} from './types.js';

// Errors
export {
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MalformedParafeDataError,
  WrongAudienceError,
  InvalidProofError,
  isParafeError,
} from './errors.js';

// Message data: write and read
export {
  withParafe,
  withConsentToken,
  withSessionClosed,
  withActionReceipts,
  parafeErrorData,
  readParafe,
  extractHandshakeChallenge,
  extractHandshakeComplete,
  extractConsentToken,
  extractSessionClosed,
  extractActionReceipts,
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
  fetchBrokerKeys,
  createBrokerKeyCache,
  verifyMessageConsentToken,
  verifyPresentationProof,
  createPresentationProof,
} from './verification.js';
export type { ConsentVerifyResult, BrokerKeyCache } from './verification.js';

// Action receipts (2.2)
export {
  createActionReceiptSigner,
  signActionReceipt,
  fileActionReceipt,
  actionErrorFor,
  jcs,
  ACTION_RECEIPT_TYP,
} from './action-receipts.js';
export type {
  ActionErrorCode,
  ActionReceiptKind,
  ActionReceiptInput,
  ActionReceiptAck,
  RecordedActionReceipt,
  ActionReceiptSigner,
  ActionReceiptSignerOptions,
} from './action-receipts.js';

// AP2 v0.2 interop (2.3, AP2 change request A3/A4)
export {
  ap2MandateReferences,
  ap2ReceiptClaims,
  signAp2Receipt,
} from './ap2.js';
export type {
  Ap2References,
  Ap2ReferenceForm,
  Ap2ReceiptKind,
  Ap2ReceiptInput,
  Ap2Receipt,
} from './ap2.js';
