import { PARAFE_EXTENSION_URI } from './constants.js';

/**
 * The Parafe-specific fields extracted from an A2A request's params.metadata.
 */
export interface ParafeExtensionMetadata {
  /** Parafe agent ID of the requesting agent. */
  agentId: string;
  /** Broker-signed JWT consent token scoping what the requester is allowed to do. */
  consentToken: string;
  /**
   * Optional Parafe session ID linking this interaction to an authenticated session.
   * Strongly recommended for production — enables signed interaction receipts and audit trails.
   */
  sessionId?: string;
}

/**
 * Decoded and verified claims from a Parafe consent token JWT.
 */
export interface ParafeConsentClaims {
  /** Agent ID (JWT subject). */
  sub: string;
  /** Broker URL that issued the token (JWT issuer). */
  iss: string;
  /** Issued-at timestamp (seconds since epoch). */
  iat: number;
  /** Expiry timestamp (seconds since epoch). */
  exp: number;
  /** Permitted scopes for this interaction. */
  scope: string[];
  /** The counterparty agent ID this token was issued for, if scoped to a specific agent. */
  counterparty?: string;
  /** Session ID, if the token is bound to a session. */
  session_id?: string;
  /** Organization ID of the requester. */
  org_id?: string;
}

/**
 * The extension entry for an AgentCard's capabilities.extensions array.
 */
export interface ParafeAgentCardExtension {
  uri: typeof PARAFE_EXTENSION_URI;
  required: boolean;
  description: string;
}

/**
 * Options for online consent token verification via the Parafe broker.
 */
export interface VerifyOnlineOptions {
  /** Parafe broker URL. Defaults to https://api.parafe.ai */
  brokerUrl?: string;
  /** Expected scope(s) that must be present in the token. */
  requiredScope?: string | string[];
}

/**
 * Options for building requester metadata.
 */
export interface BuildMetadataOptions {
  /** Parafe agent ID of the requesting agent. */
  agentId: string;
  /** Broker-signed JWT consent token. */
  consentToken: string;
  /**
   * Parafe session ID. Strongly recommended — enables audit trails and signed receipts.
   */
  sessionId?: string;
}
