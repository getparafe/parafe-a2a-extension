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
 * Matches the exact shape produced by the broker's createConsentToken() in src/crypto/jwt.js.
 */
export interface ParafeConsentClaims {
  /** The requested scope name (e.g. "flight-rebooking"). Single string, not an array. */
  scope: string;
  /** Array of permitted actions within this scope (e.g. ["read_bookings", "search_alternatives"]). */
  permissions: string[];
  /** Array of explicitly excluded actions (e.g. ["cancel_booking"]). */
  excluded: string[];
  /** The session ID this token belongs to (e.g. "sess_..."). */
  session_id: string;
  /** Always "consent" for consent tokens. */
  token_type: 'consent';
  /** Authorization modality: "autonomous", "attested", or "verified". */
  authorization_modality: 'autonomous' | 'attested' | 'verified';
  /** Agent ID of the handshake initiator. */
  initiator_agent_id: string | null;
  /** Agent ID of the handshake target. */
  target_agent_id: string | null;
  /** Issued-at timestamp (seconds since epoch). */
  iat: number;
  /** Expiry timestamp (seconds since epoch). */
  exp: number;
  /** Always "parafe-trust-broker". */
  iss: 'parafe-trust-broker';
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
  /** The action to check permission for (e.g. "read_bookings"). Required by the broker. */
  action: string;
  /** The session ID to validate against. If omitted, extracted from the token's session_id claim. */
  sessionId?: string;
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
