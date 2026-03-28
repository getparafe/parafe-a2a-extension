import { PARAFE_EXTENSION_URI } from './constants.js';

// ---------------------------------------------------------------------------
// Minimal A2A types — no official Node.js A2A SDK exists, so we define only
// what Parafe needs. These are intentionally narrow and stable.
// ---------------------------------------------------------------------------

/** An A2A data part carrying a typed payload. */
export interface A2ADataPart {
  kind: 'data';
  data: Record<string, unknown>;
}

/** An A2A text part. */
export interface A2ATextPart {
  kind: 'text';
  text: string;
}

/** Union of A2A message part types the extension can encounter. */
export type A2AMessagePart = A2ADataPart | A2ATextPart | { kind: string; [key: string]: unknown };

// ---------------------------------------------------------------------------
// DataPart payload types — match the shapes defined in
// Communication Flow Architecture v2 and Integration Guide v2.
// ---------------------------------------------------------------------------

/**
 * Payload for `parafe.handshake.Challenge` DataPart.
 * Sent by the initiating agent to the target via A2A to start the handshake.
 */
export interface HandshakeChallengePayload {
  /** Handshake reference ID from Parafe broker. */
  handshake_id: string;
  /** Cryptographic challenge nonce (hex-encoded, 32 bytes). */
  challenge: string;
  /** Parafe agent ID of the initiating agent. */
  initiator_agent_id: string;
  /** URL of the Parafe broker that issued this challenge. */
  broker_url: string;
  /** The scope being requested for this interaction. */
  requested_scope: string;
  /** Specific permissions requested (optional, defaults to scope's declared permissions). */
  requested_permissions?: string[];
}

/**
 * Payload for `parafe.handshake.Complete` DataPart.
 * Sent by the target agent back to the initiator after completing the handshake with Parafe.
 */
export interface HandshakeCompletePayload {
  /** Handshake reference ID. */
  handshake_id: string;
  /** Outcome of the handshake. */
  status: 'authenticated' | 'rejected' | 'error';
  /** Broker-signed JWT consent token (present when status is 'authenticated'). */
  consent_token?: string | undefined;
  /** Error code (present when status is 'rejected' or 'error'). */
  error_code?: string | undefined;
  /** Human-readable error message. */
  error_message?: string | undefined;
}

/**
 * Payload for `parafe.trust.ConsentToken` DataPart.
 * Included in every A2A message during the direct exchange between agents.
 */
export interface ConsentTokenPayload {
  /** Broker-signed JWT consent token. */
  token: string;
  /** Session ID linking this interaction to the authenticated session. */
  session_id: string;
}

// ---------------------------------------------------------------------------
// Typed DataPart shapes — combine A2ADataPart with the correct payload key.
// ---------------------------------------------------------------------------

export interface HandshakeChallengeDataPart {
  kind: 'data';
  data: { 'parafe.handshake.Challenge': HandshakeChallengePayload };
}

export interface HandshakeCompleteDataPart {
  kind: 'data';
  data: { 'parafe.handshake.Complete': HandshakeCompletePayload };
}

export interface ConsentTokenDataPart {
  kind: 'data';
  data: { 'parafe.trust.ConsentToken': ConsentTokenPayload };
}

// ---------------------------------------------------------------------------
// AgentCard types — match the format in Communication Flow Architecture v2.
// ---------------------------------------------------------------------------

/** Scope requirement declared in an AgentCard extension params block. */
export interface ScopeRequirement {
  /** Permitted actions within this scope. */
  permissions: string[];
  /** Minimum authorization modality required. */
  minimum_authorization_modality: 'autonomous' | 'attested' | 'verified';
}

/** The params block inside a Parafe AgentCard extension entry. */
export interface ParafeExtensionParams {
  /** Parafe agent ID of this agent. */
  agent_id: string;
  /** URL of the Parafe broker this agent uses. */
  broker_url: string;
  /** Minimum identity assurance accepted. */
  minimum_identity_assurance: 'registered' | 'self_registered';
  /** Scope requirements keyed by scope name. */
  scope_requirements: Record<string, ScopeRequirement>;
}

/** The full Parafe extension entry for an AgentCard's capabilities.extensions array. */
export interface ParafeAgentCardExtension {
  uri: typeof PARAFE_EXTENSION_URI;
  required: boolean;
  description?: string | undefined;
  params: ParafeExtensionParams;
}

/** Options for building an AgentCard extension entry. */
export interface BuildAgentCardOptions {
  /** Your Parafe agent ID. */
  agentId: string;
  /** Scope requirements to declare. */
  scopeRequirements: Record<string, ScopeRequirement>;
  /** Parafe broker URL. Defaults to DEFAULT_BROKER_URL. */
  brokerUrl?: string;
  /** Minimum identity assurance accepted. Defaults to 'self_registered'. */
  minimumIdentityAssurance?: 'registered' | 'self_registered';
  /** Whether the extension is required for interacting with this agent. Defaults to true. */
  required?: boolean;
  /** Optional description. */
  description?: string;
}

// ---------------------------------------------------------------------------
// Consent token types — kept from v0.2.0, already aligned to broker.
// ---------------------------------------------------------------------------

/**
 * Decoded and verified claims from a Parafe consent token JWT.
 * Matches the exact shape produced by the broker's createConsentToken() in src/crypto/jwt.js.
 */
export interface ParafeConsentClaims {
  /** The requested scope name (e.g. "flight-rebooking"). Single string, not an array. */
  scope: string;
  /** Array of permitted actions within this scope. */
  permissions: string[];
  /** Array of explicitly excluded actions. */
  excluded: string[];
  /** The session ID this token belongs to. */
  session_id: string;
  /** Always "consent" for consent tokens. */
  token_type: 'consent';
  /** Authorization modality. */
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
 * Options for online consent token verification via the Parafe broker.
 */
export interface VerifyOnlineOptions {
  /** Parafe broker URL. Defaults to DEFAULT_BROKER_URL. */
  brokerUrl?: string;
  /** The action to check permission for. Required by the broker. */
  action: string;
  /** The session ID to validate against. If omitted, extracted from the token's session_id claim. */
  sessionId?: string;
}
