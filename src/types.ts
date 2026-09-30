// ---------------------------------------------------------------------------
// Minimal A2A shapes. Structural on purpose: works with @a2a-js/sdk types,
// other SDKs, and raw A2A 1.0 or 0.3 JSON alike. Only the fields Parafe
// touches are declared.
// ---------------------------------------------------------------------------

/** Any A2A message: an @a2a-js/sdk `Message`, or A2A 1.0 / 0.3 wire JSON. */
export interface A2AMessageLike {
  metadata?: Record<string, unknown> | null | undefined;
  extensions?: readonly string[] | null | undefined;
  parts?: readonly unknown[] | null | undefined;
}

// ---------------------------------------------------------------------------
// Parafe message data — the object at message.metadata[PARAFE_EXTENSION_URI].
// Shapes defined in the extension specification at PARAFE_EXTENSION_URI.
// ---------------------------------------------------------------------------

/**
 * `handshake_challenge`: sent by the client (initiating agent) to the agent
 * to start the handshake.
 */
export interface HandshakeChallengePayload {
  /** Handshake reference ID from the Parafe broker. */
  handshake_id: string;
  /** Cryptographic challenge nonce (64 hex characters). */
  challenge: string;
  /** Parafe agent ID of the initiating agent. */
  initiator_agent_id: string;
  /** URL of the Parafe broker that issued this challenge. */
  broker_url: string;
  /** The scope being requested for this interaction. */
  requested_scope: string;
  /** Specific permissions requested (optional, defaults to the scope's declared permissions). */
  requested_permissions?: string[];
}

/**
 * `handshake_complete`: sent by the agent back to the client after completing
 * the handshake with the broker.
 */
export interface HandshakeCompletePayload {
  /** Handshake reference ID. */
  handshake_id: string;
  /** Outcome of the handshake. */
  status: 'authenticated' | 'rejected' | 'error';
  /** Parafe session ID (present when status is 'authenticated'). */
  session_id?: string | undefined;
  /** Broker-signed JWT consent token (present when status is 'authenticated'). */
  consent_token?: string | undefined;
  /** Error code (present when status is 'rejected' or 'error'). */
  error_code?: string | undefined;
  /** Human-readable error message. */
  error_message?: string | undefined;
}

/**
 * `consent`: sent by the client in every message after the handshake.
 */
export interface ConsentTokenPayload {
  /** Broker-signed JWT consent token. */
  token: string;
  /** Session ID linking this interaction to the authenticated session. */
  session_id: string;
  /**
   * Presentation proof (2.1): a short JWT signed with the initiator's key,
   * showing the token is presented by the key it is bound to (`cnf.jkt`).
   * Create it with createPresentationProof().
   */
  proof?: string | undefined;
}

/**
 * `session_closed` (2.1): sent by the participant that closed the session, so
 * the other side knows it's over and holds the receipt.
 */
export interface SessionClosedPayload {
  session_id: string;
  /** The session receipt: a compact JWS signed by the broker. */
  receipt: string;
}

/** Error codes an agent reports in Parafe `error` data. */
export type ParafeErrorCode =
  | 'MISSING_PARAFE_EXTENSION'
  | 'MALFORMED_PARAFE_DATA'
  | 'INVALID_CONSENT_TOKEN'
  | 'WRONG_AUDIENCE'
  | 'EXPIRED_CONSENT_TOKEN'
  | 'SCOPE_VIOLATION'
  | 'INVALID_PROOF';

/**
 * `error`: sent by an agent when it refuses an action for a Parafe reason.
 */
export interface ParafeErrorPayload {
  code: ParafeErrorCode;
  message: string;
}

/**
 * The Parafe data carried in a message, at message.metadata[PARAFE_EXTENSION_URI].
 * Exactly one member is set.
 */
export type ParafeMessageData =
  | { handshake_challenge: HandshakeChallengePayload }
  | { handshake_complete: HandshakeCompletePayload }
  | { consent: ConsentTokenPayload }
  | { session_closed: SessionClosedPayload }
  | { error: ParafeErrorPayload };

// ---------------------------------------------------------------------------
// AgentCard types.
// ---------------------------------------------------------------------------

/** Scope requirement declared in an AgentCard extension params block. */
export interface ScopeRequirement {
  /** Permitted actions within this scope. */
  permissions: string[];
  /** Minimum authorization modality required. */
  minimum_authorization_modality: 'autonomous' | 'attested' | 'verified';
  /**
   * Require the initiator to have proved it holds its key ('pop') when the
   * token was issued, not just shown its credential. The broker enforces this
   * too when it's in the agent's registered scope policy.
   */
  minimum_initiator_proof?: 'pop' | 'credential';
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

/** The Parafe extension entry for an AgentCard's capabilities.extensions array. */
export interface ParafeAgentCardExtension {
  /** PARAFE_EXTENSION_URI, or PARAFE_EXTENSION_URI_V1 when parsed from a v1 card. */
  uri: string;
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
  /**
   * true: serve no request without Parafe. A2A 1.0 servers (including @a2a-js/sdk)
   * reject requests that don't activate the extension, before your code runs.
   * false: also serve callers without Parafe; you must check consent yourself
   * for every action inside a Parafe scope.
   */
  required: boolean;
  /** Parafe broker URL. Defaults to DEFAULT_BROKER_URL. */
  brokerUrl?: string;
  /** Minimum identity assurance accepted. Defaults to 'self_registered'. */
  minimumIdentityAssurance?: 'registered' | 'self_registered';
  /** Optional description. */
  description?: string;
}

// ---------------------------------------------------------------------------
// Consent token types.
// ---------------------------------------------------------------------------

/**
 * Decoded and verified claims from a Parafe consent token JWT.
 * Matches the shape produced by the broker's createConsentToken() in src/crypto/jwt.js.
 */
export interface ParafeConsentClaims {
  /** The requested scope name (e.g. "flight-rebooking"). Single string, not an array. */
  scope: string;
  /** Array of permitted actions within this scope. */
  permissions: string[];
  /**
   * Explicitly excluded actions. Consent token v2 (broker 2026-09-30+) calls the
   * claim `exclusions`; older tokens `excluded`. The verifier sets both.
   */
  exclusions: string[];
  /** The pre-v2 name of `exclusions`; also set by the verifier. */
  excluded: string[];
  /** 2 for key-bound tokens. */
  ver?: number;
  /** Initiator agent ID (v2). */
  sub?: string;
  /** Target agent DID (v2). */
  aud?: string;
  /** The key the token is bound to: RFC 7638 thumbprint of the initiator's registered key (v2). */
  cnf?: { jkt: string };
  /** Random token ID (v2). */
  jti?: string;
  /** How the initiator proved itself when the token was issued: 'pop' or 'credential'. */
  initiator_proof?: 'pop' | 'credential';
  initiator_proof_at?: number;
  /** The session ID this token belongs to. */
  session_id: string;
  /** Always "consent" for consent tokens. */
  token_type: 'consent';
  /** Authorization modality. */
  authorization_modality: 'autonomous' | 'attested' | 'verified';
  /** Agent ID of the handshake initiator. */
  initiator_agent_id: string | null;
  /** Agent ID of the handshake target — the agent this token was issued for. */
  target_agent_id: string | null;
  /** Token this one was escalated from, if any. */
  parent_token_id?: string | null;
  /** Issued-at timestamp (seconds since epoch). */
  iat: number;
  /** Expiry timestamp (seconds since epoch). */
  exp: number;
  /** Always "parafe-trust-broker". */
  iss: 'parafe-trust-broker';
}

/**
 * Checks applied by verifyConsentTokenOffline() on top of signature and expiry.
 */
export interface VerifyConsentOptions {
  /** An action that must be in `permissions` and not in `excluded`. */
  action?: string;
  /** Your own Parafe agent ID. The token's target_agent_id must match it. */
  agentId?: string;
  /** The session ID the token must belong to. */
  sessionId?: string;
  /**
   * Your declared scope requirements (the same object you put in your AgentCard).
   * When given, the token's scope must be declared, its permissions must be a subset
   * of that scope's permissions, and its modality must meet the scope's minimum.
   */
  scopeRequirements?: Record<string, ScopeRequirement>;
}

/**
 * Checks applied by verifyMessageConsentToken(). `agentId` is required: an agent
 * must never accept a token issued for a different agent.
 */
export interface VerifyMessageOptions extends Omit<VerifyConsentOptions, 'sessionId'> {
  agentId: string;
  /**
   * Require a presentation proof with the token (key binding). Default false in
   * 2.x; true in 3.0. A proof that is sent is always checked.
   */
  requireProof?: boolean;
  /**
   * The initiator's registered public key (JWK), to check the proof against.
   * If omitted, it's fetched from the initiator's DID document at the broker
   * (`brokerUrl`) and cached.
   */
  initiatorKey?: JsonWebKeyLike;
  /** Broker URL for fetching the initiator's DID document. Defaults to DEFAULT_BROKER_URL. */
  brokerUrl?: string;
}

/** A public JWK (Ed25519 or P-256). */
export interface JsonWebKeyLike {
  kty: string;
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
}

/** The broker's signing keys, from fetchBrokerKeys(): its JWKS. */
export interface BrokerKeys {
  keys: Array<JsonWebKeyLike & { kid: string; alg?: string; status?: string }>;
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
  /** Your own Parafe agent ID. When given, the token's target_agent_id must match it. */
  agentId?: string;
  /** The initiator's presentation proof, if it sent one; the broker checks it against the token's cnf.jkt. */
  proof?: string;
}
