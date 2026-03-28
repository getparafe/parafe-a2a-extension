/**
 * @deprecated — Compatibility module for v0.2.0 metadata-based API.
 * Use the DataPart-based API from the main package instead.
 * This module will be removed in v2.0.0.
 */

import { PARAFE_EXTENSION_URI } from '../constants.js';

// ---------------------------------------------------------------------------
// Legacy metadata field constants (v0.2.0 pattern — params.metadata keys)
// ---------------------------------------------------------------------------

/** @deprecated Use DataParts instead. See buildConsentTokenPart(). */
export const PARAFE_AGENT_ID_FIELD = `${PARAFE_EXTENSION_URI}/agent-id`;
/** @deprecated Use DataParts instead. See buildConsentTokenPart(). */
export const PARAFE_CONSENT_TOKEN_FIELD = `${PARAFE_EXTENSION_URI}/consent-token`;
/** @deprecated Use DataParts instead. See buildConsentTokenPart(). */
export const PARAFE_SESSION_ID_FIELD = `${PARAFE_EXTENSION_URI}/session-id`;
/** @deprecated Use DataParts instead. */
export const PARAFE_ACTIVATION_HEADER_VALUE = PARAFE_EXTENSION_URI;
/** @deprecated Use DataParts instead. */
export const activationHeaderValue = PARAFE_EXTENSION_URI;

// ---------------------------------------------------------------------------
// Legacy types
// ---------------------------------------------------------------------------

/** @deprecated Use ConsentTokenPayload from the main package instead. */
export interface ParafeExtensionMetadata {
  agentId: string;
  consentToken: string;
  sessionId?: string;
}

/** @deprecated Use BuildAgentCardOptions from the main package instead. */
export interface BuildMetadataOptions {
  agentId: string;
  consentToken: string;
  sessionId?: string;
}

// ---------------------------------------------------------------------------
// Legacy functions
// ---------------------------------------------------------------------------

/**
 * @deprecated Use buildConsentTokenPart() from the main package instead.
 * Builds params.metadata fields for an outgoing A2A request (v0.2.0 pattern).
 */
export function buildExtensionMetadata(
  options: BuildMetadataOptions
): Record<string, string> {
  const metadata: Record<string, string> = {
    [PARAFE_AGENT_ID_FIELD]: options.agentId,
    [PARAFE_CONSENT_TOKEN_FIELD]: options.consentToken,
  };

  if (options.sessionId !== undefined) {
    metadata[PARAFE_SESSION_ID_FIELD] = options.sessionId;
  }

  return metadata;
}

/**
 * @deprecated Use extractConsentToken() from the main package instead.
 * Extracts Parafe fields from params.metadata (v0.2.0 pattern).
 */
export function extractExtensionMetadata(
  metadata: Record<string, unknown>
): ParafeExtensionMetadata {
  const agentId = metadata[PARAFE_AGENT_ID_FIELD];
  const consentToken = metadata[PARAFE_CONSENT_TOKEN_FIELD];

  const missing: string[] = [];
  if (typeof agentId !== 'string' || agentId.length === 0) {
    missing.push(PARAFE_AGENT_ID_FIELD);
  }
  if (typeof consentToken !== 'string' || consentToken.length === 0) {
    missing.push(PARAFE_CONSENT_TOKEN_FIELD);
  }

  if (missing.length > 0) {
    throw new Error(
      `Parafe extension metadata missing required field(s): ${missing.join(', ')}.`
    );
  }

  const sessionId = metadata[PARAFE_SESSION_ID_FIELD];

  return {
    agentId: agentId as string,
    consentToken: consentToken as string,
    ...(typeof sessionId === 'string' && sessionId.length > 0 ? { sessionId } : {}),
  };
}
