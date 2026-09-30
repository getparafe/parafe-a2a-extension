/**
 * Thrown when a required Parafe DataPart or metadata field is absent.
 */
export class MissingParafeExtensionError extends Error {
  readonly code = 'MISSING_PARAFE_EXTENSION';

  constructor(detail: string | string[]) {
    const msg = Array.isArray(detail)
      ? `Parafe extension data missing required field(s): ${detail.join(', ')}.`
      : detail;
    super(msg);
    this.name = 'MissingParafeExtensionError';
  }
}

/**
 * Thrown when a consent token's Ed25519 signature is invalid or the JWT is malformed.
 */
export class InvalidConsentTokenError extends Error {
  readonly code = 'INVALID_CONSENT_TOKEN';

  constructor(detail?: string) {
    super(
      `Parafe consent token is invalid${detail ? `: ${detail}` : '.'}` +
        ' Verify the token was issued by the Parafe broker and has not been tampered with.'
    );
    this.name = 'InvalidConsentTokenError';
  }
}

/**
 * Thrown when a consent token's expiry has passed.
 */
export class ExpiredConsentTokenError extends Error {
  readonly code = 'EXPIRED_CONSENT_TOKEN';
  readonly expiredAt: Date;

  constructor(expiredAt: Date) {
    super(
      `Parafe consent token expired at ${expiredAt.toISOString()}. ` +
        'Request a new token from the Parafe broker.'
    );
    this.name = 'ExpiredConsentTokenError';
    this.expiredAt = expiredAt;
  }
}

/**
 * Thrown when a consent token does not cover a required action.
 */
export class ScopeViolationError extends Error {
  readonly code = 'SCOPE_VIOLATION';
  readonly requiredScope: string | string[];
  readonly grantedScopes: string[];

  constructor(requiredScope: string | string[], grantedScopes: string[], detail?: string) {
    const required = Array.isArray(requiredScope) ? requiredScope.join(', ') : requiredScope;
    super(
      detail ??
        `Consent token does not include required scope "${required}". ` +
          `Granted scopes: ${grantedScopes.join(', ')}.`
    );
    this.name = 'ScopeViolationError';
    this.requiredScope = requiredScope;
    this.grantedScopes = grantedScopes;
  }
}

/**
 * Thrown when Parafe data is present in a message but a required field is missing or invalid.
 */
export class MalformedParafeDataError extends Error {
  readonly code = 'MALFORMED_PARAFE_DATA';
  readonly member: string;

  constructor(member: string, detail?: string) {
    super(
      `Malformed Parafe data "${member}"${detail ? `: ${detail}` : '.'}` +
        ' The Parafe data is present but a required field is missing or invalid.'
    );
    this.name = 'MalformedParafeDataError';
    this.member = member;
  }
}

/**
 * Thrown when a consent token was issued for a different agent than the one verifying it.
 */
export class WrongAudienceError extends Error {
  readonly code = 'WRONG_AUDIENCE';
  readonly expectedAgentId: string;
  readonly tokenAgentId: string | null;

  constructor(expectedAgentId: string, tokenAgentId: string | null) {
    super(
      `Parafe consent token was issued for agent "${tokenAgentId ?? '(none)'}", not "${expectedAgentId}".` +
        ' An agent must only accept tokens issued for itself.'
    );
    this.name = 'WrongAudienceError';
    this.expectedAgentId = expectedAgentId;
    this.tokenAgentId = tokenAgentId;
  }
}

/**
 * Thrown when a presentation proof is missing (and required) or doesn't check
 * out: wrong key, wrong token, wrong audience or message, stale, or replayed.
 */
export class InvalidProofError extends Error {
  readonly code = 'INVALID_PROOF';

  constructor(detail: string) {
    super(`Parafe presentation proof rejected: ${detail}`);
    this.name = 'InvalidProofError';
  }
}

type ParafeError =
  | InvalidProofError
  | MissingParafeExtensionError
  | InvalidConsentTokenError
  | ExpiredConsentTokenError
  | ScopeViolationError
  | MalformedParafeDataError
  | WrongAudienceError;

/** True for any error class this package throws. */
export function isParafeError(err: unknown): err is ParafeError {
  return (
    err instanceof InvalidProofError ||
    err instanceof MissingParafeExtensionError ||
    err instanceof InvalidConsentTokenError ||
    err instanceof ExpiredConsentTokenError ||
    err instanceof ScopeViolationError ||
    err instanceof MalformedParafeDataError ||
    err instanceof WrongAudienceError
  );
}
