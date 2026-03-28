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

  constructor(requiredScope: string | string[], grantedScopes: string[]) {
    const required = Array.isArray(requiredScope) ? requiredScope.join(', ') : requiredScope;
    super(
      `Consent token does not include required scope "${required}". ` +
        `Granted scopes: ${grantedScopes.join(', ')}.`
    );
    this.name = 'ScopeViolationError';
    this.requiredScope = requiredScope;
    this.grantedScopes = grantedScopes;
  }
}

/**
 * Thrown when a DataPart key is present but the payload structure is invalid.
 */
export class MalformedDataPartError extends Error {
  readonly code = 'MALFORMED_DATA_PART';
  readonly dataPartType: string;

  constructor(dataPartType: string, detail?: string) {
    super(
      `Malformed Parafe DataPart "${dataPartType}"${detail ? `: ${detail}` : '.'}` +
        ' The DataPart key is present but the payload is missing required fields.'
    );
    this.name = 'MalformedDataPartError';
    this.dataPartType = dataPartType;
  }
}
