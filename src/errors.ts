/**
 * Thrown when a required Parafe metadata field is absent from params.metadata.
 */
export class MissingParafeExtensionError extends Error {
  readonly code = 'MISSING_PARAFE_EXTENSION';

  constructor(missingFields: string[]) {
    super(
      `Parafe extension metadata missing required field(s): ${missingFields.join(', ')}. ` +
        `Ensure the requesting agent includes ${missingFields.join(', ')} in params.metadata.`
    );
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
 * Thrown when a consent token does not cover a required scope.
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
