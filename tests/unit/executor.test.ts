import { describe, it, expect } from 'vitest';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import {
  extractExtensionMetadata,
  verifyConsentTokenOffline,
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  PARAFE_AGENT_ID_FIELD,
  PARAFE_CONSENT_TOKEN_FIELD,
  PARAFE_SESSION_ID_FIELD,
} from '../../src/index.js';

// Helper: create an Ed25519 key pair and sign a consent token
async function createTestToken(
  overrides: Record<string, unknown> = {},
  expiresIn = '5m'
) {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA');
  const pemPublicKey = await exportSPKI(publicKey);

  const claims = {
    scope: 'test-scope',
    permissions: ['read_data', 'write_data'],
    excluded: ['delete_data'],
    session_id: 'sess_test123',
    token_type: 'consent',
    authorization_modality: 'autonomous',
    initiator_agent_id: 'prf_agent_initiator',
    target_agent_id: 'prf_agent_target',
    ...overrides,
  };

  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuer('parafe-trust-broker')
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);

  return { token, pemPublicKey, claims };
}

describe('extractExtensionMetadata', () => {
  it('extracts agent ID and consent token from metadata', () => {
    const metadata = {
      [PARAFE_AGENT_ID_FIELD]: 'prf_agent_abc',
      [PARAFE_CONSENT_TOKEN_FIELD]: 'eyJ.test.token',
    };

    const result = extractExtensionMetadata(metadata);
    expect(result.agentId).toBe('prf_agent_abc');
    expect(result.consentToken).toBe('eyJ.test.token');
    expect(result.sessionId).toBeUndefined();
  });

  it('extracts session ID when present', () => {
    const metadata = {
      [PARAFE_AGENT_ID_FIELD]: 'prf_agent_abc',
      [PARAFE_CONSENT_TOKEN_FIELD]: 'eyJ.test.token',
      [PARAFE_SESSION_ID_FIELD]: 'sess_xyz',
    };

    const result = extractExtensionMetadata(metadata);
    expect(result.sessionId).toBe('sess_xyz');
  });

  it('throws MissingParafeExtensionError when agent ID is missing', () => {
    const metadata = {
      [PARAFE_CONSENT_TOKEN_FIELD]: 'eyJ.test.token',
    };

    expect(() => extractExtensionMetadata(metadata)).toThrow(MissingParafeExtensionError);
  });

  it('throws MissingParafeExtensionError when consent token is missing', () => {
    const metadata = {
      [PARAFE_AGENT_ID_FIELD]: 'prf_agent_abc',
    };

    expect(() => extractExtensionMetadata(metadata)).toThrow(MissingParafeExtensionError);
  });

  it('throws MissingParafeExtensionError when metadata is empty', () => {
    expect(() => extractExtensionMetadata({})).toThrow(MissingParafeExtensionError);
  });

  it('throws MissingParafeExtensionError for empty string values', () => {
    const metadata = {
      [PARAFE_AGENT_ID_FIELD]: '',
      [PARAFE_CONSENT_TOKEN_FIELD]: 'eyJ.test.token',
    };

    expect(() => extractExtensionMetadata(metadata)).toThrow(MissingParafeExtensionError);
  });

  it('error includes names of missing fields', () => {
    try {
      extractExtensionMetadata({});
    } catch (err) {
      expect(err).toBeInstanceOf(MissingParafeExtensionError);
      expect((err as MissingParafeExtensionError).message).toContain('agent-id');
      expect((err as MissingParafeExtensionError).message).toContain('consent-token');
      expect((err as MissingParafeExtensionError).code).toBe('MISSING_PARAFE_EXTENSION');
    }
  });

  it('ignores empty session ID', () => {
    const metadata = {
      [PARAFE_AGENT_ID_FIELD]: 'prf_agent_abc',
      [PARAFE_CONSENT_TOKEN_FIELD]: 'eyJ.test.token',
      [PARAFE_SESSION_ID_FIELD]: '',
    };

    const result = extractExtensionMetadata(metadata);
    expect(result.sessionId).toBeUndefined();
  });
});

describe('verifyConsentTokenOffline', () => {
  it('verifies a valid consent token and returns claims', async () => {
    const { token, pemPublicKey } = await createTestToken();

    const claims = await verifyConsentTokenOffline(token, pemPublicKey);

    expect(claims.scope).toBe('test-scope');
    expect(claims.permissions).toEqual(['read_data', 'write_data']);
    expect(claims.excluded).toEqual(['delete_data']);
    expect(claims.session_id).toBe('sess_test123');
    expect(claims.token_type).toBe('consent');
    expect(claims.authorization_modality).toBe('autonomous');
    expect(claims.initiator_agent_id).toBe('prf_agent_initiator');
    expect(claims.target_agent_id).toBe('prf_agent_target');
    expect(claims.iss).toBe('parafe-trust-broker');
    expect(claims.iat).toBeTypeOf('number');
    expect(claims.exp).toBeTypeOf('number');
  });

  it('rejects a token signed with the wrong key', async () => {
    const { token } = await createTestToken();
    // Generate a different key pair
    const { publicKey: wrongKey } = await generateKeyPair('EdDSA');
    const wrongPem = await exportSPKI(wrongKey);

    await expect(
      verifyConsentTokenOffline(token, wrongPem)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects a malformed token', async () => {
    const { pemPublicKey } = await createTestToken();

    await expect(
      verifyConsentTokenOffline('not-a-jwt', pemPublicKey)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects an expired token with ExpiredConsentTokenError', async () => {
    const { token, pemPublicKey } = await createTestToken({}, '-1s');

    await expect(
      verifyConsentTokenOffline(token, pemPublicKey)
    ).rejects.toThrow(ExpiredConsentTokenError);
  });

  it('rejects a token with wrong issuer', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA');
    const pemPublicKey = await exportSPKI(publicKey);

    const token = await new SignJWT({ token_type: 'consent', scope: 'test' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer('wrong-issuer')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(
      verifyConsentTokenOffline(token, pemPublicKey)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects a token with wrong token_type', async () => {
    const { token, pemPublicKey } = await createTestToken({ token_type: 'session' });

    await expect(
      verifyConsentTokenOffline(token, pemPublicKey)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('passes when requiredAction is in permissions', async () => {
    const { token, pemPublicKey } = await createTestToken();

    const claims = await verifyConsentTokenOffline(token, pemPublicKey, 'read_data');
    expect(claims.permissions).toContain('read_data');
  });

  it('throws ScopeViolationError when requiredAction is excluded', async () => {
    const { token, pemPublicKey } = await createTestToken();

    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, 'delete_data')
    ).rejects.toThrow(ScopeViolationError);
  });

  it('throws ScopeViolationError when requiredAction is not in permissions', async () => {
    const { token, pemPublicKey } = await createTestToken();

    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, 'admin_override')
    ).rejects.toThrow(ScopeViolationError);
  });

  it('ScopeViolationError includes action and granted permissions', async () => {
    const { token, pemPublicKey } = await createTestToken();

    try {
      await verifyConsentTokenOffline(token, pemPublicKey, 'admin_override');
    } catch (err) {
      expect(err).toBeInstanceOf(ScopeViolationError);
      const scopeErr = err as ScopeViolationError;
      expect(scopeErr.code).toBe('SCOPE_VIOLATION');
      expect(scopeErr.requiredScope).toBe('admin_override');
      expect(scopeErr.grantedScopes).toEqual(['read_data', 'write_data']);
    }
  });
});
