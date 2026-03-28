import { describe, it, expect } from 'vitest';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import {
  verifyConsentTokenOffline,
  verifyMessageConsentToken,
  buildConsentTokenPart,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MissingParafeExtensionError,
} from '../../src/index.js';

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
  });

  it('rejects a token signed with the wrong key', async () => {
    const { token } = await createTestToken();
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
});

describe('verifyMessageConsentToken', () => {
  it('extracts and verifies a consent token from message parts', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const parts = [
      buildConsentTokenPart(token, 'sess_test123'),
      { kind: 'text' as const, text: 'Show me flights' },
    ];

    const { claims, sessionId } = await verifyMessageConsentToken(parts, pemPublicKey);
    expect(claims.scope).toBe('test-scope');
    expect(sessionId).toBe('sess_test123');
  });

  it('throws MissingParafeExtensionError when no consent token DataPart', async () => {
    const { pemPublicKey } = await createTestToken();
    const parts = [{ kind: 'text' as const, text: 'no token here' }];

    await expect(
      verifyMessageConsentToken(parts, pemPublicKey)
    ).rejects.toThrow(MissingParafeExtensionError);
  });

  it('verifies required action when provided', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const parts = [buildConsentTokenPart(token, 'sess_test123')];

    const { claims } = await verifyMessageConsentToken(parts, pemPublicKey, 'read_data');
    expect(claims.permissions).toContain('read_data');
  });

  it('throws ScopeViolationError for unpermitted action', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const parts = [buildConsentTokenPart(token, 'sess_test123')];

    await expect(
      verifyMessageConsentToken(parts, pemPublicKey, 'delete_data')
    ).rejects.toThrow(ScopeViolationError);
  });
});
