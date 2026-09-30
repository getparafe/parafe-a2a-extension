import { describe, it, expect } from 'vitest';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import {
  verifyConsentTokenOffline,
  verifyMessageConsentToken,
  withConsentToken,
  InvalidConsentTokenError,
  WrongAudienceError,
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

describe('verifyConsentTokenOffline checks', () => {
  const scopeRequirements = {
    'test-scope': { permissions: ['read_data', 'write_data', 'delete_data'], minimum_authorization_modality: 'autonomous' as const },
  };

  it('accepts a token issued for this agent', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const claims = await verifyConsentTokenOffline(token, pemPublicKey, { agentId: 'prf_agent_target' });
    expect(claims.target_agent_id).toBe('prf_agent_target');
  });

  it('rejects a token issued for a different agent', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { agentId: 'prf_agent_someone_else' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects a token with no target when an agent is expected', async () => {
    const { token, pemPublicKey } = await createTestToken({ target_agent_id: null });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects a session mismatch', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { sessionId: 'sess_other' })
    ).rejects.toThrow(/session/);
  });

  it('accepts a token within the declared scope requirements', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { scopeRequirements, action: 'write_data' })
    ).resolves.toBeTruthy();
  });

  it('rejects a scope the agent does not declare', async () => {
    const { token, pemPublicKey } = await createTestToken({ scope: 'admin' });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { scopeRequirements })
    ).rejects.toThrow(/does not declare/);
  });

  it('rejects permissions outside the declared scope', async () => {
    const { token, pemPublicKey } = await createTestToken({ permissions: ['read_data', 'transfer_funds'] });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { scopeRequirements })
    ).rejects.toThrow(/transfer_funds/);
  });

  it('rejects a modality below the scope minimum', async () => {
    const { token, pemPublicKey } = await createTestToken({ authorization_modality: 'autonomous' });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: 'attested' } },
      })
    ).rejects.toThrow(ScopeViolationError);
  });

  it('accepts a modality above the scope minimum', async () => {
    const { token, pemPublicKey } = await createTestToken({ authorization_modality: 'verified' });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: 'attested' } },
      })
    ).resolves.toBeTruthy();
  });

  it("B8: 'delegated' meets an attested or delegated scope, not a verified one", async () => {
    const { token, pemPublicKey } = await createTestToken({ authorization_modality: 'delegated' });
    for (const [min, ok] of [['attested', true], ['delegated', true], ['verified', false]] as const) {
      const p = verifyConsentTokenOffline(token, pemPublicKey, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: min } },
      });
      if (ok) await expect(p).resolves.toBeTruthy();
      else await expect(p).rejects.toThrow(ScopeViolationError);
    }
  });

  it('does not treat inherited object keys as declared scopes', async () => {
    const { token, pemPublicKey } = await createTestToken({ scope: 'toString' });
    await expect(
      verifyConsentTokenOffline(token, pemPublicKey, { scopeRequirements })
    ).rejects.toThrow(/does not declare/);
  });
});

describe('verifyMessageConsentToken', () => {
  const message = (token: string, sessionId = 'sess_test123') =>
    withConsentToken({ messageId: 'm1', role: 'ROLE_USER', parts: [{ text: 'Show me flights' }] }, token, sessionId);

  it('extracts and verifies a consent token from message metadata', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const { claims, sessionId } = await verifyMessageConsentToken(message(token), pemPublicKey, { agentId: 'prf_agent_target' });
    expect(claims.scope).toBe('test-scope');
    expect(sessionId).toBe('sess_test123');
  });

  it('accepts a v1 consent data part', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const v1 = { parts: [{ kind: 'data', data: { 'parafe.trust.ConsentToken': { token, session_id: 'sess_test123' } } }] };
    const { sessionId } = await verifyMessageConsentToken(v1, pemPublicKey, { agentId: 'prf_agent_target' });
    expect(sessionId).toBe('sess_test123');
  });

  it('ignores a v1 consent data part when acceptV1 is false', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const v1 = { parts: [{ kind: 'data', data: { 'parafe.trust.ConsentToken': { token, session_id: 'sess_test123' } } }] };
    await expect(
      verifyMessageConsentToken(v1, pemPublicKey, { agentId: 'prf_agent_target', acceptV1: false })
    ).rejects.toThrow(MissingParafeExtensionError);
  });

  it('throws MissingParafeExtensionError when the message has no consent token', async () => {
    const { pemPublicKey } = await createTestToken();
    await expect(
      verifyMessageConsentToken({ parts: [{ text: 'no token here' }] }, pemPublicKey, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(MissingParafeExtensionError);
  });

  it('rejects a token issued for another agent', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token), pemPublicKey, { agentId: 'prf_agent_me' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects when the message names a different session than the token', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token, 'sess_other'), pemPublicKey, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('verifies the action when provided', async () => {
    const { token, pemPublicKey } = await createTestToken();
    const { claims } = await verifyMessageConsentToken(message(token), pemPublicKey, { agentId: 'prf_agent_target', action: 'read_data' });
    expect(claims.permissions).toContain('read_data');
  });

  it('throws ScopeViolationError for an excluded action', async () => {
    const { token, pemPublicKey } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token), pemPublicKey, { agentId: 'prf_agent_target', action: 'delete_data' })
    ).rejects.toThrow(ScopeViolationError);
  });
});
