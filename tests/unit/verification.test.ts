import { describe, it, expect } from 'vitest';
import { SignJWT, exportJWK, exportSPKI, generateKeyPair } from 'jose';
import {
  verifyConsentTokenOffline,
  verifyMessageConsentToken,
  withConsentToken,
  InvalidConsentTokenError,
  WrongAudienceError,
  ExpiredConsentTokenError,
  ScopeViolationError,
  MissingParafeExtensionError,
  InvalidProofError,
} from '../../src/index.js';

/** A broker JWKS holding one ES256 key, as /.well-known/jwks.json serves it. */
async function brokerJwks(publicKey: CryptoKey | import('jose').KeyLike) {
  return { keys: [{ ...(await exportJWK(publicKey)), kid: 'broker-1', alg: 'ES256', use: 'sig' }] };
}

async function createTestToken(
  overrides: Record<string, unknown> = {},
  expiresIn = '5m'
) {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const brokerKeys = await brokerJwks(publicKey);

  const claims = {
    scope: 'test-scope',
    permissions: ['read_data', 'write_data'],
    exclusions: ['delete_data'],
    session_id: 'sess_test123',
    token_type: 'consent',
    authorization_modality: 'autonomous',
    initiator_agent_id: 'prf_agent_initiator',
    target_agent_id: 'prf_agent_target',
    ...overrides,
  };

  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', kid: 'broker-1' })
    .setIssuer('parafe-trust-broker')
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(privateKey);

  return { token, brokerKeys, claims };
}

describe('verifyConsentTokenOffline', () => {
  it('verifies a valid consent token and returns claims', async () => {
    const { token, brokerKeys } = await createTestToken();
    const claims = await verifyConsentTokenOffline(token, brokerKeys);

    expect(claims.scope).toBe('test-scope');
    expect(claims.permissions).toEqual(['read_data', 'write_data']);
    expect(claims.exclusions).toEqual(['delete_data']);
    expect(claims).not.toHaveProperty('excluded');
    expect(claims.session_id).toBe('sess_test123');
    expect(claims.token_type).toBe('consent');
    expect(claims.authorization_modality).toBe('autonomous');
    expect(claims.initiator_agent_id).toBe('prf_agent_initiator');
    expect(claims.target_agent_id).toBe('prf_agent_target');
    expect(claims.iss).toBe('parafe-trust-broker');
  });

  it('rejects a token signed with the wrong key', async () => {
    const { token } = await createTestToken();
    const { publicKey: wrongKey } = await generateKeyPair('ES256');

    await expect(
      verifyConsentTokenOffline(token, await brokerJwks(wrongKey))
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects a malformed token', async () => {
    const { brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline('not-a-jwt', brokerKeys)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects an expired token with ExpiredConsentTokenError', async () => {
    const { token, brokerKeys } = await createTestToken({}, '-1s');
    await expect(
      verifyConsentTokenOffline(token, brokerKeys)
    ).rejects.toThrow(ExpiredConsentTokenError);
  });

  it('rejects a token with wrong issuer', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const brokerKeys = await brokerJwks(publicKey);

    const token = await new SignJWT({ token_type: 'consent', scope: 'test' })
      .setProtectedHeader({ alg: 'ES256', kid: 'broker-1' })
      .setIssuer('wrong-issuer')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(
      verifyConsentTokenOffline(token, brokerKeys)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('rejects a token with wrong token_type', async () => {
    const { token, brokerKeys } = await createTestToken({ token_type: 'session' });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys)
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('passes when requiredAction is in permissions', async () => {
    const { token, brokerKeys } = await createTestToken();
    const claims = await verifyConsentTokenOffline(token, brokerKeys, 'read_data');
    expect(claims.permissions).toContain('read_data');
  });

  it('throws ScopeViolationError when requiredAction is excluded', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, 'delete_data')
    ).rejects.toThrow(ScopeViolationError);
  });

  it('throws ScopeViolationError when requiredAction is not in permissions', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, 'admin_override')
    ).rejects.toThrow(ScopeViolationError);
  });

  it('3.0: refuses EdDSA-signed tokens, a PEM key, and a token without `exclusions`', async () => {
    const ed = await generateKeyPair('EdDSA');
    const edKeys = { keys: [{ ...(await exportJWK(ed.publicKey)), kid: 'broker-1', alg: 'EdDSA' }] };
    const edToken = await new SignJWT({ token_type: 'consent', scope: 's', permissions: [], exclusions: [], session_id: 'sess_1' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'broker-1' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(ed.privateKey);
    await expect(verifyConsentTokenOffline(edToken, edKeys)).rejects.toThrow(InvalidConsentTokenError);

    const { token, brokerKeys } = await createTestToken();
    const pem = await exportSPKI((await generateKeyPair('ES256')).publicKey);
    await expect(verifyConsentTokenOffline(token, pem as never)).rejects.toThrow(/JWKS/);

    const old = await createTestToken({ exclusions: undefined, excluded: ['delete_data'] });
    await expect(verifyConsentTokenOffline(old.token, old.brokerKeys)).rejects.toThrow(/exclusions/);
    expect(brokerKeys.keys).toHaveLength(1);
  });
});

describe('verifyConsentTokenOffline checks', () => {
  const scopeRequirements = {
    'test-scope': { permissions: ['read_data', 'write_data', 'delete_data'], minimum_authorization_modality: 'autonomous' as const },
  };

  it('accepts a token issued for this agent', async () => {
    const { token, brokerKeys } = await createTestToken();
    const claims = await verifyConsentTokenOffline(token, brokerKeys, { agentId: 'prf_agent_target' });
    expect(claims.target_agent_id).toBe('prf_agent_target');
  });

  it('rejects a token issued for a different agent', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { agentId: 'prf_agent_someone_else' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects a token with no target when an agent is expected', async () => {
    const { token, brokerKeys } = await createTestToken({ target_agent_id: null });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects a session mismatch', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { sessionId: 'sess_other' })
    ).rejects.toThrow(/session/);
  });

  it('accepts a token within the declared scope requirements', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { scopeRequirements, action: 'write_data' })
    ).resolves.toBeTruthy();
  });

  it('rejects a scope the agent does not declare', async () => {
    const { token, brokerKeys } = await createTestToken({ scope: 'admin' });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { scopeRequirements })
    ).rejects.toThrow(/does not declare/);
  });

  it('rejects permissions outside the declared scope', async () => {
    const { token, brokerKeys } = await createTestToken({ permissions: ['read_data', 'transfer_funds'] });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { scopeRequirements })
    ).rejects.toThrow(/transfer_funds/);
  });

  it('rejects a modality below the scope minimum', async () => {
    const { token, brokerKeys } = await createTestToken({ authorization_modality: 'autonomous' });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: 'attested' } },
      })
    ).rejects.toThrow(ScopeViolationError);
  });

  it('accepts a modality above the scope minimum', async () => {
    const { token, brokerKeys } = await createTestToken({ authorization_modality: 'verified' });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: 'attested' } },
      })
    ).resolves.toBeTruthy();
  });

  it("B8: 'delegated' meets an attested or delegated scope, not a verified one", async () => {
    const { token, brokerKeys } = await createTestToken({ authorization_modality: 'delegated' });
    for (const [min, ok] of [['attested', true], ['delegated', true], ['verified', false]] as const) {
      const p = verifyConsentTokenOffline(token, brokerKeys, {
        scopeRequirements: { 'test-scope': { ...scopeRequirements['test-scope'], minimum_authorization_modality: min } },
      });
      if (ok) await expect(p).resolves.toBeTruthy();
      else await expect(p).rejects.toThrow(ScopeViolationError);
    }
  });

  it('does not treat inherited object keys as declared scopes', async () => {
    const { token, brokerKeys } = await createTestToken({ scope: 'toString' });
    await expect(
      verifyConsentTokenOffline(token, brokerKeys, { scopeRequirements })
    ).rejects.toThrow(/does not declare/);
  });
});

describe('verifyMessageConsentToken', () => {
  const message = (token: string, sessionId = 'sess_test123') =>
    withConsentToken({ messageId: 'm1', role: 'ROLE_USER', parts: [{ text: 'Show me flights' }] }, token, sessionId);

  it('extracts and verifies a consent token from message metadata', async () => {
    const { token, brokerKeys } = await createTestToken();
    const { claims, sessionId } = await verifyMessageConsentToken(message(token), brokerKeys, { agentId: 'prf_agent_target', requireProof: false });
    expect(claims.scope).toBe('test-scope');
    expect(sessionId).toBe('sess_test123');
  });

  it('3.0: refuses a token sent without a presentation proof by default', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token), brokerKeys, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(InvalidProofError);
  });

  it('throws MissingParafeExtensionError when the message has no consent token', async () => {
    const { brokerKeys } = await createTestToken();
    await expect(
      verifyMessageConsentToken({ parts: [{ text: 'no token here' }] }, brokerKeys, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(MissingParafeExtensionError);
  });

  it('rejects a token issued for another agent', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token), brokerKeys, { agentId: 'prf_agent_me' })
    ).rejects.toThrow(WrongAudienceError);
  });

  it('rejects when the message names a different session than the token', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token, 'sess_other'), brokerKeys, { agentId: 'prf_agent_target' })
    ).rejects.toThrow(InvalidConsentTokenError);
  });

  it('verifies the action when provided', async () => {
    const { token, brokerKeys } = await createTestToken();
    const { claims } = await verifyMessageConsentToken(message(token), brokerKeys, { agentId: 'prf_agent_target', action: 'read_data', requireProof: false });
    expect(claims.permissions).toContain('read_data');
  });

  it('throws ScopeViolationError for an excluded action', async () => {
    const { token, brokerKeys } = await createTestToken();
    await expect(
      verifyMessageConsentToken(message(token), brokerKeys, { agentId: 'prf_agent_target', action: 'delete_data' })
    ).rejects.toThrow(ScopeViolationError);
  });
});
