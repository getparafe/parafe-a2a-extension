/**
 * Broker keys by kid (ES256), consent tokens (exclusions, cnf, initiator_proof),
 * presentation proofs (required by default in 3.0), and session_closed.
 */
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createHash, randomUUID } from 'node:crypto';
import { SignJWT, calculateJwkThumbprint, type JWK } from 'jose';
import {
  verifyConsentTokenOffline,
  verifyMessageConsentToken,
  createPresentationProof,
  withConsentToken,
  withSessionClosed,
  extractSessionClosed,
  InvalidProofError,
  InvalidConsentTokenError,
  ScopeViolationError,
  PARAFE_EXTENSION_URI,
  type BrokerKeys,
  type Parties,
} from '../../src/index.js';

const broker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const legacy = generateKeyPairSync('ed25519');
const KEYS: BrokerKeys = {
  keys: [
    { ...(broker.publicKey.export({ format: 'jwk' }) as JWK), kid: 'es-1', alg: 'ES256', status: 'active' } as BrokerKeys['keys'][number],
    { ...(legacy.publicKey.export({ format: 'jwk' }) as JWK), kid: 'ed-1', alg: 'EdDSA', status: 'retired' } as BrokerKeys['keys'][number],
  ],
};

const initiator = generateKeyPairSync('ed25519');
const initiatorJwk = initiator.publicKey.export({ format: 'jwk' }) as JWK;
const SHOP_DID = 'did:web:api.parafe.ai:agents:prf_agent_shop';

async function tokenV2(extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({
    ver: 2, token_type: 'consent', scope: 'place-order', permissions: ['create_order'],
    exclusions: ['issue_refund'], session_id: 'sess_1',
    authorization_modality: 'attested', initiator_agent_id: 'prf_agent_alex', target_agent_id: 'prf_agent_shop',
    cnf: { jkt: await calculateJwkThumbprint(initiatorJwk) }, initiator_proof: 'pop', ...extra,
  }).setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuer('parafe-trust-broker')
    .setSubject('prf_agent_alex').setAudience(SHOP_DID).setIssuedAt().setExpirationTime('5m').setJti(randomUUID())
    .sign(broker.privateKey);
}

describe('broker keys and consent token v2', () => {
  it('verifies an ES256 token against the JWKS', async () => {
    const claims = await verifyConsentTokenOffline(await tokenV2(), KEYS, { agentId: 'prf_agent_shop' });
    expect(claims.exclusions).toEqual(['issue_refund']);
    expect(claims.initiator_proof).toBe('pop');
    expect(claims.aud).toBe(SHOP_DID);
  });

  it('SPEC-002: returns the parties the broker names (operator and principal)', async () => {
    const parties: Parties = { operator: { type: 'org', id: 'prf_org_p' }, principal: { type: 'external', ref: 'user-8f3a' } };
    const claims = await verifyConsentTokenOffline(await tokenV2({ initiator_parties: parties, target_parties: { operator: { type: 'org', id: 'prf_org_s' }, principal: { type: 'org', id: 'prf_org_s' } } }), KEYS, { agentId: 'prf_agent_shop' });
    expect(claims.initiator_parties).toEqual(parties);
    expect(claims.target_parties?.principal).toEqual({ type: 'org', id: 'prf_org_s' });
  });

  it('3.0: refuses a token signed by the retired Ed25519 key, even though the JWKS lists it', async () => {
    const old = await new SignJWT({ token_type: 'consent', scope: 's', permissions: ['a'], exclusions: [], session_id: 'sess_1', authorization_modality: 'autonomous' })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'ed-1' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(legacy.privateKey);
    await expect(verifyConsentTokenOffline(old, KEYS)).rejects.toBeInstanceOf(InvalidConsentTokenError);
  });

  it('enforces minimum_initiator_proof from the scope requirements', async () => {
    const scopes = { 'place-order': { permissions: ['create_order'], minimum_authorization_modality: 'attested' as const, minimum_initiator_proof: 'pop' as const } };
    await expect(verifyConsentTokenOffline(await tokenV2(), KEYS, { scopeRequirements: scopes })).resolves.toBeTruthy();
    await expect(verifyConsentTokenOffline(await tokenV2({ initiator_proof: 'credential' }), KEYS, { scopeRequirements: scopes })).rejects.toBeInstanceOf(ScopeViolationError);
  });
});

describe('presentation proofs', () => {
  const opts = { agentId: 'prf_agent_shop', initiatorKey: initiatorJwk };
  const message = async (token: string, proof?: string, messageId = 'msg-1') =>
    ({ messageId, ...withConsentToken({ parts: [] }, token, 'sess_1', proof) });

  it('accepts a proof by the bound key, for this token and message; refuses a replay', async () => {
    const token = await tokenV2();
    const proof = await createPresentationProof(token, initiator.privateKey, { messageId: 'msg-1' });
    const msg = await message(token, proof);
    const r = await verifyMessageConsentToken(msg, KEYS, opts);
    expect(r.proofVerified).toBe(true);
    await expect(verifyMessageConsentToken(msg, KEYS, opts)).rejects.toBeInstanceOf(InvalidProofError);
  });

  it('refuses a proof by another key, for another token, or for another message', async () => {
    const token = await tokenV2();
    const stranger = generateKeyPairSync('ed25519');
    await expect(verifyMessageConsentToken(await message(token, await createPresentationProof(token, stranger.privateKey)), KEYS, opts)).rejects.toBeInstanceOf(InvalidProofError);
    const other = await tokenV2();
    await expect(verifyMessageConsentToken(await message(token, await createPresentationProof(other, initiator.privateKey)), KEYS, opts)).rejects.toBeInstanceOf(InvalidProofError);
    await expect(verifyMessageConsentToken(await message(token, await createPresentationProof(token, initiator.privateKey, { messageId: 'msg-9' })), KEYS, opts)).rejects.toBeInstanceOf(InvalidProofError);
  });

  it('refuses a stale proof', async () => {
    const token = await tokenV2();
    const ath = createHash('sha256').update(token).digest('base64url');
    const stale = await new SignJWT({ ath, aud: SHOP_DID, jti: randomUUID() }).setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600).sign(initiator.privateKey);
    await expect(verifyMessageConsentToken(await message(token, stale), KEYS, opts)).rejects.toBeInstanceOf(InvalidProofError);
  });

  it('3.0: without a proof, refused by default; accepted with requireProof: false', async () => {
    const token = await tokenV2();
    await expect(verifyMessageConsentToken(await message(token), KEYS, opts)).rejects.toThrow(/requires a presentation proof/);
    expect((await verifyMessageConsentToken(await message(token), KEYS, { ...opts, requireProof: false })).proofVerified).toBe(false);
  });

  it('P-256 initiators sign ES256', async () => {
    const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = p256.publicKey.export({ format: 'jwk' }) as JWK;
    const token = await tokenV2({ cnf: { jkt: await calculateJwkThumbprint(jwk) } });
    const proof = await createPresentationProof(token, p256.privateKey);
    const r = await verifyMessageConsentToken(await message(token, proof), KEYS, { agentId: 'prf_agent_shop', initiatorKey: jwk });
    expect(r.proofVerified).toBe(true);
  });

  it('createPresentationProof refuses a token with no audience', async () => {
    const old = await new SignJWT({ token_type: 'consent' }).setProtectedHeader({ alg: 'EdDSA' }).sign(legacy.privateKey);
    await expect(createPresentationProof(old, initiator.privateKey)).rejects.toBeInstanceOf(InvalidConsentTokenError);
  });
});

describe('session_closed', () => {
  it('round-trips the receipt JWS in metadata', () => {
    const msg = withSessionClosed({ parts: [] }, 'sess_1', 'a.b.c');
    expect(msg.extensions).toContain(PARAFE_EXTENSION_URI);
    expect(extractSessionClosed(msg)).toEqual({ session_id: 'sess_1', receipt: 'a.b.c' });
  });
  it('rejects a receipt that is not a JWS', () => {
    const msg = { metadata: { [PARAFE_EXTENSION_URI]: { session_closed: { session_id: 's', receipt: 'nope' } } } };
    expect(() => extractSessionClosed(msg)).toThrow();
  });
});

describe('createBrokerKeyCache (FRICTION #68: a key added after startup)', () => {
  it('refetches once when a token names a key it does not have, and rate-limits refetches', async () => {
    const { vi } = await import('vitest');
    const { createBrokerKeyCache } = await import('../../src/index.js');
    const newKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const newJwk = { ...(newKey.publicKey.export({ format: 'jwk' }) as JWK), kid: 'es-2', alg: 'ES256', status: 'active' };
    let calls = 0;
    const realFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () => {
      calls++;
      const body = calls === 1 ? KEYS : { keys: [...KEYS.keys, newJwk] };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;
    try {
      const cache = createBrokerKeyCache('https://broker.test', { minRefetchIntervalMs: 0 });
      expect((await verifyConsentTokenOffline(await tokenV2(), cache)).scope).toBe('place-order'); // first fetch
      const rotated = await new SignJWT({ token_type: 'consent', scope: 's', permissions: [], exclusions: [], session_id: 'sess_1', authorization_modality: 'autonomous' })
        .setProtectedHeader({ alg: 'ES256', kid: 'es-2' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(newKey.privateKey);
      expect((await verifyConsentTokenOffline(rotated, cache)).scope).toBe('s');
      expect(calls).toBe(2);

      const limited = createBrokerKeyCache('https://broker.test', { minRefetchIntervalMs: 60_000 });
      calls = 0;
      await limited.get();
      await expect(verifyConsentTokenOffline(rotated, limited)).rejects.toBeInstanceOf(InvalidConsentTokenError);
      expect(calls).toBe(1); // no refetch within the interval
    } finally {
      globalThis.fetch = realFetch;
    }
  });
});
