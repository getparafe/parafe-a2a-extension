/**
 * 2.1: broker keys by kid (ES256), consent token v2 (exclusions, cnf,
 * initiator_proof), presentation proofs, and session_closed.
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
} from '../../src/index.js';

const broker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const legacy = generateKeyPairSync('ed25519');
const KEYS: BrokerKeys = {
  keys: [
    { ...(broker.publicKey.export({ format: 'jwk' }) as JWK), kid: 'es-1', alg: 'ES256', status: 'active' } as BrokerKeys['keys'][number],
    { ...(legacy.publicKey.export({ format: 'jwk' }) as JWK), kid: 'ed-1', alg: 'EdDSA', status: 'retired' } as BrokerKeys['keys'][number],
  ],
};
const LEGACY_PEM = legacy.publicKey.export({ type: 'spki', format: 'pem' }) as string;

const initiator = generateKeyPairSync('ed25519');
const initiatorJwk = initiator.publicKey.export({ format: 'jwk' }) as JWK;
const SHOP_DID = 'did:web:api.parafe.ai:agents:prf_agent_shop';

async function tokenV2(extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({
    ver: 2, token_type: 'consent', scope: 'place-order', permissions: ['create_order'],
    exclusions: ['issue_refund'], excluded: ['issue_refund'], session_id: 'sess_1',
    authorization_modality: 'attested', initiator_agent_id: 'prf_agent_alex', target_agent_id: 'prf_agent_shop',
    cnf: { jkt: await calculateJwkThumbprint(initiatorJwk) }, initiator_proof: 'pop', ...extra,
  }).setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuer('parafe-trust-broker')
    .setSubject('prf_agent_alex').setAudience(SHOP_DID).setIssuedAt().setExpirationTime('5m').setJti(randomUUID())
    .sign(broker.privateKey);
}

describe('broker keys and consent token v2', () => {
  it('verifies an ES256 token against the JWKS and sets exclusions and excluded', async () => {
    const claims = await verifyConsentTokenOffline(await tokenV2(), KEYS, { agentId: 'prf_agent_shop' });
    expect(claims.exclusions).toEqual(['issue_refund']);
    expect(claims.excluded).toEqual(['issue_refund']);
    expect(claims.initiator_proof).toBe('pop');
    expect(claims.aud).toBe(SHOP_DID);
  });

  it('still verifies a pre-2026-09-30 EdDSA token with a PEM key, reading `excluded`', async () => {
    const old = await new SignJWT({ token_type: 'consent', scope: 's', permissions: ['a'], excluded: ['b'], session_id: 'sess_1', authorization_modality: 'autonomous' })
      .setProtectedHeader({ alg: 'EdDSA' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(legacy.privateKey);
    const claims = await verifyConsentTokenOffline(old, LEGACY_PEM);
    expect(claims.exclusions).toEqual(['b']);
    await expect(verifyConsentTokenOffline(old, LEGACY_PEM, 'b')).rejects.toBeInstanceOf(ScopeViolationError);
  });

  it('a PEM key with an ES256 token explains what to do', async () => {
    await expect(verifyConsentTokenOffline(await tokenV2(), LEGACY_PEM)).rejects.toThrow(/fetchBrokerKeys/);
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

  it('without a proof: accepted by default in 2.x, refused with requireProof', async () => {
    const token = await tokenV2();
    expect((await verifyMessageConsentToken(await message(token), KEYS, opts)).proofVerified).toBe(false);
    await expect(verifyMessageConsentToken(await message(token), KEYS, { ...opts, requireProof: true })).rejects.toBeInstanceOf(InvalidProofError);
  });

  it('P-256 initiators sign ES256', async () => {
    const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = p256.publicKey.export({ format: 'jwk' }) as JWK;
    const token = await tokenV2({ cnf: { jkt: await calculateJwkThumbprint(jwk) } });
    const proof = await createPresentationProof(token, p256.privateKey);
    const r = await verifyMessageConsentToken(await message(token, proof), KEYS, { agentId: 'prf_agent_shop', initiatorKey: jwk });
    expect(r.proofVerified).toBe(true);
  });

  it('createPresentationProof refuses a token issued before key binding', async () => {
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
