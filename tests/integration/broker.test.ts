/**
 * Integration tests — validate the A2A extension against the live Parafe broker.
 *
 * Required environment variables:
 *   PARAFE_TEST_BROKER_URL — broker URL (e.g. https://parafe-staging.up.railway.app)
 *
 * Run:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run test:integration
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, generateKeyPair } from 'jose';
import {
  verifyConsentTokenOffline,
  InvalidConsentTokenError,
  type BrokerKeys,
} from '../../src/index.js';

const BROKER_URL = process.env['PARAFE_TEST_BROKER_URL'];

const describeIntegration = BROKER_URL ? describe : describe.skip;

describeIntegration('integration: the broker JWKS', () => {
  let keys: BrokerKeys;

  beforeAll(async () => {
    const { fetchBrokerKeys } = await import('../../src/index.js');
    keys = await fetchBrokerKeys(BROKER_URL);
  });

  it('has an active ES256 key with a kid', () => {
    const active = keys.keys.find((k) => k.alg === 'ES256');
    expect(active?.kid).toBeTruthy();
  });

  it("rejects a token signed with another key under the broker's kid", async () => {
    const kid = keys.keys.find((k) => k.alg === 'ES256')!.kid!;
    const { privateKey } = await generateKeyPair('ES256');
    const fakeToken = await new SignJWT({
      scope: 'test', permissions: ['read'], exclusions: [], session_id: 'sess_fake', token_type: 'consent',
      authorization_modality: 'autonomous', initiator_agent_id: null, target_agent_id: null,
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .setIssuer('parafe-trust-broker')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(verifyConsentTokenOffline(fakeToken, keys)).rejects.toThrow(InvalidConsentTokenError);
  });
});

// ── 2.1: broker JWKS, key-bound tokens and presentation proofs against a real broker ──

import { generateKeyPairSync, sign as nodeSign, randomUUID } from 'node:crypto';
import {
  fetchBrokerKeys,
  verifyMessageConsentToken,
  createPresentationProof,
  withConsentToken,
  InvalidProofError,
  createActionReceiptSigner,
} from '../../src/index.js';
import { decodeJwt } from 'jose';

describeIntegration('integration: key-bound consent tokens (2.1)', () => {
  it('verifies a real token by kid and checks a real presentation proof (initiator key from its DID document)', async () => {
    const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
      const res = await fetch(`${BROKER_URL}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error(`${res.status} ${path}: ${await res.text()}`);
      return res.json() as Promise<Record<string, any>>;
    };
    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const signup = await post('/auth/signup', { email: `ext-${suffix}@example.com`, password: 'test-password-12345', name: 'Ext Integration' });
    const auth = { Authorization: `Bearer ${signup.api_key.key}` };
    const alex = generateKeyPairSync('ed25519');
    const shop = generateKeyPairSync('ed25519');
    const spki = (k: typeof alex.publicKey) => k.export({ type: 'spki', format: 'der' }).toString('base64');
    // Broker SPEC-003 part 4: registering a key needs a proof signed by it.
    const regProof = (key: typeof alex.privateKey) => new SignJWT({ htm: 'POST', htu: `${BROKER_URL}/agents/register`, jti: randomUUID() })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(key);
    const a = await post('/agents/register', { agent_name: `ext-alex-${suffix}`, principal_name: 'Ext', public_key: spki(alex.publicKey) }, { ...auth, 'Parafe-PoP': await regProof(alex.privateKey) });
    const b = await post('/agents/register', { agent_name: `ext-shop-${suffix}`, principal_name: 'Ext', public_key: spki(shop.publicKey), scope_policies: { order: { permissions: ['create_order'], exclusions: ['issue_refund'] } } }, { ...auth, 'Parafe-PoP': await regProof(shop.privateKey) });
    const pop = await new SignJWT({ htm: 'POST', htu: `${BROKER_URL}/handshake/initiate`, target_agent_id: b.agent_id, requested_scope: 'order', jti: randomUUID() })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(alex.privateKey);
    const init = await post('/handshake/initiate', { initiator_credential: a.credential, target_agent_id: b.agent_id, requested_scope: 'order' }, { 'Parafe-PoP': pop });
    const done = await post('/handshake/complete', { handshake_id: init.handshake_id, target_credential: b.credential, challenge_response: nodeSign(null, Buffer.from(init.challenge_for_target, 'hex'), shop.privateKey).toString('base64') });

    const keys = await fetchBrokerKeys(BROKER_URL);
    const token = done.consent_token.token as string;
    const proof = await createPresentationProof(token, alex.privateKey, { messageId: 'm-1' });
    const msg = { messageId: 'm-1', ...withConsentToken({ parts: [] }, token, done.session.session_id, proof) };
    const r = await verifyMessageConsentToken(msg, keys, { agentId: b.agent_id, action: 'create_order', brokerUrl: BROKER_URL as string }); // 3.0: proof required by default
    expect(r.proofVerified).toBe(true);
    expect(r.claims.exclusions).toEqual(['issue_refund']);
    expect(r.claims.initiator_proof).toBe('pop');

    // Someone who stole the token but not Alex's key can't present it
    const thief = generateKeyPairSync('ed25519');
    const stolen = { messageId: 'm-2', ...withConsentToken({ parts: [] }, token, done.session.session_id, await createPresentationProof(token, thief.privateKey)) };
    await expect(verifyMessageConsentToken(stolen, keys, { agentId: b.agent_id, brokerUrl: BROKER_URL as string })).rejects.toBeInstanceOf(InvalidProofError);

    // 2.2: the shop receipts what it did and what it refused; the broker indexes both
    const sessionId = done.session.session_id as string;
    const receipts = createActionReceiptSigner({ agentId: b.agent_id, agentDid: b.did, privateKey: shop.privateKey, credential: b.credential, brokerUrl: BROKER_URL as string });
    const orderMsg = { messageId: 'm-3', ...withConsentToken({ parts: [] }, token, sessionId, await createPresentationProof(token, alex.privateKey, { messageId: 'm-3' })) };
    const ok = await verifyMessageConsentToken(orderMsg, keys, { agentId: b.agent_id, action: 'create_order', brokerUrl: BROKER_URL as string, receipts });
    const done1 = await ok.completeAction({ businessRef: 'ord_ext_1' });
    expect((await done1.filed)?.seq).toBe(1);
    const refundMsg = { messageId: 'm-4', ...withConsentToken({ parts: [] }, token, sessionId, await createPresentationProof(token, alex.privateKey, { messageId: 'm-4' })) };
    const refused = await verifyMessageConsentToken(refundMsg, keys, { agentId: b.agent_id, action: 'issue_refund', brokerUrl: BROKER_URL as string, receipts }).catch((e) => e);
    expect(refused.actionReceipt).toBeTruthy();
    await receipts.flush();
    const closePop = await new SignJWT({ htm: 'POST', htu: `${BROKER_URL}/session/close`, session_id: sessionId, jti: randomUUID() })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(alex.privateKey);
    const closed = await post('/session/close', { session_id: sessionId }, { Authorization: `Bearer ${a.credential}`, 'Parafe-PoP': closePop });
    const actions = decodeJwt(closed.receipt as string)['actions'] as Array<{ action: string; result: string; error: string | null }>;
    expect(actions.map((x) => [x.action, x.result, x.error])).toEqual([['create_order', 'success', null], ['issue_refund', 'error', 'excluded']]);
  });
});

// ── Broker SPEC-006: an agent replaces its key ──

describeIntegration('integration: key rotation (broker SPEC-006)', () => {
  it('after rotating, receipts carry #keys-2 and file; proofs from the retired key are refused', async () => {
    const post = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
      const res = await fetch(`${BROKER_URL}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error(`${res.status} ${path}: ${await res.text()}`);
      return res.json() as Promise<Record<string, any>>;
    };
    // Self-registered agents (no API key): each rotates itself, with its credential and a proof from its current key.
    const spki = (k: ReturnType<typeof generateKeyPairSync>['publicKey']) => k.export({ type: 'spki', format: 'der' }).toString('base64');
    const proofBy = (key: ReturnType<typeof generateKeyPairSync>['privateKey'], htu: string, claims: Record<string, unknown> = {}) =>
      new SignJWT({ htm: 'POST', htu, jti: randomUUID(), ...claims }).setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(key);
    const register = async (key: ReturnType<typeof generateKeyPairSync>, extra: Record<string, unknown> = {}) =>
      post('/agents/register', { public_key: spki(key.publicKey), ...extra }, { 'Parafe-PoP': await proofBy(key.privateKey, `${BROKER_URL}/agents/register`) });
    const rotate = async (agent: Record<string, any>, current: ReturnType<typeof generateKeyPairSync>, next: ReturnType<typeof generateKeyPairSync>) => {
      const url = `${BROKER_URL}/agents/${agent.agent_id}/rotate-key`;
      return post(`/agents/${agent.agent_id}/rotate-key`, { new_public_key: spki(next.publicKey), new_key_proof: await proofBy(next.privateKey, url, { agent_id: agent.agent_id }) },
        { Authorization: `Bearer ${agent.credential}`, 'Parafe-PoP': await proofBy(current.privateKey, url, { agent_id: agent.agent_id }) });
    };
    const handshake = async (alexKey: ReturnType<typeof generateKeyPairSync>, alexCred: string, shopKey: ReturnType<typeof generateKeyPairSync>, shopCred: string, shopId: string) => {
      const init = await post('/handshake/initiate', { initiator_credential: alexCred, target_agent_id: shopId, requested_scope: 'order' },
        { 'Parafe-PoP': await proofBy(alexKey.privateKey, `${BROKER_URL}/handshake/initiate`, { target_agent_id: shopId, requested_scope: 'order' }) });
      return post('/handshake/complete', { handshake_id: init.handshake_id, target_credential: shopCred, challenge_response: nodeSign(null, Buffer.from(init.challenge_for_target, 'hex'), shopKey.privateKey).toString('base64') });
    };

    let alexKey = generateKeyPairSync('ed25519');
    let shopKey = generateKeyPairSync('ed25519');
    const a = await register(alexKey);
    const b = await register(shopKey, { scope_policies: { order: { permissions: ['create_order'] } } });
    const keys = await fetchBrokerKeys(BROKER_URL);
    const before = await handshake(alexKey, a.credential, shopKey, b.credential, b.agent_id);
    const oldToken = before.consent_token.token as string;

    // Both agents replace their keys.
    const oldAlexKey = alexKey;
    alexKey = generateKeyPairSync('ed25519');
    const ra = await rotate(a, oldAlexKey, alexKey);
    const oldShopKey = shopKey;
    shopKey = generateKeyPairSync('ed25519');
    const rb = await rotate(b, oldShopKey, shopKey);
    expect(rb.kid).toBe(`${b.did}#keys-2`);

    // A token from before, presented with the retired key: refused (the DID document's current key is the new one).
    const stale = { messageId: 'm-r1', ...withConsentToken({ parts: [] }, oldToken, before.session.session_id, await createPresentationProof(oldToken, oldAlexKey.privateKey)) };
    await expect(verifyMessageConsentToken(stale, keys, { agentId: b.agent_id, brokerUrl: BROKER_URL as string })).rejects.toBeInstanceOf(InvalidProofError);

    // A new session with the new keys: the proof checks, the shop's receipt carries #keys-2 and the broker indexes it.
    const after = await handshake(alexKey, ra.credential, shopKey, rb.credential, b.agent_id);
    const token = after.consent_token.token as string;
    const receipts = createActionReceiptSigner({ agentId: b.agent_id, agentDid: b.did, privateKey: () => shopKey.privateKey, credential: () => rb.credential, brokerUrl: BROKER_URL as string });
    const msg = { messageId: 'm-r2', ...withConsentToken({ parts: [] }, token, after.session.session_id, await createPresentationProof(token, alexKey.privateKey, { messageId: 'm-r2' })) };
    const ok = await verifyMessageConsentToken(msg, keys, { agentId: b.agent_id, action: 'create_order', brokerUrl: BROKER_URL as string, receipts });
    expect(ok.proofVerified).toBe(true);
    const done = await ok.completeAction({ businessRef: 'ord_rot_1' });
    expect(decodeJwt(done.receipt) && JSON.parse(Buffer.from(done.receipt.split('.')[0]!, 'base64url').toString()).kid).toBe(`${b.did}#keys-2`);
    expect((await done.filed)?.seq).toBe(1);
  });
});
