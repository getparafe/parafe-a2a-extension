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
