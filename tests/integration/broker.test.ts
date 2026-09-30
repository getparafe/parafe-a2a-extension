/**
 * Integration tests — validate the A2A extension against the live Parafe broker.
 *
 * These tests call the real broker's /public-key endpoint to fetch the Ed25519
 * public key, then verify that fetchBrokerPublicKey() returns a valid PEM key
 * that can be used with verifyConsentTokenOffline().
 *
 * Required environment variables:
 *   PARAFE_TEST_BROKER_URL — broker URL (e.g. https://parafe-staging.up.railway.app)
 *
 * Run:
 *   PARAFE_TEST_BROKER_URL=https://parafe-staging.up.railway.app npm run test:integration
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { SignJWT, generateKeyPair, exportSPKI } from 'jose';
import {
  fetchBrokerPublicKey,
  verifyConsentTokenOffline,
  InvalidConsentTokenError,
} from '../../src/index.js';

const BROKER_URL = process.env['PARAFE_TEST_BROKER_URL'];

const describeIntegration = BROKER_URL ? describe : describe.skip;

describeIntegration('integration: fetchBrokerPublicKey against live broker', () => {
  let brokerPublicKey: string;

  beforeAll(async () => {
    brokerPublicKey = await fetchBrokerPublicKey(BROKER_URL);
  });

  it('returns a PEM-formatted public key', () => {
    expect(brokerPublicKey).toContain('-----BEGIN PUBLIC KEY-----');
    expect(brokerPublicKey).toContain('-----END PUBLIC KEY-----');
  });

  it('returned key is a valid Ed25519 public key (can be imported)', async () => {
    // importSPKI is used internally by verifyConsentTokenOffline — if this succeeds,
    // the key format is correct
    const { importSPKI } = await import('jose');
    const key = await importSPKI(brokerPublicKey, 'EdDSA');
    expect(key).toBeTruthy();
    expect(key.type).toBe('public');
  });

  it('rejects a token signed with a different key', async () => {
    // Create a token signed with a random key (not the broker)
    const { privateKey } = await generateKeyPair('EdDSA');

    const fakeToken = await new SignJWT({
      scope: 'test',
      permissions: ['read'],
      excluded: [],
      session_id: 'sess_fake',
      token_type: 'consent',
      authorization_modality: 'autonomous',
      initiator_agent_id: null,
      target_agent_id: null,
    })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer('parafe-trust-broker')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    // Verify against the REAL broker key — should fail because the token
    // was signed with our random key, not the broker's key
    await expect(
      verifyConsentTokenOffline(fakeToken, brokerPublicKey)
    ).rejects.toThrow(InvalidConsentTokenError);
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
} from '../../src/index.js';

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
    const a = await post('/agents/register', { agent_name: `ext-alex-${suffix}`, owner: 'Ext', public_key: spki(alex.publicKey) }, auth);
    const b = await post('/agents/register', { agent_name: `ext-shop-${suffix}`, owner: 'Ext', public_key: spki(shop.publicKey), scope_policies: { order: { permissions: ['create_order'], exclusions: ['issue_refund'] } } }, auth);
    const pop = await new SignJWT({ htm: 'POST', htu: `${BROKER_URL}/handshake/initiate`, target_agent_id: b.agent_id, requested_scope: 'order', jti: randomUUID() })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'parafe-pop+jwt' }).setIssuedAt().sign(alex.privateKey);
    const init = await post('/handshake/initiate', { initiator_credential: a.credential, target_agent_id: b.agent_id, requested_scope: 'order' }, { 'Parafe-PoP': pop });
    const done = await post('/handshake/complete', { handshake_id: init.handshake_id, target_credential: b.credential, challenge_response: nodeSign(null, Buffer.from(init.challenge_for_target, 'hex'), shop.privateKey).toString('base64') });

    const keys = await fetchBrokerKeys(BROKER_URL);
    const token = done.consent_token.token as string;
    const proof = await createPresentationProof(token, alex.privateKey, { messageId: 'm-1' });
    const msg = { messageId: 'm-1', ...withConsentToken({ parts: [] }, token, done.session.session_id, proof) };
    const r = await verifyMessageConsentToken(msg, keys, { agentId: b.agent_id, action: 'create_order', brokerUrl: BROKER_URL as string, requireProof: true });
    expect(r.proofVerified).toBe(true);
    expect(r.claims.exclusions).toEqual(['issue_refund']);
    expect(r.claims.initiator_proof).toBe('pop');

    // Someone who stole the token but not Alex's key can't present it
    const thief = generateKeyPairSync('ed25519');
    const stolen = { messageId: 'm-2', ...withConsentToken({ parts: [] }, token, done.session.session_id, await createPresentationProof(token, thief.privateKey)) };
    await expect(verifyMessageConsentToken(stolen, keys, { agentId: b.agent_id, brokerUrl: BROKER_URL as string })).rejects.toBeInstanceOf(InvalidProofError);
  });
});
