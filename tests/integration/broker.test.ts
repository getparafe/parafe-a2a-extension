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
