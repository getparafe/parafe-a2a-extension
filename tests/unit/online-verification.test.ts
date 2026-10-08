/**
 * verifyConsentTokenOnline: the broker's refusal codes (P-53), the fallback for
 * brokers that give only a reason, and agent_id in the request.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';
import {
  verifyConsentTokenOnline,
  actionErrorFor,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  WrongAudienceError,
  InvalidProofError,
  ScopeViolationError,
} from '../../src/index.js';

const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const EXP = Math.floor(Date.now() / 1000) + 300;

async function token(): Promise<string> {
  return new SignJWT({ token_type: 'consent', session_id: 'sess_1', target_agent_id: 'prf_agent_shop', permissions: ['create_order'], exclusions: [] })
    .setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime(EXP)
    .sign(key.privateKey);
}

const requests: { url: string; body: Record<string, unknown> }[] = [];
function stubBroker(status: number, body: Record<string, unknown>) {
  requests.length = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    requests.push({ url, body: JSON.parse(String(init.body)) });
    return new Response(JSON.stringify(body), { status });
  }));
}
afterEach(() => vi.unstubAllGlobals());

const refusal = async (body: Record<string, unknown>, agentId?: string) => {
  stubBroker(401, { valid: false, ...body });
  return rejection(verifyConsentTokenOnline(await token(), { brokerUrl: 'https://broker.test', action: 'create_order', ...(agentId ? { agentId } : {}) }));
};
/** The error a verification throws (fails the test if it resolves). */
const rejection = (p: Promise<unknown>): Promise<Error> =>
  p.then(() => { throw new Error('expected a refusal'); }, (e: unknown) => e as Error);

describe('verifyConsentTokenOnline', () => {
  it('sends agent_id when agentId is given (the broker refuses another agent\'s token), and not otherwise', async () => {
    const ok = { valid: true, permitted: true, action: 'create_order', session_id: 'sess_1' };
    stubBroker(200, ok);
    const r = await verifyConsentTokenOnline(await token(), { brokerUrl: 'https://broker.test/', action: 'create_order', agentId: 'prf_agent_shop' });
    expect(r).toMatchObject({ valid: true, permitted: true, sessionId: 'sess_1' });
    expect(requests[0]!.url).toBe('https://broker.test/consent/verify');
    expect(requests[0]!.body).toMatchObject({ action: 'create_order', session_id: 'sess_1', agent_id: 'prf_agent_shop' });
    stubBroker(200, ok);
    await verifyConsentTokenOnline(await token(), { brokerUrl: 'https://broker.test', action: 'create_order' });
    expect(requests[0]!.body).not.toHaveProperty('agent_id');
  });

  it('maps each broker refusal code to its error', async () => {
    const expired = await refusal({ error: 'token_expired', reason: 'Consent token expired' });
    expect(expired).toBeInstanceOf(ExpiredConsentTokenError);
    expect((expired as ExpiredConsentTokenError).expiredAt.getTime()).toBe(EXP * 1000);

    const audience = await refusal({ error: 'wrong_audience', reason: 'Consent token was issued for another agent' }, 'prf_agent_other');
    expect(audience).toBeInstanceOf(WrongAudienceError);
    expect(audience).toMatchObject({ expectedAgentId: 'prf_agent_other', tokenAgentId: 'prf_agent_shop' });

    expect(await refusal({ error: 'proof_invalid', reason: 'proof is stale' })).toBeInstanceOf(InvalidProofError);

    const forged = await refusal({ error: 'token_invalid', reason: 'Consent token signature invalid' });
    expect(forged).toBeInstanceOf(InvalidConsentTokenError);
    expect(forged.message).toMatch(/signature invalid.*tampered with/);

    for (const [error, says] of [
      ['agent_revoked', /revoked or suspended/],
      ['session_inactive', /closed or expired.*new handshake/],
      ['session_not_found', /no such session/],
      ['session_mismatch', /another session/],
    ] as const) {
      const err = await refusal({ error, reason: `broker says ${error}` });
      expect(err, error).toBeInstanceOf(InvalidConsentTokenError);
      expect(err.message).toMatch(says);
      expect(err.message).toContain(`broker says ${error}`);
      expect(err.message, error).not.toMatch(/tampered/); // not the advice for a bad signature
    }
  });

  it('P-53: a refusal saying "signature invalid or token expired" without a code is not reported as expired', async () => {
    const err = await refusal({ reason: 'Consent token signature invalid or token expired' });
    expect(err).toBeInstanceOf(InvalidConsentTokenError);
    expect(err).not.toBeInstanceOf(ExpiredConsentTokenError);
    expect(actionErrorFor(err, 'create_order')).toBe('consent_invalid'); // the refusal receipt no longer says consent_expired
  });

  it('a refusal without a code is invalid, never read as expired from its text', async () => {
    for (const reason of ['Session has expired', 'Consent token expired', 'Session not found']) {
      const err = await refusal({ reason });
      expect(err, reason).toBeInstanceOf(InvalidConsentTokenError);
      expect(err, reason).not.toBeInstanceOf(ExpiredConsentTokenError);
    }
    expect(await refusal({ error: 'agent_revoked', reason: 'An agent in this session has been revoked or suspended' })).toBeInstanceOf(InvalidConsentTokenError);
  });

  it('other refusals (validation, rate limit) say what the broker said', async () => {
    stubBroker(400, { error: 'validation_error', message: 'action is required' });
    const err = await rejection(verifyConsentTokenOnline(await token(), { brokerUrl: 'https://broker.test', action: 'x' }));
    expect(err).toBeInstanceOf(InvalidConsentTokenError);
    expect(err.message).toContain('400 validation_error: action is required');
  });

  it('a valid token for an action it does not permit is a scope violation', async () => {
    stubBroker(200, { valid: true, permitted: false, action: 'issue_refund', reason: 'excluded', session_id: 'sess_1' });
    await expect(verifyConsentTokenOnline(await token(), { brokerUrl: 'https://broker.test', action: 'issue_refund' })).rejects.toBeInstanceOf(ScopeViolationError);
  });
});
