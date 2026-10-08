/**
 * 2.2: action receipts. The target signs what it did or refused, bound to the
 * consent token; refusals are receipted automatically by
 * verifyMessageConsentToken with `receipts`; receipts are filed in the
 * background and travel back in `action_receipt` / `error.action_receipt`.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { generateKeyPairSync, createHash, randomUUID, createPublicKey } from 'node:crypto';
import { SignJWT, jwtVerify, calculateJwkThumbprint, decodeJwt, type JWK } from 'jose';
import {
  verifyMessageConsentToken,
  createActionReceiptSigner,
  signActionReceipt,
  actionErrorFor,
  createPresentationProof,
  withConsentToken,
  withActionReceipts,
  withParafe,
  parafeErrorData,
  extractActionReceipts,
  readParafe,
  jcs,
  ScopeViolationError,
  ExpiredConsentTokenError,
  InvalidProofError,
  InvalidConsentTokenError,
  type BrokerKeys,
} from '../../src/index.js';

const sha = (s: string) => createHash('sha256').update(s).digest('base64url');
const broker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const KEYS: BrokerKeys = { keys: [{ ...(broker.publicKey.export({ format: 'jwk' }) as JWK), kid: 'es-1', alg: 'ES256' } as BrokerKeys['keys'][number]] };
const initiator = generateKeyPairSync('ed25519');
const shop = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const SHOP_DID = 'did:web:api.parafe.ai:agents:prf_agent_shop';

async function token(extra: Record<string, unknown> = {}, exp = '5m'): Promise<string> {
  return new SignJWT({
    ver: 2, token_type: 'consent', scope: 'place-order', permissions: ['create_order'],
    exclusions: ['issue_refund'], session_id: 'sess_1',
    authorization_modality: 'attested', initiator_agent_id: 'prf_agent_alex', target_agent_id: 'prf_agent_shop',
    cnf: { jkt: await calculateJwkThumbprint(initiator.publicKey.export({ format: 'jwk' }) as JWK) }, ...extra,
  }).setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuer('parafe-trust-broker')
    .setSubject('prf_agent_alex').setAudience(SHOP_DID).setIssuedAt().setExpirationTime(exp).setJti(randomUUID())
    .sign(broker.privateKey);
}

// fetch stub: the broker's filing endpoint
const filed: { url: string; headers: Record<string, string>; body: { receipt: string; kind?: string } }[] = [];
function stubBroker(status = 201) {
  filed.length = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    filed.push({ url, headers: init.headers as Record<string, string>, body });
    const ack = { session_id: 'sess_1', seq: filed.length, receipt_hash: sha(body.receipt), entry_hash: 'eh', acknowledgment: 'a.b.c' };
    return new Response(JSON.stringify(status === 409 ? { error: 'duplicate_receipt', message: 'filed', ...ack } : ack), { status });
  }));
}
afterEach(() => vi.unstubAllGlobals());

const signer = (opts: { file?: boolean } = {}) =>
  createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: 'cred.jwt.sig', brokerUrl: 'https://broker.test', ...opts });

async function message(tok: string, withProof = true) {
  const proof = withProof ? await createPresentationProof(tok, initiator.privateKey) : undefined;
  return withConsentToken({ messageId: 'm1', role: 'ROLE_USER', parts: [] }, tok, 'sess_1', proof);
}

describe('signActionReceipt()', () => {
  it('signs with the agent key: typ, kid, iss, consent_ref, hashes; verifies with jose', async () => {
    const tok = await token();
    const r = await signActionReceipt(shop.privateKey, SHOP_DID, { sessionId: 'sess_1', consentToken: tok, action: 'create_order', details: { b: 1, a: 2 }, request: 'hi', businessRef: 'ord_1' });
    const { payload, protectedHeader } = await jwtVerify(r, createPublicKey(shop.privateKey), { typ: 'parafe-action-receipt+jwt', issuer: SHOP_DID });
    expect(protectedHeader).toMatchObject({ alg: 'ES256', kid: `${SHOP_DID}#keys-1` });
    expect(payload).toMatchObject({ ver: 1, session_id: 'sess_1', consent_ref: sha(tok), action: 'create_order', result: 'success', error: null, details_hash: sha('{"a":2,"b":1}'), request_ref: sha('hi'), business_ref: 'ord_1' });
  });

  it('jcs sorts keys', () => {
    expect(jcs({ b: [{ d: 1, c: 2 }], a: null })).toBe('{"a":null,"b":[{"c":2,"d":1}]}');
  });
});

describe('verifyMessageConsentToken() with receipts', () => {
  it('a permitted action: completeAction() signs a success receipt and files it in the background', async () => {
    stubBroker();
    const receipts = signer();
    const tok = await token();
    const { completeAction, consentToken } = await verifyMessageConsentToken(await message(tok), KEYS, {
      agentId: 'prf_agent_shop', action: 'create_order', receipts, initiatorKey: initiator.publicKey.export({ format: 'jwk' }) as JWK,
    });
    expect(consentToken).toBe(tok);
    const { receipt, filed: ack } = await completeAction({ businessRef: 'ord_9' });
    expect((await ack)?.seq).toBe(1);
    await receipts.flush();
    expect(decodeJwt(receipt)).toMatchObject({ action: 'create_order', result: 'success', business_ref: 'ord_9', consent_ref: sha(tok) });
    expect(filed[0]!.url).toBe('https://broker.test/sessions/sess_1/action-receipts');
    expect(filed[0]!.headers.Authorization).toBe('Bearer cred.jwt.sig');
    const pop = await jwtVerify(filed[0]!.headers['Parafe-PoP']!, createPublicKey(shop.privateKey), { typ: 'parafe-pop+jwt' });
    expect(pop.payload).toMatchObject({ htm: 'POST', htu: filed[0]!.url, session_id: 'sess_1' });
  });

  it('an excluded action: the thrown error carries a signed `excluded` receipt, and parafeErrorData returns it', async () => {
    stubBroker();
    const receipts = signer();
    const tok = await token();
    const err = await verifyMessageConsentToken(await message(tok), KEYS, { agentId: 'prf_agent_shop', action: 'issue_refund', receipts, initiatorKey: initiator.publicKey.export({ format: 'jwk' }) as JWK })
      .catch((e) => e);
    expect(err).toBeInstanceOf(ScopeViolationError);
    expect(decodeJwt(err.actionReceipt)).toMatchObject({ action: 'issue_refund', result: 'error', error: 'excluded', consent_ref: sha(tok) });
    await receipts.flush();
    expect(filed).toHaveLength(1);
    const reply = withParafe({ messageId: 'r1', role: 'ROLE_AGENT', parts: [] }, parafeErrorData(err));
    expect(extractActionReceipts(reply)).toEqual([err.actionReceipt]);
    expect(readParafe(reply)).toMatchObject({ error: { code: 'SCOPE_VIOLATION' }, action_receipts: [err.actionReceipt] });
  });

  it('not permitted, expired, bad proof and wrong audience map to their error codes', async () => {
    stubBroker();
    const receipts = signer({ file: false });
    const jwk = initiator.publicKey.export({ format: 'jwk' }) as JWK;
    const tok = await token();
    const notPermitted = await verifyMessageConsentToken(await message(tok), KEYS, { agentId: 'prf_agent_shop', action: 'read_menu', receipts, initiatorKey: jwk }).catch((e) => e);
    expect(decodeJwt(notPermitted.actionReceipt).error).toBe('not_permitted');
    const expired = await verifyMessageConsentToken(await message(await token({}, '-1s'), false), KEYS, { agentId: 'prf_agent_shop', action: 'create_order', receipts }).catch((e) => e);
    expect(expired).toBeInstanceOf(ExpiredConsentTokenError);
    expect(decodeJwt(expired.actionReceipt).error).toBe('consent_expired');
    const noProof = await verifyMessageConsentToken(await message(tok, false), KEYS, { agentId: 'prf_agent_shop', action: 'create_order', receipts }).catch((e) => e); // 3.0: required by default
    expect(noProof).toBeInstanceOf(InvalidProofError);
    expect(decodeJwt(noProof.actionReceipt).error).toBe('proof_invalid');
    const wrongAud = await verifyMessageConsentToken(await message(tok, false), KEYS, { agentId: 'prf_agent_other', action: 'create_order', receipts }).catch((e) => e);
    expect(decodeJwt(wrongAud.actionReceipt).error).toBe('consent_invalid');
    expect(filed).toHaveLength(0); // file: false
  });

  it('without receipts, nothing is signed; completeAction() explains', async () => {
    const { completeAction } = await verifyMessageConsentToken(await message(await token(), false), KEYS, { agentId: 'prf_agent_shop', action: 'create_order', requireProof: false });
    await expect(completeAction()).rejects.toThrow(/receipts/);
    const err = await verifyMessageConsentToken(await message(await token(), false), KEYS, { agentId: 'prf_agent_shop', action: 'issue_refund' }).catch((e) => e);
    expect(err.actionReceipt).toBeUndefined();
  });

  it('a duplicate filing returns the original acknowledgment', async () => {
    stubBroker(409);
    const ack = await signer().file('sess_1', 'x.y.z');
    expect(ack.duplicate).toBe(true);
  });

  it('a failed background filing is reported, not thrown', async () => {
    const onFileError = vi.fn();
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'session_closed', message: 'closed' }), { status: 409 })));
    const receipts = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: 'c', brokerUrl: 'https://broker.test', onFileError });
    const { filed: ack } = await receipts.record({ sessionId: 'sess_1', consentToken: await token(), action: 'create_order' });
    expect(await ack).toBeNull();
    expect(onFileError).toHaveBeenCalledOnce();
  });

  it('reads the agent DID from its DID document when not given', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ id: 'did:web:broker.test:agents:prf_agent_x' }), { status: 200 })));
    const receipts = createActionReceiptSigner({ agentId: 'prf_agent_x', privateKey: shop.privateKey, credential: 'c', brokerUrl: 'https://broker.test', file: false });
    const r = await receipts.sign({ sessionId: 's', consentToken: 't', action: 'a' });
    expect(decodeJwt(r).iss).toBe('did:web:broker.test:agents:prf_agent_x');
  });
});

describe('createActionReceiptSigner(): credential and broker', () => {
  it('credential as a function is read at each filing, so a renewed credential is used', async () => {
    stubBroker();
    let current = 'cred.old';
    const receipts = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: async () => current, brokerUrl: 'https://broker.test' });
    await receipts.file('sess_1', 'x.y.z');
    current = 'cred.renewed'; // the agent renewed; the broker revoked cred.old
    await (await receipts.record({ sessionId: 'sess_1', consentToken: await token(), action: 'create_order' })).filed;
    expect(filed.map((f) => f.headers.Authorization)).toEqual(['Bearer cred.old', 'Bearer cred.renewed']);
  });

  it('a credential function that returns nothing fails the filing (reported, not thrown); a credential that is neither is refused', async () => {
    stubBroker();
    const onFileError = vi.fn();
    const receipts = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: () => '', brokerUrl: 'https://broker.test', onFileError });
    expect(await (await receipts.record({ sessionId: 'sess_1', consentToken: await token(), action: 'create_order' })).filed).toBeNull();
    expect(onFileError).toHaveBeenCalledOnce();
    expect(filed).toHaveLength(0);
    expect(() => createActionReceiptSigner({ agentId: 'a', privateKey: shop.privateKey, credential: undefined as unknown as string })).toThrow(TypeError);
  });

  it('a failed filing names the broker, so filing with the wrong one shows', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_credential', message: 'unknown' }), { status: 401 })));
    const receipts = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: 'c' });
    expect(receipts.brokerUrl).toBe('https://api.parafe.ai');
    await expect(receipts.file('sess_1', 'x.y.z')).rejects.toThrow('with https://api.parafe.ai failed (401 invalid_credential)');
  });

  it('verifyMessageConsentToken warns (once) when the signer files with another broker than the keys came from', async () => {
    const { createBrokerKeyCache } = await import('../../src/index.js');
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(KEYS), { status: 200 })));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const keys = createBrokerKeyCache('https://staging.test');
      const jwk = initiator.publicKey.export({ format: 'jwk' }) as JWK;
      const production = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: 'c', file: false });
      for (let i = 0; i < 2; i++) {
        await verifyMessageConsentToken(await message(await token()), keys, { agentId: 'prf_agent_shop', action: 'create_order', receipts: production, initiatorKey: jwk });
      }
      expect(warn).toHaveBeenCalledOnce();
      expect(String(warn.mock.calls[0]![0])).toMatch(/filed with https:\/\/api\.parafe\.ai, but .* against https:\/\/staging\.test/);
      const staging = createActionReceiptSigner({ agentId: 'prf_agent_shop', agentDid: SHOP_DID, privateKey: shop.privateKey, credential: 'c', file: false, brokerUrl: 'https://staging.test/' });
      await verifyMessageConsentToken(await message(await token()), keys, { agentId: 'prf_agent_shop', action: 'create_order', receipts: staging, initiatorKey: jwk });
      expect(warn).toHaveBeenCalledOnce();
    } finally {
      warn.mockRestore();
    }
  });
});

describe('action_receipts message data', () => {
  it('alone, or beside a member; withParafe keeps receipts attached earlier; duplicates collapse', async () => {
    const r1 = await signActionReceipt(shop.privateKey, SHOP_DID, { sessionId: 'sess_1', consentToken: 't', action: 'read_menu' });
    const r2 = await signActionReceipt(shop.privateKey, SHOP_DID, { sessionId: 'sess_1', consentToken: 't', action: 'create_order' });
    const alone = withActionReceipts({ messageId: 'r', role: 'ROLE_AGENT', parts: [] }, [r1, r2, r1]);
    expect(readParafe(alone)).toEqual({ action_receipts: [r1, r2] });
    const withError = withParafe(alone, { error: { code: 'SCOPE_VIOLATION', message: 'no refunds' } });
    expect(readParafe(withError)).toEqual({ error: { code: 'SCOPE_VIOLATION', message: 'no refunds' }, action_receipts: [r1, r2] });
    const handshake = withActionReceipts(withParafe({ parts: [] }, { handshake_complete: { handshake_id: 'hs', status: 'authenticated', session_id: 's', consent_token: 'a.b.c' } }), [r1]);
    expect(extractActionReceipts(handshake)).toEqual([r1]);
    expect(readParafe(handshake)).toHaveProperty('handshake_complete');
    expect(extractActionReceipts(withParafe({ parts: [] }, { error: { code: 'SCOPE_VIOLATION', message: 'x' } }))).toEqual([]);
  });

  it('refuses malformed receipts and data with neither a member nor receipts', () => {
    expect(() => readParafe(withParafe({ parts: [] }, { action_receipts: ['nope'] }))).toThrow();
    expect(() => readParafe(withParafe({ parts: [] }, { action_receipts: [] }))).toThrow();
  });

  it('ignores members it does not know: beside a member, or alone (reads as no Parafé data)', () => {
    const uri = 'https://parafe.ai/extensions/a2a/v2';
    expect(readParafe({ metadata: { [uri]: { some_future_member: { x: 1 } } } })).toBeNull();
    expect(readParafe({ metadata: { [uri]: { error: { code: 'SCOPE_VIOLATION', message: 'm' }, some_future_member: 1 } } }))
      .toEqual({ error: { code: 'SCOPE_VIOLATION', message: 'm' } });
    expect(() => readParafe({ metadata: { [uri]: {} } })).toThrow(/expected one of/);
  });

  it('actionErrorFor maps each error', () => {
    expect(actionErrorFor(new ScopeViolationError('x', []), 'x', ['x'])).toBe('excluded');
    expect(actionErrorFor(new ScopeViolationError('x', []), 'x', [])).toBe('not_permitted');
    expect(actionErrorFor(new InvalidConsentTokenError(), 'x')).toBe('consent_invalid');
  });
});
