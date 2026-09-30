/**
 * AP2 change request A3: AP2 Checkout and Payment Receipts for Parafé-protected
 * merchants. Mandates are AP2 Python SDK vectors (tests/fixtures/ap2-sdk-vectors.json).
 *
 * With AP2_SDK_PYTHONPATH (the AP2 repo's code/sdk/python) and AP2_PYTHON (a
 * Python with its dependencies), the AP2 SDK's ReceiptClient.verify_receipt
 * also checks each receipt (signature, schema, reference in store).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { jwtVerify, importJWK, type JWK } from 'jose';
import { ap2MandateReferences, signAp2Receipt, createActionReceiptSigner } from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2-sdk-vectors.json', import.meta.url), 'utf8'));
const sha = (s: string) => createHash('sha256').update(s, 'ascii').digest('base64url');
const merchantJwk = fx.keys.merchant as JWK;
const merchantKey = createPrivateKey({ key: merchantJwk as never, format: 'jwk' });
const pub = (k: JWK): JWK => { const { d: _d, ...p } = k; return p; };
const checkoutVector = fx.vectors.find((v: { id: string }) => v.id === 'hnp-checkout');
const paymentVector = fx.vectors.find((v: { id: string }) => v.id === 'hnp-payment');

describe('ap2MandateReferences', () => {
  it("closedJwt equals the AP2 SDK's reference on every vector; sdHash is the final SD-JWT's hash", async () => {
    for (const v of fx.vectors) {
      const refs = await ap2MandateReferences(v.chain);
      expect(refs.closedJwt).toBe(v.sdk_reference);
      const last = (v.chain as string).split('~~').pop() as string;
      expect(refs.sdHash).toBe(sha(last));
    }
  });
  it('refuses something that is not a presented SD-JWT', async () => {
    await expect(ap2MandateReferences('a.b.c')).rejects.toThrow(/ending in "~"/);
  });
});

describe('signAp2Receipt', () => {
  it('a Success checkout receipt: ES256, AP2 schema fields, reference as the AP2 SDK computes it', async () => {
    const r = await signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'https://demo-merchant.example', orderId: 'ord_1', kid: 'merchant-key-1' });
    expect(r.kind).toBe('ap2.checkout_receipt');
    expect(r.reference).toBe(checkoutVector.sdk_reference);
    const { payload, protectedHeader } = await jwtVerify(r.receipt, await importJWK(pub(merchantJwk), 'ES256'));
    expect(protectedHeader).toMatchObject({ alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' });
    expect(payload).toEqual({ status: 'Success', iss: 'https://demo-merchant.example', iat: expect.any(Number), reference: checkoutVector.sdk_reference, order_id: 'ord_1' });
  });

  it('rejections get a receipt too: Error with the AP2 code; the spec form of reference on request', async () => {
    const r = await signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'm', error: 'invalid_mandate', errorDescription: 'checkout.line_items: not filled', referenceForm: 'sd_hash' });
    expect(r.claims).toMatchObject({ status: 'Error', error: 'invalid_mandate', error_description: 'checkout.line_items: not filled', reference: r.references.sdHash });
    expect(r.claims).not.toHaveProperty('order_id');
  });

  it('payment receipts need payment_id; Success also the confirmations', async () => {
    const ok = await signAp2Receipt(merchantKey, { kind: 'payment', mandate: paymentVector.chain, iss: 'psp.example', paymentId: 'pay_1', pspConfirmationId: 'psp_1', networkConfirmationId: 'net_1' });
    expect(ok.claims).toMatchObject({ status: 'Success', payment_id: 'pay_1', psp_confirmation_id: 'psp_1', network_confirmation_id: 'net_1', reference: paymentVector.sdk_reference });
    await expect(signAp2Receipt(merchantKey, { kind: 'payment', mandate: paymentVector.chain, iss: 'psp.example', paymentId: 'pay_1' })).rejects.toThrow(/ConfirmationId/);
    const err = await signAp2Receipt(merchantKey, { kind: 'payment', mandate: paymentVector.chain, iss: 'psp.example', paymentId: 'pay_2', error: 'invalid_credential', errorDescription: 'untrusted issuer' });
    expect(err.claims).toMatchObject({ status: 'Error', payment_id: 'pay_2' });
  });

  it('refuses a non-P-256 key and incomplete receipts', async () => {
    const ed = generateKeyPairSync('ed25519').privateKey;
    await expect(signAp2Receipt(ed, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'm', orderId: 'o' })).rejects.toThrow(/P-256/);
    await expect(signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'm' })).rejects.toThrow(/orderId/);
    await expect(signAp2Receipt(merchantKey, { kind: 'checkout', iss: 'm', orderId: 'o' })).rejects.toThrow(/mandate/);
    await expect(signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'm', status: 'Error', error: 'invalid_mandate' })).rejects.toThrow(/errorDescription/);
  });
});

describe('the signer files AP2 receipts with their kind', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('iss and kid default to the agent DID; filed in the background as ap2.checkout_receipt', async () => {
    const calls: { url: string; body: Record<string, unknown> }[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push({ url, body: JSON.parse(String(init?.body)) });
      return new Response(JSON.stringify({ session_id: 's1', seq: 1, receipt_hash: 'h', entry_hash: 'e', acknowledgment: 'ack' }), { status: 201 });
    }));
    const signer = createActionReceiptSigner({ agentId: 'prf_agent_shop', privateKey: merchantKey, credential: 'cred', brokerUrl: 'https://broker.test', agentDid: 'did:web:broker.test:agents:prf_agent_shop' });
    const r = await signer.ap2Receipt('s1', { kind: 'checkout', mandate: checkoutVector.chain, orderId: 'ord_9' });
    expect(r.claims.iss).toBe('did:web:broker.test:agents:prf_agent_shop');
    expect(await r.filed).toMatchObject({ seq: 1, duplicate: false });
    expect(calls[0]).toMatchObject({ url: 'https://broker.test/sessions/s1/action-receipts', body: { receipt: r.receipt, kind: 'ap2.checkout_receipt' } });
  });
});

const PY = process.env['AP2_PYTHON'];
const PYPATH = process.env['AP2_SDK_PYTHONPATH'];
describe.skipIf(!PY || !PYPATH)("the AP2 Python SDK's ReceiptClient.verify_receipt accepts our receipts", () => {
  it('checkout and payment, Success and Error', async () => {
    const receipts = [
      [await signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'https://demo-merchant.example', orderId: 'ord_1' }), false],
      [await signAp2Receipt(merchantKey, { kind: 'checkout', mandate: checkoutVector.chain, iss: 'https://demo-merchant.example', error: 'invalid_mandate', errorDescription: 'no' }), false],
      [await signAp2Receipt(merchantKey, { kind: 'payment', mandate: paymentVector.chain, iss: 'psp.example', paymentId: 'p1', pspConfirmationId: 'a', networkConfirmationId: 'b' }), true],
      [await signAp2Receipt(merchantKey, { kind: 'payment', mandate: paymentVector.chain, iss: 'psp.example', paymentId: 'p2', error: 'invalid_credential', errorDescription: 'no' }), true],
    ] as const;
    const script = `
import json, sys
from jwcrypto.jwk import JWK
from ap2.sdk.receipt_wrapper import ReceiptClient
data = json.load(sys.stdin)
key = JWK(**data['jwk'])
out = []
for r in data['receipts']:
    out.append(ReceiptClient().verify_receipt(r['jwt'], key, has_reference_in_store_cb=lambda ref, want=r['reference']: ref == want, is_payment_receipt=r['payment']))
print(json.dumps(out))
`;
    const input = JSON.stringify({ jwk: pub(merchantJwk), receipts: receipts.map(([r, payment]) => ({ jwt: r.receipt, reference: r.references.closedJwt, payment })) });
    const res = spawnSync(PY as string, ['-c', script], { input, env: { ...process.env, PYTHONPATH: PYPATH as string }, encoding: 'utf8' });
    expect(res.stderr).not.toMatch(/Traceback/);
    expect(JSON.parse(res.stdout)).toEqual([{ verified: true }, { verified: true }, { verified: true }, { verified: true }]);
  });
});
