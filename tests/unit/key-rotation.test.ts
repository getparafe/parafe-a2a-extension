/**
 * Broker SPEC-006 (key rotation): receipts are signed with the key the
 * credential names (`kid`, `#keys-N`), the signer reads a replaced key, and
 * presentation proofs check against the initiator's current key (the one in
 * `authentication`), never a retired one still listed for old receipts.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { generateKeyPairSync, createPublicKey, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify, decodeProtectedHeader, calculateJwkThumbprint, decodeJwt, type JWK } from 'jose';
import {
  createActionReceiptSigner,
  agentKeyId,
  currentDidKey,
  verifyPresentationProof,
  createPresentationProof,
  InvalidProofError,
  type ParafeConsentClaims,
} from '../../src/index.js';

const DID = 'did:web:broker.test:agents:prf_agent_alex';
const unsigned = (claims: Record<string, unknown>) =>
  `${Buffer.from('{"alg":"ES256"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;
const key1 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const key2 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = (k: typeof key1) => k.publicKey.export({ format: 'jwk' }) as JWK;
afterEach(() => vi.unstubAllGlobals());

describe('agentKeyId()', () => {
  it("is the credential's kid, else #keys-1", () => {
    expect(agentKeyId(DID, unsigned({ kid: `${DID}#keys-3` }))).toBe(`${DID}#keys-3`);
    expect(agentKeyId(DID, unsigned({ sub: 'x' }))).toBe(`${DID}#keys-1`);
    expect(agentKeyId(DID, unsigned({ kid: 'did:web:elsewhere#keys-9' }))).toBe(`${DID}#keys-1`);
    expect(agentKeyId(DID, 'not a jwt')).toBe(`${DID}#keys-1`);
  });
});

describe('createActionReceiptSigner() after a key rotation', () => {
  it('signs with the current key and kid, read at each use', async () => {
    let current = { key: key1.privateKey, credential: unsigned({ sub: 'prf_agent_alex' }) };
    const signer = createActionReceiptSigner({
      agentId: 'prf_agent_alex', agentDid: DID, brokerUrl: 'https://broker.test', file: false,
      privateKey: () => current.key, credential: () => current.credential,
    });
    const input = { sessionId: 's', consentToken: 't', action: 'a' };
    const before = await signer.sign(input);
    expect(decodeProtectedHeader(before).kid).toBe(`${DID}#keys-1`);
    await jwtVerify(before, createPublicKey(key1.privateKey));

    current = { key: key2.privateKey, credential: unsigned({ sub: 'prf_agent_alex', kid: `${DID}#keys-2` }) };
    const after = await signer.sign(input);
    expect(decodeProtectedHeader(after).kid).toBe(`${DID}#keys-2`);
    await jwtVerify(after, createPublicKey(key2.privateKey));
  });

  it('files with the current key', async () => {
    let key = key1.privateKey;
    const proofs: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      proofs.push((init.headers as Record<string, string>)['Parafe-PoP']!);
      return new Response(JSON.stringify({ session_id: 's', seq: 1, receipt_hash: 'h', entry_hash: 'e', acknowledgment: 'a.b.c' }), { status: 201 });
    }));
    const signer = createActionReceiptSigner({ agentId: 'prf_agent_alex', agentDid: DID, brokerUrl: 'https://broker.test', privateKey: () => key, credential: 'c' });
    key = key2.privateKey;
    await signer.file('s', 'r');
    await jwtVerify(proofs[0]!, createPublicKey(key2.privateKey));
  });
});

describe('currentDidKey()', () => {
  it('is the key in authentication, wherever it is listed', () => {
    const doc = {
      verificationMethod: [{ id: `${DID}#keys-1`, publicKeyJwk: jwk(key1) }, { id: `${DID}#keys-2`, publicKeyJwk: jwk(key2) }],
      authentication: [`${DID}#keys-2`],
    };
    expect(currentDidKey(doc)).toEqual(jwk(key2));
  });
  it('a document with one key and no authentication: that key; several: none', () => {
    expect(currentDidKey({ verificationMethod: [{ publicKeyJwk: jwk(key1) }] })).toEqual(jwk(key1));
    expect(currentDidKey({ verificationMethod: [{ publicKeyJwk: jwk(key1) }, { publicKeyJwk: jwk(key2) }] })).toBeUndefined();
  });
});

describe('verifyPresentationProof() and a rotated initiator', () => {
  const broker = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  async function tokenFor(k: typeof key1): Promise<{ token: string; claims: ParafeConsentClaims }> {
    const token = await new SignJWT({ token_type: 'consent', cnf: { jkt: await calculateJwkThumbprint(jwk(k)) } })
      .setProtectedHeader({ alg: 'ES256' }).setSubject('prf_agent_alex').setAudience('did:web:broker.test:agents:prf_agent_shop')
      .setIssuedAt().setExpirationTime('5m').setJti(randomUUID()).sign(broker.privateKey);
    return { token, claims: decodeJwt(token) as unknown as ParafeConsentClaims };
  }
  const docBefore = { id: DID, verificationMethod: [{ id: `${DID}#keys-1`, publicKeyJwk: jwk(key1) }], authentication: [`${DID}#keys-1`] };
  const docAfter = {
    id: DID,
    verificationMethod: [{ id: `${DID}#keys-2`, publicKeyJwk: jwk(key2) }, { id: `${DID}#keys-1`, publicKeyJwk: jwk(key1), 'parafe:retiredAt': '2026-10-30T00:00:00Z' }],
    authentication: [`${DID}#keys-2`],
  };

  it('refuses a proof from the retired key, though the document still lists it', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(docAfter), { status: 200 })));
    const { token, claims } = await tokenFor(key1);
    const proof = await createPresentationProof(token, key1.privateKey);
    await expect(verifyPresentationProof(proof, token, claims, { brokerUrl: 'https://retired.test' })).rejects.toBeInstanceOf(InvalidProofError);
  });

  it('reads the document again when the cached key is not the one the token is bound to', async () => {
    let doc: object = docBefore;
    const fetches = vi.fn(async () => new Response(JSON.stringify(doc), { status: 200 }));
    vi.stubGlobal('fetch', fetches);
    const old = await tokenFor(key1);
    await verifyPresentationProof(await createPresentationProof(old.token, key1.privateKey), old.token, old.claims, { brokerUrl: 'https://rotating.test' });
    doc = docAfter;
    const fresh = await tokenFor(key2);
    await verifyPresentationProof(await createPresentationProof(fresh.token, key2.privateKey), fresh.token, fresh.claims, { brokerUrl: 'https://rotating.test' });
    expect(fetches).toHaveBeenCalledTimes(2);
  });
});
