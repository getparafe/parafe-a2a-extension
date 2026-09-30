import { SignJWT, decodeJwt, type KeyLike } from 'jose';

// ---------------------------------------------------------------------------
// AP2 v0.2 receipts for Parafé-protected merchants (AP2 change request A3).
// Once a merchant has accepted or rejected a Checkout Mandate it MUST return a
// Checkout Receipt (specification.md); a payment processor returns a Payment
// Receipt. They are ES256 JWTs bound to the closed mandate by `reference`. File
// them with the broker unchanged (kind ap2.checkout_receipt /
// ap2.payment_receipt): the session index checks `reference` against the
// mandates verified in the session.
// ---------------------------------------------------------------------------

/**
 * AP2's spec and its SDK compute a receipt's `reference` differently: the spec
 * hashes the final SD-JWT of the chain like `sd_hash` (with its `_sd_alg`); the
 * AP2 Python SDK hashes only the closed mandate's JWT (SHA-256). Both are given
 * until FIDO settles it.
 */
export interface Ap2References {
  /** The spec: hash of the final SD-JWT as presented (issuer JWT, disclosures, trailing `~`). */
  sdHash: string;
  /** The AP2 SDK (`get_closed_mandate_jwt`): SHA-256 of the closed mandate's JWT. */
  closedJwt: string;
}

/** Which form goes in the receipt's `reference`. Default 'closed_jwt' (what the AP2 SDK and samples check). */
export type Ap2ReferenceForm = 'closed_jwt' | 'sd_hash';

export type Ap2ReceiptKind = 'ap2.checkout_receipt' | 'ap2.payment_receipt';

const SUBTLE_HASH: Record<string, string> = { 'sha-256': 'SHA-256', 'sha-384': 'SHA-384', 'sha-512': 'SHA-512' };

function b64url(bytes: ArrayBuffer): string {
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function digest(sdAlg: string, value: string): Promise<string> {
  const alg = SUBTLE_HASH[sdAlg.toLowerCase()];
  if (!alg) throw new TypeError(`Unsupported _sd_alg "${sdAlg}"`);
  return b64url(await crypto.subtle.digest(alg, new TextEncoder().encode(value) as unknown as ArrayBuffer));
}

/**
 * Both `reference` forms for an AP2 mandate as presented (a `~~`-joined chain,
 * or one SD-JWT). Doesn't verify the mandate.
 */
export async function ap2MandateReferences(mandate: string): Promise<Ap2References> {
  if (typeof mandate !== 'string' || !mandate.endsWith('~')) {
    throw new TypeError('An AP2 mandate as presented is an SD-JWT (or ~~-joined chain) ending in "~"');
  }
  const last = mandate.split('~~').pop() as string;
  const jwt = last.split('~')[0] as string;
  const payload = decodeJwt(jwt);
  const sdAlg = typeof payload['_sd_alg'] === 'string' ? payload['_sd_alg'] : 'sha-256';
  return { sdHash: await digest(sdAlg, last), closedJwt: await digest('sha-256', jwt) };
}

export interface Ap2ReceiptInput {
  kind: 'checkout' | 'payment';
  /** The mandate the receipt answers, as presented; or pass `references`. */
  mandate?: string;
  references?: Ap2References;
  /** Default 'closed_jwt'. */
  referenceForm?: Ap2ReferenceForm;
  /** The receipt's issuer: the merchant (checkout) or payment processor (payment), e.g. its website or your agent DID. */
  iss: string;
  /** Default 'Success', or 'Error' when `error` is set. */
  status?: 'Success' | 'Error';
  /** An AP2 error code: invalid_credential, unresolved_constraint, invalid_mandate, mandates_not_supported. */
  error?: string;
  errorDescription?: string;
  /** Checkout, Success: the order. */
  orderId?: string;
  /** Payment: always. */
  paymentId?: string;
  /** Payment, Success. */
  pspConfirmationId?: string;
  networkConfirmationId?: string;
  /** JWS header kid, e.g. `<agent DID>#keys-1`. */
  kid?: string;
  iat?: number;
}

export interface Ap2Receipt {
  /** The receipt JWT (ES256). Return it to the shopping agent and file it with the broker. */
  receipt: string;
  kind: Ap2ReceiptKind;
  /** The `reference` in the receipt. */
  reference: string;
  /** Both forms, for your records. */
  references: Ap2References;
  claims: Record<string, unknown>;
}

function isP256(privateKey: KeyLike): boolean {
  const k = privateKey as unknown as { asymmetricKeyType?: string; asymmetricKeyDetails?: { namedCurve?: string }; algorithm?: { name?: string; namedCurve?: string } };
  if (k.asymmetricKeyType) return k.asymmetricKeyType === 'ec' && (k.asymmetricKeyDetails?.namedCurve ?? 'prime256v1') === 'prime256v1';
  return k.algorithm?.name === 'ECDSA' && k.algorithm.namedCurve === 'P-256';
}

/** The receipt claims, checked against AP2's checkout_receipt.json / payment_receipt.json. */
export function ap2ReceiptClaims(input: Ap2ReceiptInput, reference: string): Record<string, unknown> {
  const status = input.status ?? (input.error ? 'Error' : 'Success');
  if (input.kind !== 'checkout' && input.kind !== 'payment') throw new TypeError("kind must be 'checkout' or 'payment'");
  if (!input.iss) throw new TypeError('iss is required (the merchant or payment processor issuing the receipt)');
  const claims: Record<string, unknown> = { status, iss: input.iss, iat: input.iat ?? Math.floor(Date.now() / 1000), reference };
  if (status === 'Error') {
    if (!input.error || !input.errorDescription) throw new TypeError('An Error receipt needs error and errorDescription');
    claims['error'] = input.error;
    claims['error_description'] = input.errorDescription;
  } else if (input.error) {
    throw new TypeError('A Success receipt has no error');
  }
  if (input.kind === 'checkout') {
    if (status === 'Success') {
      if (!input.orderId) throw new TypeError('A Success checkout receipt needs orderId');
      claims['order_id'] = input.orderId;
    }
  } else {
    if (!input.paymentId) throw new TypeError('A payment receipt needs paymentId');
    claims['payment_id'] = input.paymentId;
    if (status === 'Success') {
      if (!input.pspConfirmationId || !input.networkConfirmationId) throw new TypeError('A Success payment receipt needs pspConfirmationId and networkConfirmationId');
      claims['psp_confirmation_id'] = input.pspConfirmationId;
      claims['network_confirmation_id'] = input.networkConfirmationId;
    }
  }
  return claims;
}

/**
 * Sign an AP2 Checkout or Payment Receipt (ES256: AP2's only algorithm, so the
 * key must be P-256). Issue one for a rejected mandate too (`error`, with the
 * AP2 error code from the verification).
 */
export async function signAp2Receipt(privateKey: KeyLike, input: Ap2ReceiptInput): Promise<Ap2Receipt> {
  if (!isP256(privateKey)) throw new TypeError('AP2 receipts are signed ES256: use a P-256 key');
  const references = input.references ?? (input.mandate ? await ap2MandateReferences(input.mandate) : undefined);
  if (!references) throw new TypeError('Pass the mandate the receipt answers (mandate) or its references');
  const reference = (input.referenceForm ?? 'closed_jwt') === 'sd_hash' ? references.sdHash : references.closedJwt;
  const claims = ap2ReceiptClaims(input, reference);
  const receipt = await new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT', ...(input.kid ? { kid: input.kid } : {}) })
    .sign(privateKey);
  return { receipt, kind: input.kind === 'checkout' ? 'ap2.checkout_receipt' : 'ap2.payment_receipt', reference, references, claims };
}
