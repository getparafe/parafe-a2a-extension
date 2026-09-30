import { SignJWT, decodeJwt, type KeyLike } from 'jose';
import { dataPartValue } from './message.js';

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

// ---------------------------------------------------------------------------
// AP2 artifacts in A2A messages (A4). PROVISIONAL: AP2 v0.2 has no normative
// AP2-over-A2A binding (it deleted its A2A extension spec); these follow the
// AP2 samples (code/samples/python/src/common/constants.py), which put each
// artifact in its own data part under a fixed key and declare the extension
// `https://github.com/google-agentic-commerce/ap2/v1` on A2A 0.3. They may
// change when AP2 (now at FIDO) publishes a binding. Parafé data stays in
// message metadata, so the two never collide.
// ---------------------------------------------------------------------------

/** The extension URI the AP2 samples declare (provisional). */
export const AP2_EXTENSION_URI = 'https://github.com/google-agentic-commerce/ap2/v1';
/** Data-part keys the AP2 samples use. */
export const AP2_CHECKOUT_MANDATE_KEY = 'ap2.mandates.CheckoutMandateSdJwt';
export const AP2_PAYMENT_MANDATE_KEY = 'ap2.mandates.PaymentMandateSdJwt';
export const AP2_PAYMENT_RECEIPT_KEY = 'ap2.PaymentReceipt';
/** Not in the AP2 samples (they return checkout receipts over MCP); named after ap2.PaymentReceipt. */
export const AP2_CHECKOUT_RECEIPT_KEY = 'ap2.CheckoutReceipt';

const AP2_KEYS = {
  checkoutMandate: AP2_CHECKOUT_MANDATE_KEY,
  paymentMandate: AP2_PAYMENT_MANDATE_KEY,
  checkoutReceipt: AP2_CHECKOUT_RECEIPT_KEY,
  paymentReceipt: AP2_PAYMENT_RECEIPT_KEY,
} as const;

/** AP2 artifacts carried in an A2A message. Mandates are SD-JWT strings; receipts are JWTs (the AP2 samples also send unsigned receipt objects). */
export interface Ap2MessageData {
  checkoutMandate?: string;
  paymentMandate?: string;
  checkoutReceipt?: string | Record<string, unknown>;
  paymentReceipt?: string | Record<string, unknown>;
}

/** The DataPart shape to write: @a2a-js/sdk objects, A2A 1.0 JSON, or A2A 0.3 JSON. */
export type A2APartShape = 'a2a-js' | '1.0' | '0.3';

interface MessageWithParts {
  parts?: readonly unknown[] | null | undefined;
  extensions?: readonly string[] | null | undefined;
}

function partShapeOf(parts: readonly unknown[]): A2APartShape {
  for (const p of parts) {
    if (p && typeof p === 'object') {
      if ('content' in p) return 'a2a-js';
      if ('kind' in p) return '0.3';
    }
  }
  return '1.0';
}

function dataPart(shape: A2APartShape, data: Record<string, unknown>): unknown {
  if (shape === 'a2a-js') return { content: { $case: 'data', value: data }, metadata: undefined, filename: '', mediaType: 'application/json' };
  if (shape === '0.3') return { kind: 'data', data };
  return { data, mediaType: 'application/json' };
}

/**
 * Returns a copy of `message` with each AP2 artifact in its own data part (the
 * AP2 samples' keys) and the AP2 extension URI in `extensions`. Parafé data in
 * metadata is untouched. The part shape follows the message's existing parts
 * (override with `shape`). PROVISIONAL (see AP2_EXTENSION_URI).
 */
export function withAp2<M extends MessageWithParts>(message: M, data: Ap2MessageData, options: { shape?: A2APartShape } = {}): M {
  const parts = [...(message.parts ?? [])];
  const shape = options.shape ?? partShapeOf(parts);
  for (const [field, key] of Object.entries(AP2_KEYS) as [keyof Ap2MessageData, string][]) {
    const value = data[field];
    if (value === undefined) continue;
    if (field.endsWith('Mandate') && typeof value !== 'string') throw new TypeError(`${field} must be the mandate as presented (an SD-JWT string)`);
    parts.push(dataPart(shape, { [key]: value }));
  }
  const extensions = [...(message.extensions ?? [])];
  if (!extensions.includes(AP2_EXTENSION_URI)) extensions.push(AP2_EXTENSION_URI);
  return { ...message, parts, extensions };
}

/** The AP2 artifacts in an A2A message (data parts, any shape), or null when there are none. */
export function readAp2(message: MessageWithParts): Ap2MessageData | null {
  const out: Ap2MessageData = {};
  for (const part of message.parts ?? []) {
    const data = dataPartValue(part);
    if (!data) continue;
    for (const [field, key] of Object.entries(AP2_KEYS) as [keyof Ap2MessageData, string][]) {
      if (!(key in data) || out[field] !== undefined) continue;
      const value = data[key];
      if (field.endsWith('Mandate') ? typeof value === 'string' : typeof value === 'string' || (!!value && typeof value === 'object' && !Array.isArray(value))) {
        (out as Record<string, unknown>)[field] = value;
      }
    }
  }
  return Object.keys(out).length ? out : null;
}

/**
 * The AP2 agent-card extension entry, as the AP2 samples declare it. List it
 * beside Parafé's (buildAgentCardExtension) in `capabilities.extensions`.
 * PROVISIONAL (see AP2_EXTENSION_URI).
 */
export function buildAp2AgentCardExtension(options: { required?: boolean; description?: string } = {}): { uri: string; description: string; required: boolean } {
  return { uri: AP2_EXTENSION_URI, description: options.description ?? 'Supports the Agent Payments Protocol.', required: options.required ?? false };
}
