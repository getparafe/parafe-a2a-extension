import { SignJWT, decodeJwt, type KeyLike } from 'jose';
import { DEFAULT_BROKER_URL } from './constants.js';
import { signAp2Receipt, type Ap2Receipt, type Ap2ReceiptInput } from './ap2.js';
import {
  ExpiredConsentTokenError,
  InvalidProofError,
  ScopeViolationError,
} from './errors.js';

// ---------------------------------------------------------------------------
// Action receipts (2.2; Parafé broker AP2 Phase 2). The agent that performs or
// refuses an action signs what happened with its own key, bound to the consent
// token it was asked under. Either participant files the receipt with the
// broker, which indexes it for the session; the session receipt lists every
// filed receipt. Refusals get a receipt too.
// ---------------------------------------------------------------------------

export const ACTION_RECEIPT_TYP = 'parafe-action-receipt+jwt';
const POP_TYP = 'parafe-pop+jwt';

/** Why an action was refused or failed. */
export type ActionErrorCode =
  | 'not_permitted'
  | 'excluded'
  | 'consent_invalid'
  | 'consent_expired'
  | 'proof_invalid'
  | 'failed';

export type ActionReceiptKind = 'parafe.action_receipt' | 'ap2.checkout_receipt' | 'ap2.payment_receipt';

export interface ActionReceiptInput {
  sessionId: string;
  /** The consent token the action was requested under. */
  consentToken: string;
  action: string;
  /** Default 'success'. */
  result?: 'success' | 'error';
  error?: ActionErrorCode;
  errorDescription?: string;
  /** The request message (string or bytes): the receipt carries its SHA-256. */
  request?: string | Uint8Array;
  requestRef?: string;
  /** What was done: only its hash (JCS, SHA-256) goes on the receipt. */
  details?: unknown;
  detailsHash?: string;
  /** Your reference for the outcome (e.g. an order ID). The broker sees it. */
  businessRef?: string;
  /** AP2 closed-mandate hash, when AP2-authorized. */
  mandateRef?: string;
}

/** The broker's acknowledgment of a filed receipt. */
export interface ActionReceiptAck {
  session_id: string;
  seq: number;
  receipt_hash: string;
  entry_hash: string;
  /** JWS signed by the broker (typ parafe-index-ack+jwt). */
  acknowledgment: string;
  /** True when it was already filed (by you or the other agent). */
  duplicate: boolean;
  /**
   * A3, for receipts that name an AP2 mandate (null otherwise): whether it
   * matched a mandate this receipt's issuer (or the handshake) verified in the
   * session, that closed-mandate hash, who verified it, and whose trust list
   * it passed (`scope_policy`, `broker`, `request`).
   */
  reference_verified: boolean | null;
  mandate_ref: string | null;
  mandate_verified_by: string | null;
  mandate_issuer_source: string | null;
}

export interface RecordedActionReceipt {
  /** The receipt (a JWS). Return it to the other agent: withActionReceipts(). */
  receipt: string;
  /** Filing with the broker, started in the background (null when `file: false`). */
  filed: Promise<ActionReceiptAck | null>;
}

export interface ActionReceiptSignerOptions {
  /** Your Parafé agent ID. */
  agentId: string;
  /** Your agent's private key (a Node KeyObject or WebCrypto CryptoKey; Ed25519 or P-256). */
  privateKey: KeyLike;
  /** Your agent's credential (to file receipts with the broker). */
  credential: string;
  /** Default DEFAULT_BROKER_URL. */
  brokerUrl?: string;
  /** Your agent's DID. Default: read once from your DID document at the broker. */
  agentDid?: string;
  /** File every receipt with the broker in the background. Default true. */
  file?: boolean;
  /** Called when a background filing fails (default: console.warn). */
  onFileError?: (err: unknown, receipt: string) => void;
}

export interface ActionReceiptSigner {
  readonly agentId: string;
  /** Sign an action receipt. */
  sign(input: ActionReceiptInput): Promise<string>;
  /** File a receipt (yours, the other agent's, or an AP2 receipt with its kind) and wait for the acknowledgment. */
  file(sessionId: string, receipt: string, kind?: ActionReceiptKind): Promise<ActionReceiptAck>;
  /** Sign, and file in the background unless `file: false`. */
  record(input: ActionReceiptInput): Promise<RecordedActionReceipt>;
  /**
   * Sign (and file) the error receipt for a failed consent check: `err` from
   * verifyMessageConsentToken. Null when there was no consent token to bind it to.
   */
  refuse(consent: { token: string; session_id: string } | null, action: string, err: unknown): Promise<RecordedActionReceipt | null>;
  /**
   * AP2 (A3): sign an AP2 Checkout or Payment Receipt with your agent key (it
   * must be P-256) and file it in the session's index in the background.
   * `iss` defaults to your agent DID, `kid` to its key.
   */
  ap2Receipt(sessionId: string, input: Omit<Ap2ReceiptInput, 'iss' | 'kid'> & { iss?: string; kid?: string }): Promise<Ap2Receipt & { filed: Promise<ActionReceiptAck | null> }>;
  /** Wait for every background filing. Call before closing the session. */
  flush(): Promise<void>;
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256b64u(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return b64url(await crypto.subtle.digest('SHA-256', bytes as unknown as ArrayBuffer));
}

/** RFC 8785 (JCS) canonical JSON: keys sorted by UTF-16 code units. */
export function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('JCS: non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? 'null' : jcs(v))).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(obj[k])}`).join(',')}}`;
}

function algOf(privateKey: KeyLike): 'ES256' | 'EdDSA' {
  const k = privateKey as unknown as { asymmetricKeyType?: string; algorithm?: { name?: string } };
  return k.asymmetricKeyType === 'ec' || k.algorithm?.name === 'ECDSA' ? 'ES256' : 'EdDSA';
}

/**
 * Sign an action receipt with the agent's key: typ parafe-action-receipt+jwt,
 * kid `<agent DID>#keys-1`, iss the agent DID.
 */
export async function signActionReceipt(privateKey: KeyLike, agentDid: string, input: ActionReceiptInput): Promise<string> {
  const result = input.result ?? 'success';
  if (result === 'error' && !input.error) throw new TypeError("an 'error' receipt needs error (e.g. 'excluded')");
  if (result === 'success' && input.error) throw new TypeError("a 'success' receipt has no error");
  const requestRef = input.requestRef ?? (input.request !== undefined ? await sha256b64u(input.request) : null);
  const detailsHash = input.detailsHash ?? (input.details !== undefined ? await sha256b64u(jcs(input.details)) : null);
  return new SignJWT({
    ver: 1,
    session_id: input.sessionId,
    consent_ref: await sha256b64u(input.consentToken),
    action: input.action,
    result,
    error: result === 'error' ? input.error : null,
    error_description: input.errorDescription ?? null,
    request_ref: requestRef,
    details_hash: detailsHash,
    business_ref: input.businessRef ?? null,
    mandate_ref: input.mandateRef ?? null,
  })
    .setProtectedHeader({ alg: algOf(privateKey), kid: `${agentDid}#keys-1`, typ: ACTION_RECEIPT_TYP })
    .setIssuer(agentDid)
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

/**
 * The action receipt error code for a failed consent check (an error from
 * verifyMessageConsentToken / verifyConsentTokenOffline). `exclusions` (the
 * token's, when known) tells an excluded action from one merely not permitted.
 */
export function actionErrorFor(err: unknown, action: string, exclusions: string[] = []): ActionErrorCode {
  if (err instanceof ScopeViolationError) return exclusions.includes(action) ? 'excluded' : 'not_permitted';
  if (err instanceof ExpiredConsentTokenError) return 'consent_expired';
  if (err instanceof InvalidProofError) return 'proof_invalid';
  return 'consent_invalid';
}

/**
 * File a receipt with the broker (POST /sessions/:id/action-receipts), as your
 * agent: its credential plus a proof of possession bound to the session. A
 * receipt already filed returns its original acknowledgment (`duplicate: true`).
 */
export async function fileActionReceipt(
  receipt: string,
  opts: { sessionId: string; credential: string; privateKey: KeyLike; brokerUrl?: string; kind?: ActionReceiptKind }
): Promise<ActionReceiptAck> {
  const brokerUrl = (opts.brokerUrl ?? DEFAULT_BROKER_URL).replace(/\/$/, '');
  const url = `${brokerUrl}/sessions/${encodeURIComponent(opts.sessionId)}/action-receipts`;
  const proof = await new SignJWT({ htm: 'POST', htu: url, session_id: opts.sessionId, jti: crypto.randomUUID() })
    .setProtectedHeader({ alg: algOf(opts.privateKey), typ: POP_TYP })
    .setIssuedAt()
    .sign(opts.privateKey);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${opts.credential}`, 'Parafe-PoP': proof },
    body: JSON.stringify({ receipt, ...(opts.kind ? { kind: opts.kind } : {}) }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  const claims = (body['claims'] && typeof body['claims'] === 'object' ? body['claims'] : {}) as Record<string, unknown>;
  const ack = (duplicate: boolean): ActionReceiptAck => ({
    session_id: body['session_id'] as string,
    seq: body['seq'] as number,
    receipt_hash: body['receipt_hash'] as string,
    entry_hash: body['entry_hash'] as string,
    acknowledgment: body['acknowledgment'] as string,
    duplicate,
    reference_verified: typeof claims['reference_verified'] === 'boolean' ? claims['reference_verified'] : null,
    mandate_ref: typeof claims['mandate_ref'] === 'string' ? claims['mandate_ref'] : null,
    mandate_verified_by: typeof claims['mandate_verified_by'] === 'string' ? claims['mandate_verified_by'] : null,
    mandate_issuer_source: typeof claims['mandate_issuer_source'] === 'string' ? claims['mandate_issuer_source'] : null,
  });
  if (res.status === 201) return ack(false);
  if (res.status === 409 && body['error'] === 'duplicate_receipt' && typeof body['acknowledgment'] === 'string') return ack(true);
  throw new Error(`Filing the action receipt failed (${res.status} ${String(body['error'] ?? '')}): ${String(body['message'] ?? '')}`);
}

/** Agent DIDs read from DID documents, by broker and agent ID. */
const didCache = new Map<string, string>();
async function resolveAgentDid(brokerUrl: string, agentId: string): Promise<string> {
  const key = `${brokerUrl}|${agentId}`;
  const cached = didCache.get(key);
  if (cached) return cached;
  const res = await fetch(`${brokerUrl}/agents/${encodeURIComponent(agentId)}/did.json`);
  if (!res.ok) throw new Error(`Could not read this agent's DID document (${res.status})`);
  const doc = (await res.json()) as { id?: string };
  if (typeof doc.id !== 'string') throw new Error("This agent's DID document has no id");
  didCache.set(key, doc.id);
  return doc.id;
}

/**
 * Action receipts for your agent: sign what it did or refused, and file each
 * receipt with the broker in the background. Pass it to verifyMessageConsentToken
 * (`receipts`) to receipt refusals automatically; call `flush()` before closing
 * the session.
 *
 * @example
 * const receipts = createActionReceiptSigner({ agentId, privateKey, credential });
 * const { completeAction } = await verifyMessageConsentToken(msg, keys, { agentId, action: 'create_order', receipts });
 * const order = await createOrder(...);
 * const { receipt } = await completeAction({ businessRef: order.id });
 * reply = withActionReceipts(reply, [receipt]);
 */
export function createActionReceiptSigner(options: ActionReceiptSignerOptions): ActionReceiptSigner {
  const brokerUrl = (options.brokerUrl ?? DEFAULT_BROKER_URL).replace(/\/$/, '');
  const fileByDefault = options.file ?? true;
  const pending = new Set<Promise<unknown>>();
  const onFileError = options.onFileError ?? ((err: unknown) => {
    console.warn(`[parafe] filing an action receipt failed: ${err instanceof Error ? err.message : String(err)}`);
  });
  const did = async () => options.agentDid ?? resolveAgentDid(brokerUrl, options.agentId);

  const file = (sessionId: string, receipt: string, kind?: ActionReceiptKind) =>
    fileActionReceipt(receipt, { sessionId, credential: options.credential, privateKey: options.privateKey, brokerUrl, ...(kind ? { kind } : {}) });

  const inBackground = (sessionId: string, receipt: string, kind?: ActionReceiptKind): Promise<ActionReceiptAck | null> => {
    const filed: Promise<ActionReceiptAck | null> = file(sessionId, receipt, kind).catch((err) => {
      onFileError(err, receipt);
      return null;
    });
    pending.add(filed);
    void filed.finally(() => pending.delete(filed));
    return filed;
  };

  const record = async (input: ActionReceiptInput): Promise<RecordedActionReceipt> => {
    const receipt = await signActionReceipt(options.privateKey, await did(), input);
    if (!fileByDefault) return { receipt, filed: Promise.resolve(null) };
    return { receipt, filed: inBackground(input.sessionId, receipt) };
  };

  return {
    agentId: options.agentId,
    sign: async (input) => signActionReceipt(options.privateKey, await did(), input),
    file,
    record,
    async refuse(consent, action, err) {
      if (!consent) return null;
      let exclusions: string[] = [];
      try {
        const c = decodeJwt(consent.token);
        const ex = c['exclusions'] ?? c['excluded'];
        if (Array.isArray(ex)) exclusions = ex.filter((x): x is string => typeof x === 'string');
      } catch {
        // not a readable token: consent_invalid
      }
      const error = actionErrorFor(err, action, exclusions);
      return record({
        sessionId: consent.session_id,
        consentToken: consent.token,
        action,
        result: 'error',
        error,
        errorDescription: err instanceof Error ? err.message.slice(0, 500) : String(err).slice(0, 500),
      });
    },
    async ap2Receipt(sessionId, input) {
      const agentDid = await did();
      const signed = await signAp2Receipt(options.privateKey, { ...input, iss: input.iss ?? agentDid, kid: input.kid ?? `${agentDid}#keys-1` });
      const filed = fileByDefault ? inBackground(sessionId, signed.receipt, signed.kind) : Promise.resolve(null);
      return { ...signed, filed };
    },
    async flush() {
      await Promise.allSettled([...pending]);
    },
  };
}
