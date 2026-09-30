/**
 * Interop (A4, provisional): AP2 artifacts beside Parafé data in the same A2A
 * message, through a real @a2a-js/sdk server, from the official A2A 1.0 client
 * and as raw A2A 1.0 and 0.3 JSON-RPC. Neither payload may be dropped or
 * reshaped. The mandate is an AP2 Python SDK vector.
 */
import { randomUUID, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import { A2A_PROTOCOL_VERSION, Role, type AgentCard, type Message } from '@a2a-js/sdk';
import { duplicateInterfacesForLegacy } from '@a2a-js/sdk/compat/v0_3';
import { AgentEvent, DefaultRequestHandler, InMemoryTaskStore, type AgentExecutor, type ExecutionEventBus, type RequestContext } from '@a2a-js/sdk/server';
import { agentCardHandler, jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';
import { ClientFactory, ServiceParameters, withA2AExtensions } from '@a2a-js/sdk/client';
import {
  PARAFE_EXTENSION_URI,
  AP2_EXTENSION_URI,
  AP2_CHECKOUT_MANDATE_KEY,
  activationHeaders,
  buildAgentCardExtension,
  buildAp2AgentCardExtension,
  parseAgentCardExtension,
  readAp2,
  extractConsentToken,
  verifyMessageConsentToken,
  withConsentToken,
  withAp2,
  type ScopeRequirement,
} from '../../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../fixtures/ap2-sdk-vectors.json', import.meta.url), 'utf8'));
const MANDATE: string = fx.vectors.find((v: { id: string }) => v.id === 'hnp-checkout').chain;
const sha = (s: string) => createHash('sha256').update(s).digest('base64url');
const AGENT_ID = 'prf_agent_shop';
const SCOPES: Record<string, ScopeRequirement> = { checkout: { permissions: ['create_order'], minimum_authorization_modality: 'delegated' } };
const RECEIPT = 'eyJhbGciOiJFUzI1NiJ9.eyJzdGF0dXMiOiJTdWNjZXNzIn0.c2ln';

let brokerKey: string;
let sign: () => Promise<string>;
let server: Server;
let base: string;

/** Reads both payloads, verifies the consent token, answers with what it saw and an AP2 Checkout Receipt. */
class ShopExecutor implements AgentExecutor {
  async execute(ctx: RequestContext, bus: ExecutionEventBus): Promise<void> {
    const ap2 = readAp2(ctx.userMessage);
    let text: string;
    try {
      const { sessionId } = await verifyMessageConsentToken(ctx.userMessage, brokerKey, { agentId: AGENT_ID, action: 'create_order', scopeRequirements: SCOPES });
      text = `consent ${sessionId}; mandate ${ap2?.checkoutMandate ? sha(ap2.checkoutMandate) : 'none'}`;
    } catch (err) {
      text = `refused ${(err as Error).message}`;
    }
    ctx.context.addActivatedExtension(PARAFE_EXTENSION_URI);
    const reply = withAp2({
      messageId: randomUUID(), contextId: ctx.contextId, taskId: '', role: Role.ROLE_AGENT,
      parts: [{ content: { $case: 'text' as const, value: text }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
      metadata: undefined, extensions: [], referenceTaskIds: [],
    } as Message, { checkoutReceipt: RECEIPT });
    bus.publish(AgentEvent.message(reply));
    bus.finished();
  }
  async cancelTask(): Promise<void> {}
}

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  brokerKey = await exportSPKI(publicKey);
  sign = () => new SignJWT({
    scope: 'checkout', permissions: ['create_order'], excluded: [], session_id: 'sess_ap2', token_type: 'consent',
    authorization_modality: 'delegated', initiator_agent_id: 'prf_agent_client', target_agent_id: AGENT_ID,
    mandate_refs: [{ family: 'checkout', closed_jwt: 'c', sd_hash: 's' }],
  }).setProtectedHeader({ alg: 'EdDSA' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(privateKey);

  const app = express();
  server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
  base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const card = {
    name: 'AP2 shop', description: 'Parafé + AP2 interop agent', version: '1.0.0',
    supportedInterfaces: duplicateInterfacesForLegacy([{ url: `${base}/shop`, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: A2A_PROTOCOL_VERSION }], ['JSONRPC']),
    capabilities: { streaming: false, pushNotifications: false, extensions: [buildAgentCardExtension({ agentId: AGENT_ID, scopeRequirements: SCOPES, required: false }), buildAp2AgentCardExtension()] },
    securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'], skills: [], signatures: [],
  } as unknown as AgentCard;
  const handler = new DefaultRequestHandler(card, new InMemoryTaskStore(), new ShopExecutor());
  app.use('/shop', jsonRpcHandler({ requestHandler: handler, userBuilder: UserBuilder.noAuthentication, legacyCompat: { enabled: true } }));
  app.use(['/.well-known/agent-card.json', '/.well-known/agent.json'], agentCardHandler({ agentCardProvider: handler, legacyCompat: { enabled: true } }));
});

afterAll(() => server?.close());

const expected = () => `consent sess_ap2; mandate ${sha(MANDATE)}`;

async function rpc(headers: Record<string, string>, body: unknown) {
  const res = await fetch(`${base}/shop`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return (await res.json()) as { result?: Record<string, unknown>; error?: { message: string } };
}

describe('interop (A4): a Parafé consent token and an AP2 mandate in one message', () => {
  it('the agent card declares both extensions, in the A2A 1.0 and 0.3 views', async () => {
    for (const headers of [{ 'A2A-Version': '1.0' }, {}]) {
      const card = (await (await fetch(`${base}/.well-known/agent-card.json`, { headers })).json()) as { capabilities: { extensions: Array<{ uri: string }> } };
      expect(parseAgentCardExtension(card.capabilities.extensions)?.params.agent_id).toBe(AGENT_ID);
      expect(card.capabilities.extensions.map((e) => e.uri)).toContain(AP2_EXTENSION_URI);
    }
  });

  it('official A2A 1.0 client: both reach the agent intact; the reply carries the AP2 receipt', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    const message: Message = {
      messageId: randomUUID(), contextId: '', taskId: '', role: Role.ROLE_USER,
      parts: [{ content: { $case: 'text', value: 'Buy the gold sneakers.' }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
      metadata: undefined, extensions: [], referenceTaskIds: [],
    };
    const both = withAp2(withConsentToken(message, await sign(), 'sess_ap2'), { checkoutMandate: MANDATE });
    expect(both.parts).toHaveLength(2);
    const reply = (await client.sendMessage(
      { tenant: '', message: both, configuration: undefined, metadata: undefined },
      { serviceParameters: ServiceParameters.create(withA2AExtensions(PARAFE_EXTENSION_URI)) }
    )) as Message;
    expect(reply.parts.map((p) => (p.content?.$case === 'text' ? p.content.value : '')).join('')).toBe(expected());
    expect(readAp2(reply)).toEqual({ checkoutReceipt: RECEIPT });
  });

  it('raw A2A 1.0 JSON-RPC', async () => {
    const message = withAp2(withConsentToken({ messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: 'Buy.' }] }, await sign(), 'sess_ap2'), { checkoutMandate: MANDATE });
    expect(message.parts[1]).toEqual({ data: { [AP2_CHECKOUT_MANDATE_KEY]: MANDATE }, mediaType: 'application/json' });
    const json = await rpc(activationHeaders('1.0'), { jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message } });
    expect(json.error).toBeUndefined();
    const reply = json.result!['message'] as { parts: Array<{ text?: string }> };
    expect(reply.parts[0]?.text).toBe(expected());
    expect(readAp2(reply)).toEqual({ checkoutReceipt: RECEIPT });
  });

  it('raw A2A 0.3 JSON-RPC (compatibility layer), as the AP2 samples send it', async () => {
    const message = withAp2(withConsentToken({ messageId: randomUUID(), role: 'user', kind: 'message', parts: [{ kind: 'text', text: 'Buy.' }] }, await sign(), 'sess_ap2'), { checkoutMandate: MANDATE });
    expect(message.parts[1]).toEqual({ kind: 'data', data: { [AP2_CHECKOUT_MANDATE_KEY]: MANDATE } });
    expect(message.extensions).toEqual([PARAFE_EXTENSION_URI, AP2_EXTENSION_URI]);
    const json = await rpc(activationHeaders('0.3'), { jsonrpc: '2.0', id: 2, method: 'message/send', params: { message } });
    expect(json.error).toBeUndefined();
    expect((json.result!['parts'] as Array<{ text?: string }>)[0]?.text).toBe(expected());
    expect(readAp2(json.result!)).toEqual({ checkoutReceipt: RECEIPT });
  });

  it('the Parafé token stays out of parts; the AP2 data stays out of Parafé metadata', async () => {
    const token = await sign();
    const m = withAp2(withConsentToken({ parts: [{ text: 'x' }] }, token, 's'), { checkoutMandate: MANDATE, paymentReceipt: { status: 'Success' } });
    expect(JSON.stringify(m.parts)).not.toContain(token);
    expect(JSON.stringify(m.metadata)).not.toContain(MANDATE);
    expect(extractConsentToken(m)?.token).toBe(token);
    expect(readAp2(m)).toEqual({ checkoutMandate: MANDATE, paymentReceipt: { status: 'Success' } });
  });
});
