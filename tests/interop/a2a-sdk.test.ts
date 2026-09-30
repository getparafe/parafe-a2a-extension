/**
 * Interop tests — this package against a real A2A server and client (@a2a-js/sdk).
 *
 * A local A2A 1.0 server (v0.3 compatibility on, as most deployments run it) uses the
 * package to read and verify Parafe data. Requests come from the official A2A 1.0
 * client and as raw A2A 1.0 and 0.3 JSON-RPC, the way non-SDK clients send them.
 * No network beyond localhost.
 */
import { randomUUID, generateKeyPairSync } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import { SignJWT, exportJWK, generateKeyPair, calculateJwkThumbprint, type JWK } from 'jose';
import { A2A_PROTOCOL_VERSION, Role, type AgentCard, type Message } from '@a2a-js/sdk';
import { duplicateInterfacesForLegacy } from '@a2a-js/sdk/compat/v0_3';
import { AgentEvent, DefaultRequestHandler, InMemoryTaskStore, type AgentExecutor, type ExecutionEventBus, type RequestContext } from '@a2a-js/sdk/server';
import { agentCardHandler, jsonRpcHandler, UserBuilder } from '@a2a-js/sdk/server/express';
import { ClientFactory, ServiceParameters, withA2AExtensions } from '@a2a-js/sdk/client';
import {
  PARAFE_EXTENSION_URI,
  activationHeaders,
  buildAgentCardExtension,
  createPresentationProof,
  extractHandshakeComplete,
  extractParafeError,
  parafeErrorData,
  parseAgentCardExtension,
  readParafe,
  verifyMessageConsentToken,
  withConsentToken,
  withParafe,
  type BrokerKeys,
  type ScopeRequirement,
} from '../../src/index.js';

const AGENT_ID = 'prf_agent_shop';
const SCOPES: Record<string, ScopeRequirement> = {
  'order-donuts': { permissions: ['read_menu', 'create_order'], minimum_authorization_modality: 'attested' },
};
const CHALLENGE = {
  handshake_id: 'hs_1',
  challenge: 'ab'.repeat(32),
  initiator_agent_id: 'prf_agent_client',
  broker_url: 'https://api.parafe.ai',
  requested_scope: 'order-donuts',
};

let brokerKeys: BrokerKeys;
// The initiator's key: consent tokens are bound to it and it signs the presentation proofs (required by default in 3.0).
const client = generateKeyPairSync('ed25519');
const clientJwk = client.publicKey.export({ format: 'jwk' }) as JWK;
let sign: (claims?: Record<string, unknown>) => Promise<string>;
let server: Server;
let base: string;

/** The shop's agent logic: answer handshakes, verify consent, report Parafe errors. */
class ShopExecutor implements AgentExecutor {
  async execute(ctx: RequestContext, bus: ExecutionEventBus): Promise<void> {
    let reply: Message = {
      messageId: randomUUID(), contextId: ctx.contextId, taskId: '', role: Role.ROLE_AGENT,
      parts: [], metadata: undefined, extensions: [], referenceTaskIds: [],
    };
    const text = (value: string) => [{ content: { $case: 'text' as const, value }, metadata: undefined, filename: '', mediaType: 'text/plain' }];

    try {
      const data = readParafe(ctx.userMessage);
      if (data && 'handshake_challenge' in data) {
        // A real agent signs the challenge with the broker here.
        reply = withParafe(reply, {
          handshake_complete: { handshake_id: data.handshake_challenge.handshake_id, status: 'authenticated', session_id: 'sess_1', consent_token: await sign() },
        });
        reply.parts = text('handshake complete');
      } else {
        const { sessionId } = await verifyMessageConsentToken(ctx.userMessage, brokerKeys, {
          agentId: AGENT_ID, action: 'create_order', scopeRequirements: SCOPES, initiatorKey: clientJwk,
        });
        reply.parts = text(`verified ${sessionId}`);
      }
      ctx.context.addActivatedExtension(PARAFE_EXTENSION_URI);
    } catch (err) {
      reply = withParafe(reply, parafeErrorData(err));
      reply.parts = text('refused');
    }

    bus.publish(AgentEvent.message(reply));
    bus.finished();
  }
  async cancelTask(): Promise<void> {}
}

function mount(app: express.Express, path: string, required: boolean): AgentCard {
  const card: AgentCard = {
    name: `Shop (${path})`, description: 'Parafe interop test agent', version: '1.0.0',
    supportedInterfaces: duplicateInterfacesForLegacy(
      [{ url: `${base}${path}`, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: A2A_PROTOCOL_VERSION }],
      ['JSONRPC']
    ),
    capabilities: { streaming: false, pushNotifications: false, extensions: [buildAgentCardExtension({ agentId: AGENT_ID, scopeRequirements: SCOPES, required })] },
    securitySchemes: {}, securityRequirements: [], defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
    skills: [], signatures: [],
  } as unknown as AgentCard;
  const handler = new DefaultRequestHandler(card, new InMemoryTaskStore(), new ShopExecutor());
  app.use(path, jsonRpcHandler({ requestHandler: handler, userBuilder: UserBuilder.noAuthentication, legacyCompat: { enabled: true } }));
  if (path === '/strict') {
    app.use(['/.well-known/agent-card.json', '/.well-known/agent.json'], agentCardHandler({ agentCardProvider: handler, legacyCompat: { enabled: true } }));
  }
  return card;
}

let openCard: AgentCard;

beforeAll(async () => {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  brokerKeys = { keys: [{ ...(await exportJWK(publicKey)), kid: 'broker-1', alg: 'ES256' }] } as BrokerKeys;
  const jkt = await calculateJwkThumbprint(clientJwk);
  sign = (claims = {}) =>
    new SignJWT({
      scope: 'order-donuts', permissions: ['read_menu', 'create_order'], exclusions: [], session_id: 'sess_1',
      token_type: 'consent', authorization_modality: 'attested', initiator_agent_id: 'prf_agent_client', target_agent_id: AGENT_ID,
      cnf: { jkt }, ...claims,
    }).setProtectedHeader({ alg: 'ES256', kid: 'broker-1' }).setIssuer('parafe-trust-broker').setSubject('prf_agent_client')
      .setAudience(`did:web:api.parafe.ai:agents:${AGENT_ID}`).setIssuedAt().setExpirationTime('5m').sign(privateKey);

  const app = express();
  server = await new Promise<Server>((resolve) => { const s = app.listen(0, () => resolve(s)); });
  base = `http://localhost:${(server.address() as AddressInfo).port}`;
  mount(app, '/strict', true);
  openCard = mount(app, '/open', false);
});

afterAll(() => {
  server?.close();
});

// ── helpers ──

const sdkMessage = (): Message => ({
  messageId: randomUUID(), contextId: '', taskId: '', role: Role.ROLE_USER,
  parts: [{ content: { $case: 'text', value: 'Two dozen glazed, please.' }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
  metadata: undefined, extensions: [], referenceTaskIds: [],
});
const parafeHeaders = { serviceParameters: ServiceParameters.create(withA2AExtensions(PARAFE_EXTENSION_URI)) };
const replyText = (m: Message) => m.parts.map((p) => (p.content?.$case === 'text' ? p.content.value : '')).join('');

async function send(client: Awaited<ReturnType<ClientFactory['createFromUrl']>>, message: Message, withHeader = true) {
  return (await client.sendMessage(
    { tenant: '', message, configuration: undefined, metadata: undefined },
    withHeader ? parafeHeaders : undefined
  )) as Message;
}

/** The message with a fresh consent token and the initiator's proof, bound to the message ID. */
async function consented<M extends { messageId: string }>(message: M, claims: Record<string, unknown> = {}) {
  const token = await sign(claims);
  return withConsentToken(message, token, 'sess_1', await createPresentationProof(token, client.privateKey, { messageId: message.messageId }));
}

async function rpc(path: string, headers: Record<string, string>, body: unknown) {
  const res = await fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { res, json: (await res.json()) as { result?: Record<string, unknown>; error?: { code: number; message: string } } };
}

// ── tests ──

describe('interop: agent card', () => {
  it('the Parafe entry survives the SDK card handler, in both A2A 1.0 and 0.3 views', async () => {
    for (const headers of [{ 'A2A-Version': '1.0' }, {}]) {
      const card = (await (await fetch(`${base}/.well-known/agent-card.json`, { headers })).json()) as { capabilities: { extensions: Array<{ uri: string }> } };
      const parafe = parseAgentCardExtension(card.capabilities.extensions);
      expect(parafe?.uri).toBe(PARAFE_EXTENSION_URI);
      expect(parafe?.params.agent_id).toBe(AGENT_ID);
      expect(parafe?.required).toBe(true);
    }
  });
});

describe('interop: official A2A 1.0 client', () => {
  it('consent token in metadata reaches the agent and verifies', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    const reply = await send(client, await consented(sdkMessage()));
    expect(replyText(reply)).toBe('verified sess_1');
  });

  it('3.0: a consent token without a proof is refused', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    const reply = await send(client, withConsentToken(sdkMessage(), await sign(), 'sess_1'));
    expect(extractParafeError(reply)?.code).toBe('INVALID_PROOF');
  });

  it('handshake round trip: challenge in, handshake_complete back in the reply metadata', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    const reply = await send(client, withParafe(sdkMessage(), { handshake_challenge: CHALLENGE }));
    const complete = extractHandshakeComplete(reply);
    expect(complete?.status).toBe('authenticated');
    expect(complete?.session_id).toBe('sess_1');
    expect(typeof complete?.consent_token).toBe('string');
  });

  it('a required Parafe extension turns away clients that do not activate it', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    await expect(send(client, sdkMessage(), false)).rejects.toThrow(/required extensions/);
  });

  it('refusals come back as Parafe error data the client can read', async () => {
    const client = await new ClientFactory().createFromUrl(base);
    const reply = await send(client, await consented(sdkMessage(), { target_agent_id: 'prf_agent_other_shop' }));
    expect(replyText(reply)).toBe('refused');
    expect(extractParafeError(reply)?.code).toBe('WRONG_AUDIENCE');
  });

  it('a message without Parafe data is refused on the open door with MISSING_PARAFE_EXTENSION', async () => {
    const client = await new ClientFactory().createFromAgentCard(openCard);
    const reply = await send(client, sdkMessage(), false);
    expect(extractParafeError(reply)?.code).toBe('MISSING_PARAFE_EXTENSION');
  });

  it('the token never appears in message parts', async () => {
    const token = await sign();
    const message = withConsentToken(sdkMessage(), token, 'sess_1');
    expect(JSON.stringify(message.parts)).not.toContain(token);
  });
});

describe('interop: raw A2A 1.0 JSON-RPC', () => {
  it('SendMessage with metadata + A2A-Extensions verifies, and the agent echoes activation', async () => {
    const message = await consented({ messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: 'Two dozen glazed.' }] });
    const { res, json } = await rpc('/strict', activationHeaders('1.0'), { jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message } });

    expect(json.error).toBeUndefined();
    const reply = json.result!['message'] as { parts: Array<{ text?: string }> };
    expect(reply.parts[0]?.text).toBe('verified sess_1');
    expect(res.headers.get('A2A-Extensions')).toContain(PARAFE_EXTENSION_URI);
  });

  it('the handshake_complete in the wire reply is readable', async () => {
    const message = withParafe({ messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: 'hi' }] }, { handshake_challenge: CHALLENGE });
    const { json } = await rpc('/strict', activationHeaders('1.0'), { jsonrpc: '2.0', id: 2, method: 'SendMessage', params: { message } });
    expect(extractHandshakeComplete(json.result!['message'] as object)?.status).toBe('authenticated');
  });

  it('the A2A 0.3 header name on an A2A 1.0 request does not activate the extension', async () => {
    const message = withConsentToken({ messageId: randomUUID(), role: 'ROLE_USER', parts: [{ text: 'hi' }] }, await sign(), 'sess_1');
    const { json } = await rpc('/strict', { 'A2A-Version': '1.0', 'X-A2A-Extensions': PARAFE_EXTENSION_URI }, { jsonrpc: '2.0', id: 3, method: 'SendMessage', params: { message } });
    expect(json.error?.code).toBe(-32008);
  });
});

describe('interop: raw A2A 0.3 JSON-RPC (compatibility layer)', () => {
  it('message/send with metadata + X-A2A-Extensions verifies', async () => {
    const message = await consented({ messageId: randomUUID(), role: 'user', kind: 'message', parts: [{ kind: 'text', text: 'Two dozen glazed.' }] });
    const { json } = await rpc('/strict', activationHeaders('0.3'), { jsonrpc: '2.0', id: 4, method: 'message/send', params: { message } });

    expect(json.error).toBeUndefined();
    expect((json.result!['parts'] as Array<{ text: string }>)[0]?.text).toBe('verified sess_1');
  });

  it('the handshake_complete survives translation back to an A2A 0.3 reply', async () => {
    const message = withParafe({ messageId: randomUUID(), role: 'user', kind: 'message', parts: [{ kind: 'text', text: 'hi' }] }, { handshake_challenge: CHALLENGE });
    const { json } = await rpc('/strict', activationHeaders('0.3'), { jsonrpc: '2.0', id: 5, method: 'message/send', params: { message } });
    expect(json.result!['kind']).toBe('message');
    expect(extractHandshakeComplete(json.result!)?.status).toBe('authenticated');
  });
});

describe('interop: v1 senders (data parts)', () => {
  it('3.0: a v1 data part is not Parafé data; the open agent answers MISSING_PARAFE_EXTENSION', async () => {
    const message = {
      messageId: randomUUID(), role: 'user', kind: 'message',
      parts: [{ kind: 'data', data: { 'parafe.trust.ConsentToken': { token: await sign(), session_id: 'sess_1' } } }, { kind: 'text', text: 'hi' }],
    };
    const { json } = await rpc('/open', {}, { jsonrpc: '2.0', id: 6, method: 'message/send', params: { message } });
    expect(extractParafeError(json.result!)?.code).toBe('MISSING_PARAFE_EXTENSION');
  });
});
