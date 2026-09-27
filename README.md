# @getparafe/a2a-extension

Parafé trust for the [A2A protocol](https://a2a-protocol.org). Adds cryptographic agent identity, brokered mutual authentication, and scoped consent to agent-to-agent calls, for A2A 1.0 (and 0.3).

```
npm install @getparafe/a2a-extension
```

**Specification:** [`https://parafe.ai/extensions/a2a/v2`](https://parafe.ai/extensions/a2a/v2). The URI of the extension is also where its spec lives.

| | |
|---|---|
| Extension URI | `https://parafe.ai/extensions/a2a/v2` |
| A2A versions | 1.0 and 0.3 |
| Works with | [`@a2a-js/sdk`](https://www.npmjs.com/package/@a2a-js/sdk) 1.x, any other A2A SDK, or raw A2A JSON |
| Runtime | Node 18+, browsers, edge runtimes (only depends on `jose`) |

---

## How it works

1. The **agent** (the one being called) declares its Parafé requirements, per scope, in its agent card.
2. The **client** (the calling agent) starts a handshake with the Parafé broker and sends the broker's challenge in an A2A message.
3. The agent completes the handshake with the broker and returns a broker-signed **consent token**.
4. The client includes the token in every following message. The agent verifies it before acting: offline, with the broker's public key.

All Parafé data rides in the message's **metadata**, under the extension URI, and never in message `parts`. Agents usually hand `parts` to a language model and store them in chat logs. A consent token belongs in neither.

```json
{
  "messageId": "6f1c…",
  "role": "ROLE_USER",
  "parts": [{ "text": "Two dozen glazed for pickup at 9." }],
  "extensions": ["https://parafe.ai/extensions/a2a/v2"],
  "metadata": {
    "https://parafe.ai/extensions/a2a/v2": {
      "consent": { "token": "eyJhbGciOiJFZERTQSJ9…", "session_id": "sess_7d2…" }
    }
  }
}
```

The handshake uses the same slot: `handshake_challenge` (client → agent), then `handshake_complete` (agent → client). An agent that refuses sends `error`. See the [spec](https://parafe.ai/extensions/a2a/v2) for every field.

You need a Parafé account ([platform.parafe.ai](https://platform.parafe.ai)) and a registered agent. The [Parafé SDK](https://github.com/getparafe/sdk) (`@getparafe/sdk`) talks to the broker. This package handles the A2A side.

---

## Agent side (the agent being called)

### 1. Declare Parafé in your agent card

```typescript
import { buildAgentCardExtension } from '@getparafe/a2a-extension';

export const SCOPES = {
  'check-menu': { permissions: ['read_menu'], minimum_authorization_modality: 'autonomous' },
  'order-donuts': { permissions: ['read_menu', 'create_order'], minimum_authorization_modality: 'attested' },
} as const;

const card = {
  name: 'SoHo Donuts Shop Agent',
  // … supportedInterfaces, skills, etc.
  capabilities: {
    extensions: [
      buildAgentCardExtension({ agentId: 'prf_agent_donuts01', scopeRequirements: SCOPES, required: false }),
    ],
  },
};
```

**`required` is a real choice:**

- `required: true`: the agent serves nobody without Parafé. A2A 1.0 servers, including `@a2a-js/sdk`, reject any request that doesn't activate the extension (error `-32008`) before your code runs. That's enforcement for free.
- `required: false`: the agent also serves callers without Parafé, for example to answer questions about the menu. You must then check consent yourself before every action inside a Parafé scope.

### 2. Answer handshakes and verify consent (`@a2a-js/sdk` executor)

```typescript
import { ParafeClient } from '@getparafe/sdk';
import {
  PARAFE_EXTENSION_URI,
  fetchBrokerPublicKey,
  readParafe,
  verifyMessageConsentToken,
  withParafe,
  parafeErrorData,
} from '@getparafe/a2a-extension';

const parafe = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey: process.env.PARAFE_API_KEY });
const brokerPublicKey = await fetchBrokerPublicKey(); // once, at startup

class ShopExecutor implements AgentExecutor {
  async execute(ctx: RequestContext, bus: ExecutionEventBus) {
    let reply: Message = { messageId: randomUUID(), contextId: ctx.contextId, role: Role.ROLE_AGENT, parts: [], /* … */ };
    try {
      const data = readParafe(ctx.userMessage);

      if (data && 'handshake_challenge' in data) {
        const c = data.handshake_challenge;
        const { sessionId, consentToken } = await parafe.completeHandshake({ handshakeId: c.handshake_id, challengeNonce: c.challenge });
        reply = withParafe(reply, {
          handshake_complete: { handshake_id: c.handshake_id, status: 'authenticated', session_id: sessionId, consent_token: consentToken.token },
        });
      } else {
        // Before any action inside a Parafé scope:
        const { claims } = await verifyMessageConsentToken(ctx.userMessage, brokerPublicKey, {
          agentId: 'prf_agent_donuts01', // reject tokens issued for any other agent
          action: 'create_order',
          scopeRequirements: SCOPES, // defence in depth: scope, permissions and modality match your card
        });
        // … place the order; claims.authorization_modality says what human backing it has
      }
      ctx.context.addActivatedExtension(PARAFE_EXTENSION_URI); // echoes A2A-Extensions in the response
    } catch (err) {
      reply = withParafe(reply, parafeErrorData(err)); // tells the client why, e.g. EXPIRED_CONSENT_TOKEN
    }
    bus.publish(AgentEvent.message(reply));
    bus.finished();
  }
}
```

Not using `@a2a-js/sdk`? The same functions take plain A2A JSON messages, and `isParafeActivated(req.headers)` tells you whether the request activated the extension.

---

## Client side (the calling agent)

```typescript
import { ClientFactory, ServiceParameters, withA2AExtensions } from '@a2a-js/sdk/client';
import { ParafeClient } from '@getparafe/sdk';
import {
  PARAFE_EXTENSION_URI,
  parseAgentCardExtension,
  withParafe,
  withConsentToken,
  extractHandshakeComplete,
} from '@getparafe/a2a-extension';

// 1. Discover: fetch the card (at /.well-known/agent-card.json) and read the Parafé requirements
const card = await (await fetch('https://shop.example/.well-known/agent-card.json', { headers: { 'A2A-Version': '1.0' } })).json();
const requirements = parseAgentCardExtension(card.capabilities?.extensions);
// requirements.params.agent_id, .broker_url, .scope_requirements['order-donuts']

const a2a = await new ClientFactory().createFromAgentCard(card);
const activate = { serviceParameters: ServiceParameters.create(withA2AExtensions(PARAFE_EXTENSION_URI)) };

// 2. Handshake: get a challenge from the broker and send it to the agent
const { handshakeId, challengeForTarget } = await parafe.handshake({
  targetAgentId: requirements.params.agent_id,
  scope: 'order-donuts',
  permissions: ['read_menu', 'create_order'],
  authorization: ParafeClient.authorization.attested({ instruction: 'get me donuts', platform: 'whatsapp' }),
});
const reply = await a2a.sendMessage({
  message: withParafe(newMessage('Hi, I\'d like to order.'), {
    handshake_challenge: {
      handshake_id: handshakeId,
      challenge: challengeForTarget,
      initiator_agent_id: parafe.credentialStatus().agentId,
      broker_url: requirements.params.broker_url,
      requested_scope: 'order-donuts',
    },
  }),
}, activate);
const { session_id, consent_token } = extractHandshakeComplete(reply);

// 3. Every following message carries the token
await a2a.sendMessage({ message: withConsentToken(newMessage('Two dozen glazed for 9am.'), consent_token, session_id) }, activate);
```

The SDK picks the right activation header for the A2A version it negotiated. Sending raw HTTP? Use `activationHeaders()`: `A2A-Version: 1.0` + `A2A-Extensions` for A2A 1.0, or `X-A2A-Extensions` for A2A 0.3.

---

## Verification

`verifyMessageConsentToken(message, brokerPublicKey, { agentId, action?, scopeRequirements? })` does all of this. `verifyConsentTokenOffline(token, key, options)` does it for a bare token.

| Check | Error |
|---|---|
| Ed25519 signature, issuer `parafe-trust-broker`, `token_type: consent` | `InvalidConsentTokenError` |
| Not expired | `ExpiredConsentTokenError` |
| `target_agent_id` is you (`agentId`) | `WrongAudienceError` |
| The message's `session_id` matches the token's | `InvalidConsentTokenError` |
| `action` is permitted and not excluded | `ScopeViolationError` |
| Scope declared, permissions within it, modality ≥ minimum (`scopeRequirements`) | `ScopeViolationError` |
| No consent token in the message | `MissingParafeExtensionError` |
| Parafé data present but malformed | `MalformedParafeDataError` |

Fetch the broker key once with `fetchBrokerPublicKey()` and cache it. There's no network call per message. For real-time confirmation on high-value actions, `verifyConsentTokenOnline(token, { action, agentId })` asks the broker.

Every error has a `code`. `parafeErrorData(err)` turns it into the spec's `error` data for your reply, and never leaks the message of an error that isn't ours.

---

## API reference

| Function | Purpose |
|---|---|
| `buildAgentCardExtension({ agentId, scopeRequirements, required, brokerUrl?, minimumIdentityAssurance?, description? })` | Agent card entry |
| `parseAgentCardExtension(extensions)` | Read a card's Parafé entry (v2 or v1 URI), or `null` |
| `withParafe(message, data)` | Copy of `message` with Parafé data in metadata and the URI in `extensions` |
| `withConsentToken(message, token, sessionId)` | Shorthand for `withParafe(message, { consent: … })` |
| `readParafe(message, { acceptV1? })` | The message's Parafé data, or `null` |
| `extractHandshakeChallenge` / `extractHandshakeComplete` / `extractConsentToken` / `extractParafeError` `(message)` | One member, or `null` |
| `hasParafeData(message)` | Any Parafé data present? |
| `parafeErrorData(err)` | `{ error: { code, message } }` for a refusal |
| `activationHeaders(a2aVersion?, otherExtensions?)` | HTTP headers that activate the extension |
| `isParafeActivated(headers)` | Did this request activate it? |
| `verifyMessageConsentToken(message, key, options)` | Extract + verify in one step |
| `verifyConsentTokenOffline(token, key, options?)` | Verify a token locally |
| `verifyConsentTokenOnline(token, options)` | Verify via the broker's `/consent/verify` |
| `fetchBrokerPublicKey(brokerUrl?)` | The broker's Ed25519 key, as PEM |

Messages can be `@a2a-js/sdk` `Message` objects or raw A2A 1.0 / 0.3 JSON.

---

## Migrating from 1.x

2.0 follows A2A 1.0. What changed:

- **Parafé data moved from message parts to message metadata.** `buildConsentTokenPart()`, `buildHandshakeChallenge()` and `buildHandshakeComplete()` are gone. Use `withConsentToken()` / `withParafe()` on the whole message. 1.x data parts were silently emptied by the A2A 1.0 client, and never found by 1.x readers on A2A 1.0 servers.
- **Readers take the whole message**, not `message.parts`: `extractConsentToken(message)`, `verifyMessageConsentToken(message, key, { agentId })`.
- **`agentId` is required** when verifying a message: tokens issued for another agent are rejected (`WrongAudienceError`).
- **New extension URI**: `https://parafe.ai/extensions/a2a/v2`. `parseAgentCardExtension` still recognizes v1 cards.
- **Activation header**: `A2A-Extensions` on A2A 1.0 (was `X-A2A-Extensions`, now only for A2A 0.3).
- **`required` must be set** in `buildAgentCardExtension`.
- `MalformedDataPartError` is now `MalformedParafeDataError` (`MALFORMED_PARAFE_DATA`). The `/compat` export is removed.

Agents on 2.x still **read** 1.x-style data parts (all three wire shapes) until 2027-03-31. Pass `{ acceptV1: false }` to turn that off. A 1.x client only activates the v1 URI, so it can reach agents that declare `required: false`.

---

## Related

- [Extension specification](https://parafe.ai/extensions/a2a/v2)
- [Parafé SDK](https://github.com/getparafe/sdk) (`@getparafe/sdk`): registration, handshakes, receipts
- [Parafé Platform](https://platform.parafe.ai): agent registration and API keys
- [A2A protocol specification](https://a2a-protocol.org/v1.0.0/specification/)
