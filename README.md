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

The handshake uses the same slot: `handshake_challenge` (client → agent), then `handshake_complete` (agent → client). An agent that refuses sends `error`. Since 2.2 the agent signs an **action receipt** for each action it performs or refuses and returns it in `action_receipts`, beside any other Parafé data in the reply; both sides can file it with the broker, and the session receipt lists every one. See the [spec](https://parafe.ai/extensions/a2a/v2) for every field.

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
// Modalities, weakest to strongest: autonomous < attested < delegated < verified.
// 'delegated' and 'verified' mean the broker checked a user-signed AP2 mandate
// (claims.mandate_refs lists it); set ap2_trusted_issuers in the broker scope policy.

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

**Say what the broker enforces, from the broker.** Build `scope_requirements` from your agent's scope policies so the card can't drift from them: who the initiator must be (`minimum_identity_assurance`, `minimum_verification_tier`), `exclusions`, reputation floors, and the AP2 issuers you trust (by key thumbprint):

```typescript
import { scopeRequirementsFromPolicies } from '@getparafe/a2a-extension';

const { scope_policies } = await (await fetch(`https://api.parafe.ai/agents/${agentId}/scope-policies`)).json();
const scopeRequirements = await scopeRequirementsFromPolicies(scope_policies);
```

**`required` is a real choice:**

- `required: true`: the agent serves nobody without Parafé. A2A 1.0 servers, including `@a2a-js/sdk`, reject any request that doesn't activate the extension (error `-32008`) before your code runs. That's enforcement for free.
- `required: false`: the agent also serves callers without Parafé, for example to answer questions about the menu. You must then check consent yourself before every action inside a Parafé scope.

### 2. Answer handshakes and verify consent (`@a2a-js/sdk` executor)

```typescript
import { ParafeClient } from '@getparafe/sdk';
import {
  PARAFE_EXTENSION_URI,
  createBrokerKeyCache,
  readParafe,
  verifyMessageConsentToken,
  withParafe,
  withActionReceipts,
  parafeErrorData,
  createActionReceiptSigner,
} from '@getparafe/a2a-extension';

const parafe = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey: process.env.PARAFE_API_KEY });
const brokerKeys = createBrokerKeyCache(); // the broker's JWKS; refetches if the broker adds a key
// 2.2: sign an action receipt for what this agent does or refuses; filed with the broker in the background
const receipts = createActionReceiptSigner({ agentId: 'prf_agent_donuts01', privateKey, credential });

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
        const { claims, sessionId, completeAction } = await verifyMessageConsentToken(ctx.userMessage, brokerKeys, {
          agentId: 'prf_agent_donuts01', // reject tokens issued for any other agent
          action: 'create_order',
          scopeRequirements: SCOPES, // defence in depth: scope, permissions and modality match your card
          receipts, // a refusal is receipted automatically (the error carries it)
        });
        // … place the order; claims.authorization_modality says what human backing it has
        const { receipt } = await completeAction({ businessRef: order.id }); // or { result: 'error', error: 'failed' }
        reply = withActionReceipts(reply, [receipt]); // one receipt per action; several per turn is fine
      }
      ctx.context.addActivatedExtension(PARAFE_EXTENSION_URI); // echoes A2A-Extensions in the response
    } catch (err) {
      reply = withParafe(reply, parafeErrorData(err)); // why (e.g. SCOPE_VIOLATION), with the signed refusal receipt
    }
    bus.publish(AgentEvent.message(reply));
    bus.finished();
  }
}
```

Not using `@a2a-js/sdk`? The same functions take plain A2A JSON messages, and `isParafeActivated(req.headers)` tells you whether the request activated the extension.

**Action receipts (2.2).** With `receipts`, a failed consent check signs an error receipt (`excluded`, `not_permitted`, `consent_expired`, `proof_invalid` or `consent_invalid`), files it and attaches it to the thrown error; `parafeErrorData(err)` returns it to the client in `action_receipts`, beside the `error`. On success, `completeAction()` signs and files the receipt for the outcome. Filing runs in the background: call `receipts.flush()` before you close the session. The broker learns action names, results and your `businessRef`, never the message content (`details` and `request` are sent only as hashes). Without a consent token in the message there's nothing to bind a receipt to, so none is signed. **If a language model decides which tools to call,** tell it to attempt the tool and let the consent check refuse: a model that declines a forbidden request on its own never reaches the check, so the refusal isn't receipted.

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
  withSessionClosed,
  extractHandshakeComplete,
  extractActionReceipts,
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

// 3. Every following message carries the token, and a proof that you hold the key it's bound to
const message = newMessage('Two dozen glazed for 9am.');
const proof = await parafe.createPresentationProof(consent_token, message.messageId); // or createPresentationProof(token, privateKey)
const agentReply = await a2a.sendMessage({ message: withConsentToken(message, consent_token, session_id, proof) }, activate);

// The agent's reply carries its signed action receipt; file your copy too, so it's indexed even if the agent doesn't
for (const r of extractActionReceipts(agentReply)) await parafe.fileActionReceipt(session_id, r);

// 4. When you close the session, tell the agent and hand it the receipt
const receipt = await parafe.closeSession(session_id);
await a2a.sendMessage({ message: withSessionClosed(newMessage('Thanks!'), session_id, receipt.receipt) }, activate);
```

The SDK picks the right activation header for the A2A version it negotiated. Sending raw HTTP? Use `activationHeaders()`: `A2A-Version: 1.0` + `A2A-Extensions` for A2A 1.0, or `X-A2A-Extensions` for A2A 0.3.

---

## AP2 receipts (merchant side)

If your agent is a merchant and a shopping agent presents an [AP2](https://github.com/google-agentic-commerce/AP2) v0.2 Checkout Mandate, AP2 says you MUST answer with a Checkout Receipt, for a rejection too. After verifying the mandate (the broker's `POST /ap2/mandates/verify` via `@getparafe/sdk`'s `verifyMandate()`, or offline with `@getparafe/verify`'s `verifyAp2Mandate`), sign the receipt with your agent's P-256 key and file it in the session's index:

```typescript
const receipts = createActionReceiptSigner({ agentId, privateKey, credential });
const { receipt, reference, references } = await receipts.ap2Receipt(sessionId, verified.valid
  ? { kind: 'checkout', mandate, orderId: order.id }
  : { kind: 'checkout', mandate, error: verified.error, errorDescription: verified.message });
// return `receipt` to the shopping agent; it is filed in the background (receipts.flush() before close)
```

AP2's spec and its SDK compute `reference` differently (the spec: the final SD-JWT's hash, like `sd_hash`; the AP2 SDK: SHA-256 of the closed mandate's JWT). The receipt uses the SDK's form by default (`referenceForm: 'sd_hash'` for the spec's) and `references` gives both. The broker matches either form against the mandates verified in the session and marks the index entry `reference_verified`. `signAp2Receipt` and `ap2MandateReferences` work without the signer; `kind: 'payment'` makes a Payment Receipt (`paymentId`, and on success `pspConfirmationId`, `networkConfirmationId`). The AP2 Python SDK's `ReceiptClient.verify_receipt` accepts these receipts.

## AP2 mandates and receipts in A2A messages (provisional)

AP2 v0.2 has no normative binding to A2A (it deleted its A2A extension spec); its samples put each artifact in its own data part under a fixed key and declare `https://github.com/google-agentic-commerce/ap2/v1`. `withAp2()` and `readAp2()` follow the samples, so AP2 data travels beside Parafé's without colliding (Parafé's stays in metadata). They may change when AP2 (now at FIDO) publishes a binding.

```typescript
// Shopping agent: the consent token (Parafé) and the checkout mandate (AP2) in one message
const message = withAp2(withConsentToken(msg, token, sessionId, proof), { checkoutMandate });

// Merchant agent
const { checkoutMandate } = readAp2(ctx.userMessage) ?? {};
const reply = withAp2(replyMessage, { checkoutReceipt: receipt });

// Agent card: declare both
capabilities: { extensions: [buildAgentCardExtension({ agentId, scopeRequirements, required: false }), buildAp2AgentCardExtension()] }
```

## Verification

`verifyMessageConsentToken(message, brokerKeys, { agentId, action?, scopeRequirements?, requireProof? })` does all of this (`requireProof` defaults to true). `verifyConsentTokenOffline(token, keys, options)` does it for a bare token (without the proof).

| Check | Error |
|---|---|
| Broker signature (ES256 by `kid` from the JWKS), issuer `parafe-trust-broker`, `token_type: consent`, `exclusions` present | `InvalidConsentTokenError` |
| Not expired | `ExpiredConsentTokenError` |
| `target_agent_id` is you (`agentId`) | `WrongAudienceError` |
| The message's `session_id` matches the token's | `InvalidConsentTokenError` |
| `action` is permitted and not excluded | `ScopeViolationError` |
| Scope declared, permissions within it, modality ≥ minimum, `initiator_proof` meets `minimum_initiator_proof` (`scopeRequirements`) | `ScopeViolationError` |
| Presentation proof (required unless `requireProof: false`; always checked when sent): signed by the key in the token's `cnf.jkt`, for this token, its audience and this message, fresh, not replayed | `InvalidProofError` |
| No consent token in the message | `MissingParafeExtensionError` |
| Parafé data present but malformed | `MalformedParafeDataError` |

Hold the broker keys with `createBrokerKeyCache()`: it fetches them on first use and, if a token names a key it doesn't have yet (the broker rotated or added one), refetches once and retries, at most once a minute. There's no network call per message, except the first time an initiator's key is needed to check a proof: it's fetched from the initiator's DID document at the broker and cached (pass `initiatorKey` to avoid even that). Tokens name their initiator (`sub`), their target (`aud`, a DID) and the key they're bound to (`cnf.jkt`); `claims.exclusions` and `claims.initiator_proof` (`pop` or `credential`) say what's forbidden and how the initiator proved itself. A token sent without a presentation proof is refused unless you pass `requireProof: false`. For real-time confirmation on high-value actions, `verifyConsentTokenOnline(token, { action, agentId })` asks the broker.

Every error has a `code`. `parafeErrorData(err)` turns it into the spec's `error` data for your reply, and never leaks the message of an error that isn't ours.

---

## API reference

| Function | Purpose |
|---|---|
| `buildAgentCardExtension({ agentId, scopeRequirements, required, brokerUrl?, minimumIdentityAssurance?, description? })` | Agent card entry |
| `parseAgentCardExtension(extensions)` | Read a card's Parafé entry, or `null` |
| `withParafe(message, data)` | Copy of `message` with Parafé data in metadata and the URI in `extensions` |
| `withConsentToken(message, token, sessionId, proof?)` | Shorthand for `withParafe(message, { consent: … })` |
| `withSessionClosed(message, sessionId, receipt)` / `extractSessionClosed(message)` | Tell the other side the session is over, with the receipt JWS |
| `createPresentationProof(token, privateKey, { messageId? })` | Initiator: the proof to send with a key-bound token |
| `createActionReceiptSigner({ agentId, privateKey, credential, brokerUrl?, agentDid?, file? })` | 2.2: sign (`sign`), file (`file`), both (`record`), receipt a refusal (`refuse`); `flush()` before close |
| `signActionReceipt(privateKey, agentDid, input)` / `fileActionReceipt(receipt, { sessionId, credential, privateKey })` | The same, as functions |
| `withActionReceipts(message, receipts)` / `extractActionReceipts(message)` | Attach the action receipts you signed (beside any other Parafé data, or alone); read them |
| `verifyPresentationProof(proof, token, claims, options?)` | Check a proof yourself |
| `readParafe(message)` | The message's Parafé data, or `null` |
| `extractHandshakeChallenge` / `extractHandshakeComplete` / `extractConsentToken` / `extractParafeError` `(message)` | One member, or `null` |
| `hasParafeData(message)` | Any Parafé data present? |
| `parafeErrorData(err)` | `{ error: { code, message }, action_receipts? }` for a refusal |
| `activationHeaders(a2aVersion?, otherExtensions?)` | HTTP headers that activate the extension |
| `isParafeActivated(headers)` | Did this request activate it? |
| `verifyMessageConsentToken(message, key, options)` | Extract + verify in one step |
| `verifyConsentTokenOffline(token, key, options?)` | Verify a token locally |
| `verifyConsentTokenOnline(token, options)` | Verify via the broker's `/consent/verify` |
| `createBrokerKeyCache(brokerUrl?, { minRefetchIntervalMs? })` | The broker's signing keys, refetched when a token names a new key (use this) |
| `fetchBrokerKeys(brokerUrl?)` | The broker's signing keys (JWKS), fetched once |

Messages can be `@a2a-js/sdk` `Message` objects or raw A2A 1.0 / 0.3 JSON.

---

## Migrating from 2.x

3.0 removes what only older brokers and 1.x senders needed:

- **`requireProof` defaults to true.** A consent token sent without a presentation proof is refused (`InvalidProofError`). Initiators using `@getparafe/sdk` or `createPresentationProof()` already send one. Pass `requireProof: false` to accept tokens without a proof.
- **Broker keys are a JWKS.** `fetchBrokerPublicKey()` and PEM keys are gone: pass `fetchBrokerKeys()` or, better, `createBrokerKeyCache()`. Only ES256 consent tokens verify (the broker has signed ES256 since 2026-09-30).
- **`claims.exclusions` only.** The verifier no longer sets the old `claims.excluded`; a token without `exclusions` is refused.
- **No v1 data.** Readers ignore 1.x-style data parts, `acceptV1` and `ReadParafeOptions` are gone, `parseAgentCardExtension` ignores the v1 URI, and `PARAFE_EXTENSION_URI_V1` and the `PARAFE_V1_*` constants are removed.
- Agent cards may require `minimum_identity_assurance: 'claimed'` (an agent its principal approved).
- Consent token claims name both parties (3.1, broker SPEC-002): `initiator_parties` and `target_parties`, each `{ operator, principal }` (type `Parties`): who runs the agent and who it acts for.

## Migrating from 1.x

2.0 follows A2A 1.0. What changed:

- **Parafé data moved from message parts to message metadata.** `buildConsentTokenPart()`, `buildHandshakeChallenge()` and `buildHandshakeComplete()` are gone. Use `withConsentToken()` / `withParafe()` on the whole message. 1.x data parts were silently emptied by the A2A 1.0 client, and never found by 1.x readers on A2A 1.0 servers.
- **Readers take the whole message**, not `message.parts`: `extractConsentToken(message)`, `verifyMessageConsentToken(message, key, { agentId })`.
- **`agentId` is required** when verifying a message: tokens issued for another agent are rejected (`WrongAudienceError`).
- **New extension URI**: `https://parafe.ai/extensions/a2a/v2`.
- **Activation header**: `A2A-Extensions` on A2A 1.0 (was `X-A2A-Extensions`, now only for A2A 0.3).
- **`required` must be set** in `buildAgentCardExtension`.
- `MalformedDataPartError` is now `MalformedParafeDataError` (`MALFORMED_PARAFE_DATA`). The `/compat` export is removed.

---

## Related

- [Extension specification](https://parafe.ai/extensions/a2a/v2)
- [Parafé SDK](https://github.com/getparafe/sdk) (`@getparafe/sdk`): registration, handshakes, receipts
- [Parafé Platform](https://platform.parafe.ai): agent registration and API keys
- [A2A protocol specification](https://a2a-protocol.org/v1.0.0/specification/)
