# @getparafe/a2a-extension

Parafe trust extension for the [Google A2A protocol](https://google.github.io/A2A/). Adds cryptographic agent identity, scoped consent, and handshake lifecycle to A2A agent-to-agent communication via DataParts.

```
npm install @getparafe/a2a-extension
```

---

## Overview

This extension defines how to add Parafe's cryptographic trust layer to A2A agent communication. Trust data flows as **A2A DataParts** inside the message `parts[]` array — the same pattern used by A2A's built-in data types.

Three DataPart types cover the full trust lifecycle:

| DataPart | When used | Direction |
|---|---|---|
| `parafe.handshake.Challenge` | Handshake initiation | Initiator → Target |
| `parafe.handshake.Complete` | Handshake completion | Target → Initiator |
| `parafe.trust.ConsentToken` | Every message during direct exchange | Both directions |

---

## Extension URI

The URI of this extension is `https://github.com/getparafe/parafe-a2a-extension/v1`.

This is the only URI accepted for this extension.

---

## Agent Card Format

Agents that require Parafe trust declare the extension in their AgentCard with scope requirements:

```json
{
  "uri": "https://github.com/getparafe/parafe-a2a-extension/v1",
  "required": true,
  "params": {
    "agent_id": "prf_agent_donuts01",
    "agent_did": "did:web:api.parafe.ai:agents:prf_agent_donuts01",
    "broker_url": "https://api.parafe.ai",
    "minimum_identity_assurance": "self_registered",
    "scope_requirements": {
      "check-menu": {
        "permissions": ["read_menu", "read_availability"],
        "minimum_authorization_modality": "autonomous"
      },
      "order-donuts": {
        "permissions": ["read_menu", "create_order", "process_payment"],
        "minimum_authorization_modality": "attested"
      }
    }
  }
}
```

This tells discovering agents: which broker to use, what scopes are available, and what authorization level each scope requires.

---

## Process

### Client agent MUST:

1. Fetch the target's AgentCard and discover the Parafe extension entry
2. Register with the Parafe broker (via the [Parafe SDK](https://github.com/getparafe/sdk) or raw API)
3. Initiate a handshake with the broker, receive a challenge nonce
4. Send the challenge to the target as a `parafe.handshake.Challenge` DataPart
5. Receive the consent token from the target as a `parafe.handshake.Complete` DataPart
6. Include a `parafe.trust.ConsentToken` DataPart in every subsequent message

### Server agent MUST:

1. Declare the Parafe extension in its AgentCard with scope requirements
2. Extract and validate `parafe.handshake.Challenge` DataParts from incoming messages
3. Sign the challenge with its private key and complete the handshake with the broker
4. Return the consent token as a `parafe.handshake.Complete` DataPart
5. On every subsequent message, extract and verify the `parafe.trust.ConsentToken` DataPart
6. Verify offline using the broker's Ed25519 public key (recommended) or online via `/consent/verify`
7. If verification fails, reject the message

---

## Extension Activation

Clients activate this extension by including the Extension URI via the transport-defined mechanism:

- **JSON-RPC / HTTP:** set the `X-A2A-Extensions` HTTP header to the Extension URI
- **gRPC:** set `X-A2A-Extensions` as a metadata value

---

## Why Offline Verification

Parafe consent tokens are **W3C Verifiable Digital Credentials (VDCs)** — self-contained JWTs signed by the broker's Ed25519 key. Fetch the broker's public key once at startup, cache it, and verify every token locally. No server call needed per request.

- Zero latency overhead per request
- No runtime dependency on Parafe's availability for verification
- Independently verifiable by anyone with the public key

---

## Setup

Before using this extension, you need:

1. A Parafe account — sign up at [platform.parafe.ai](https://platform.parafe.ai)
2. A registered agent with an Ed25519 key pair (via the [Parafe SDK](https://github.com/getparafe/sdk))
3. A handshake completed via the Parafe SDK to obtain a consent token

---

## Usage

### Declaring the Extension (AgentCard)

```typescript
import { buildAgentCardExtension } from '@getparafe/a2a-extension';

const agentCard = {
  name: 'Agent Donuts',
  capabilities: {
    extensions: [
      buildAgentCardExtension({
        agentId: 'prf_agent_donuts01',
        scopeRequirements: {
          'check-menu': {
            permissions: ['read_menu', 'read_availability'],
            minimum_authorization_modality: 'autonomous',
          },
          'order-donuts': {
            permissions: ['read_menu', 'create_order', 'process_payment'],
            minimum_authorization_modality: 'attested',
          },
        },
      }),
    ],
  },
};
```

### Discovering Parafe Requirements

```typescript
import { parseAgentCardExtension } from '@getparafe/a2a-extension';

const agentCard = await fetchAgentCard('https://agentdonuts.com/.well-known/agent.json');
const parafe = parseAgentCardExtension(agentCard.capabilities.extensions);

if (parafe) {
  console.log('Broker URL:', parafe.params.broker_url);
  console.log('Target agent:', parafe.params.agent_id);
  console.log('Scopes:', Object.keys(parafe.params.scope_requirements));
}
```

### Initiating a Handshake (Requesting Agent)

```typescript
import { ParafeClient } from '@getparafe/sdk';
import { buildHandshakeChallenge } from '@getparafe/a2a-extension';

// 1. Perform the handshake with the Parafe broker
const { handshakeId, challengeForTarget } = await parafe.handshake({
  targetAgentId: parafe.params.agent_id,
  scope: 'order-donuts',
  permissions: ['read_menu', 'create_order'],
  authorization: ParafeClient.authorization.attested({
    instruction: 'go get me donuts',
    platform: 'whatsapp',
  }),
});

// 2. Send the challenge to the target as an A2A DataPart
const message = {
  role: 'user',
  parts: [
    buildHandshakeChallenge({
      handshake_id: handshakeId,
      challenge: challengeForTarget,
      initiator_agent_id: parafe.credentialStatus().agentId,
      broker_url: 'https://api.parafe.ai',
      requested_scope: 'order-donuts',
    }),
  ],
};
```

### Completing a Handshake (Receiving Agent)

```typescript
import {
  extractHandshakeChallenge,
  buildHandshakeComplete,
} from '@getparafe/a2a-extension';

// 1. Extract the challenge from the incoming A2A message
const challenge = extractHandshakeChallenge(incomingMessage.parts);
if (!challenge) {
  // Not a handshake message — handle normally
}

// 2. Sign the challenge and complete with the broker (via SDK)
const { sessionId, consentToken } = await parafe.completeHandshake({
  handshakeId: challenge.handshake_id,
  challengeNonce: challenge.challenge,
});

// 3. Send the consent token back as an A2A DataPart
const response = {
  role: 'agent',
  parts: [
    buildHandshakeComplete({
      handshake_id: challenge.handshake_id,
      status: 'authenticated',
      consent_token: consentToken.token,
    }),
  ],
};
```

### Sending Messages with Trust (Direct Exchange)

```typescript
import { buildConsentTokenPart } from '@getparafe/a2a-extension';

// Include the consent token DataPart in every message
const message = {
  role: 'user',
  parts: [
    buildConsentTokenPart(consentToken.token, sessionId),
    { kind: 'text', text: "I'd like 2 dozen assorted donuts delivered by 2pm." },
  ],
};
```

### Verifying Incoming Messages

```typescript
import {
  verifyMessageConsentToken,
  fetchBrokerPublicKey,
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
} from '@getparafe/a2a-extension';

// At startup — fetch and cache the broker public key
const brokerPublicKey = await fetchBrokerPublicKey();

// On each incoming message — extract + verify in one step
async function handleMessage(message) {
  try {
    const { claims, sessionId } = await verifyMessageConsentToken(
      message.parts,
      brokerPublicKey,
      'create_order' // optional: assert a required action
    );

    console.log('Scope:', claims.scope);                     // "order-donuts"
    console.log('Permissions:', claims.permissions);          // ["read_menu", "create_order"]
    console.log('Authorization:', claims.authorization_modality); // "attested"
    console.log('Session:', sessionId);

    // Token verified — process the message
  } catch (err) {
    if (err instanceof MissingParafeExtensionError) {
      return { error: 'Parafe trust extension required' };
    }
    if (err instanceof ExpiredConsentTokenError) {
      return { error: 'Consent token expired' };
    }
    if (err instanceof InvalidConsentTokenError) {
      return { error: 'Invalid consent token' };
    }
    if (err instanceof ScopeViolationError) {
      return { error: `Action not permitted: ${err.message}` };
    }
    throw err;
  }
}
```

### Online Verification (optional)

For high-value actions where you want real-time confirmation from the broker:

```typescript
import { verifyConsentTokenOnline } from '@getparafe/a2a-extension';

const result = await verifyConsentTokenOnline(consentToken.token, {
  action: 'process_payment',
  sessionId: sessionId,
});
// result.valid, result.permitted, result.action, result.expiresAt
```

---

## API Reference

### DataPart Builders

| Function | Returns |
|---|---|
| `buildHandshakeChallenge(payload)` | `HandshakeChallengeDataPart` |
| `buildHandshakeComplete(payload)` | `HandshakeCompleteDataPart` |
| `buildConsentTokenPart(token, sessionId)` | `ConsentTokenDataPart` |

### DataPart Parsers

| Function | Returns |
|---|---|
| `extractHandshakeChallenge(parts)` | `HandshakeChallengePayload \| null` |
| `extractHandshakeComplete(parts)` | `HandshakeCompletePayload \| null` |
| `extractConsentToken(parts)` | `ConsentTokenPayload \| null` |
| `hasParafeDataPart(parts)` | `boolean` |

### AgentCard

| Function | Returns |
|---|---|
| `buildAgentCardExtension(options)` | `ParafeAgentCardExtension` |
| `parseAgentCardExtension(extensions)` | `ParafeAgentCardExtension \| null` |

### Verification

| Function | Description |
|---|---|
| `verifyMessageConsentToken(parts, publicKey, action?)` | Extract + verify consent token from message parts |
| `verifyConsentTokenOffline(token, publicKey, action?)` | Verify Ed25519 JWT signature locally |
| `verifyConsentTokenOnline(token, options)` | Verify via broker's `/consent/verify` endpoint |
| `fetchBrokerPublicKey(brokerUrl?)` | Fetch broker's Ed25519 public key |

### Errors

| Error | Code | When thrown |
|---|---|---|
| `MissingParafeExtensionError` | `MISSING_PARAFE_EXTENSION` | Required DataPart absent |
| `InvalidConsentTokenError` | `INVALID_CONSENT_TOKEN` | Signature invalid or JWT malformed |
| `ExpiredConsentTokenError` | `EXPIRED_CONSENT_TOKEN` | Token past expiry |
| `ScopeViolationError` | `SCOPE_VIOLATION` | Action not permitted or excluded |
| `MalformedDataPartError` | `MALFORMED_DATA_PART` | DataPart key present but payload invalid |

---

## Migration from v0.2.0

v1.0.0 replaces `params.metadata` with A2A DataParts. For backwards compatibility during migration:

```typescript
import {
  buildExtensionMetadata,
  extractExtensionMetadata,
} from '@getparafe/a2a-extension/compat';
```

The compat module is deprecated and will be removed in v2.0.0.

---

## Related

- [Parafe SDK](https://github.com/getparafe/sdk) — `@getparafe/sdk` — full trust lifecycle (handshake, consent, receipts)
- [Parafe Platform](https://platform.parafe.ai) — agent registration and API key management
- [Parafe Docs](https://parafe.ai) — full documentation
