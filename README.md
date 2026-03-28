# @getparafe/a2a-extension

Parafe trust extension for the [Google A2A protocol](https://google.github.io/A2A/). Adds cryptographic agent identity and scoped consent verification to A2A agent-to-agent communication.

```
npm install @getparafe/a2a-extension
```

---

## Overview

This extension defines how to add Parafe's cryptographic trust layer to A2A agent communication. When an agent sends a task to another agent, it attaches a **Parafe consent token** — a broker-signed JWT that proves who the requester is, what it is permitted to do, and that it was mutually authenticated before this request was made.

The receiving agent verifies the token using the Parafe broker's **published Ed25519 public key** — no round-trip to a central server required.

```
Agent A                            Agent B
  │                                   │
  │── A2A request ──────────────────▶ │
  │   X-A2A-Extensions: parafe/v1     │
  │   metadata:                       │
  │     agent-id: agent_abc           │  extractExtensionMetadata()
  │     consent-token: eyJ...         │  verifyConsentTokenOffline()
  │     session-id: sess_xyz          │       │
  │                                   │       ▼
  │                                   │  Verify Ed25519 signature
  │                                   │  using Parafe public key
  │                                   │  (no network call needed)
  │                                   │       │
  │◀── A2A response ─────────────────  │       ▼
  │   X-A2A-Extensions: parafe/v1     │  Claims: { sub, scope, exp }
```

---

## Extension URI

The URI of this extension is `https://github.com/getparafe/parafe-a2a-extension/v1`.

This is the only URI accepted for this extension.

---

## Message Metadata Fields

Messages from the client agent MUST include the following metadata fields in `params.metadata`:

| Field | Key |
|---|---|
| Agent ID | `https://github.com/getparafe/parafe-a2a-extension/v1/agent-id` |
| Consent Token | `https://github.com/getparafe/parafe-a2a-extension/v1/consent-token` |
| Session ID | `https://github.com/getparafe/parafe-a2a-extension/v1/session-id` *(recommended)* |

---

## Process

### Client agent MUST:

1. Register with the Parafe broker and obtain an agent ID and Ed25519 credential (via [platform.parafe.ai](https://platform.parafe.ai) or the [Parafe SDK](https://github.com/getparafe/sdk))
2. Perform a Parafe mutual handshake with the target agent to obtain a session ID and consent token
3. Activate this extension via the `X-A2A-Extensions` header (or gRPC metadata value)
4. Include all required metadata fields in `params.metadata`

### Server agent MUST:

1. Validate that all required metadata fields are present — if any are missing, return an error
2. Verify the consent token using either:
   - **Offline:** the Parafe broker's published Ed25519 public key at `https://api.parafe.ai/public-key` (recommended — no network call required)
   - **Online:** the Parafe broker's `/consent/verify` endpoint
3. If verification fails, return an error
4. If verification passes, process the task and echo the `X-A2A-Extensions` header on the response

---

## Extension Activation

Clients activate this extension by including the Extension URI via the transport-defined mechanism:

- **JSON-RPC / HTTP:** set the `X-A2A-Extensions` HTTP header to the Extension URI
- **gRPC:** set `X-A2A-Extensions` as a metadata value

---

## Why Offline Verification

Most agent trust layers route every verification through their own server. If that server is slow, down, or compromised, your agents are blocked.

Parafe consent tokens are **self-contained JWTs signed by the broker's Ed25519 key**. Fetch the broker's public key once at startup, cache it, and verify every token locally. No server call needed per request.

- Zero latency overhead per request
- No runtime dependency on Parafe's availability for verification
- The token is independently verifiable by anyone with the public key

---

## Setup

Before using this extension, you need:

1. A Parafe account — sign up at [platform.parafe.ai](https://platform.parafe.ai)
2. A registered agent with an Ed25519 key pair (via the [Parafe SDK](https://github.com/getparafe/sdk))
3. A consent token minted via the Parafe SDK's handshake flow

---

## Usage

### Requesting Agent (sending tasks)

```typescript
import { ParafeClient } from '@getparafe/sdk';
import {
  buildExtensionMetadata,
  getAgentCardExtension,
  activationHeaderValue,
} from '@getparafe/a2a-extension';

// 1. Initialize Parafe and load your agent credentials
const parafe = new ParafeClient({
  brokerUrl: 'https://api.parafe.ai',
  apiKey: 'prf_key_live_...',
});
await parafe.loadCredentials('./parafe-credentials.enc', 'your-passphrase');

// 2. Declare the extension in your AgentCard
const agentCard = {
  name: 'My Agent',
  capabilities: {
    extensions: [getAgentCardExtension()],
  },
};

// 3. Perform a Parafe handshake with the target agent to get a session + consent token
const { handshakeId, challengeForTarget } = await parafe.handshake({
  targetAgentId: 'prf_agent_target_id',  // The agent you're about to call via A2A
  scope: 'your-scope',
  permissions: ['read:data'],
  authorization: ParafeClient.authorization.autonomous(),
});

// Send handshakeId + challengeForTarget to the target agent out-of-band,
// then receive back their completed handshake response.
// (How you exchange this depends on your transport — HTTP, message queue, etc.)

const { sessionId, consentToken } = await parafe.completeHandshake({
  handshakeId,
  challengeNonce: challengeForTarget,
});

// 4. Build the Parafe metadata and attach it to your A2A request
const parafeMetadata = buildExtensionMetadata({
  agentId: parafe.credentialStatus().agentId,
  consentToken: consentToken.token,
  sessionId, // strongly recommended — enables audit trail and signed receipts
});

// 5. Send the A2A task with Parafe trust metadata
await a2aClient.sendTask({
  params: {
    metadata: { ...parafeMetadata },
    // ...rest of your task params
  },
  headers: {
    'X-A2A-Extensions': activationHeaderValue,
  },
});
```

---

### Executing Agent (receiving tasks)

```typescript
import {
  extractExtensionMetadata,
  verifyConsentTokenOffline,
  fetchBrokerPublicKey,
  MissingParafeExtensionError,
  InvalidConsentTokenError,
  ExpiredConsentTokenError,
  ScopeViolationError,
} from '@getparafe/a2a-extension';

// At startup — fetch and cache the broker public key
const brokerPublicKey = await fetchBrokerPublicKey();

// On each incoming A2A task
async function handleTask(task) {
  // 1. Extract Parafe fields from metadata
  let parafe;
  try {
    parafe = extractExtensionMetadata(task.params.metadata ?? {});
  } catch (err) {
    if (err instanceof MissingParafeExtensionError) {
      // Request has no Parafe metadata — reject or handle as untrusted
      return { error: 'Parafe trust extension required' };
    }
    throw err;
  }

  // 2. Verify the consent token offline
  let claims;
  try {
    claims = await verifyConsentTokenOffline(
      parafe.consentToken,
      brokerPublicKey,
      'read:data' // optional: assert a required scope
    );
  } catch (err) {
    if (err instanceof ExpiredConsentTokenError) {
      return { error: 'Consent token expired — request a new one' };
    }
    if (err instanceof InvalidConsentTokenError) {
      return { error: 'Invalid consent token' };
    }
    if (err instanceof ScopeViolationError) {
      return { error: `Insufficient scope: ${err.message}` };
    }
    throw err;
  }

  // 3. claims is now verified — proceed with the task
  console.log('Verified agent:', claims.sub);
  console.log('Granted scopes:', claims.scope);
  console.log('Session:', parafe.sessionId);

  // ... do the work
}
```

---

### Online Verification (optional)

For high-value actions where you want real-time confirmation from the broker:

```typescript
import { verifyConsentTokenOnline } from '@getparafe/a2a-extension';

const claims = await verifyConsentTokenOnline(parafe.consentToken, {
  brokerUrl: 'https://api.parafe.ai',
  requiredScope: 'write:data',
});
```

---

## API Reference

### Requester

| Export | Description |
|---|---|
| `buildExtensionMetadata(options)` | Returns namespaced metadata fields for `params.metadata` |
| `getAgentCardExtension()` | Returns the AgentCard `capabilities.extensions[]` entry |
| `activationHeaderValue` | String value for the `X-A2A-Extensions` header |

### Executor

| Export | Description |
|---|---|
| `extractExtensionMetadata(metadata)` | Extracts Parafe fields; throws `MissingParafeExtensionError` if absent |
| `verifyConsentTokenOffline(token, publicKey, scope?)` | Verifies Ed25519 JWT signature locally — no network call |
| `verifyConsentTokenOnline(token, options?)` | Verifies via broker's `/consent/verify` endpoint |
| `fetchBrokerPublicKey(brokerUrl?)` | Fetches broker's Ed25519 public key for offline verification |

### Errors

| Error | Code | When thrown |
|---|---|---|
| `MissingParafeExtensionError` | `MISSING_PARAFE_EXTENSION` | Required metadata fields absent |
| `InvalidConsentTokenError` | `INVALID_CONSENT_TOKEN` | Signature invalid or JWT malformed |
| `ExpiredConsentTokenError` | `EXPIRED_CONSENT_TOKEN` | Token past expiry |
| `ScopeViolationError` | `SCOPE_VIOLATION` | Token does not cover required scope |

---

## Related

- [Parafe SDK](https://github.com/getparafe/sdk) — `@getparafe/sdk` — full trust lifecycle (handshake, consent, receipts)
- [Parafe Platform](https://platform.parafe.ai) — agent registration and API key management
- [Parafe Docs](https://parafe.ai) — full documentation
