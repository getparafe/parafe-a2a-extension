# PRD: Parafe A2A Extension (`@getparafe/a2a-extension`)

**Version:** 1.0 — Draft
**Date:** March 28, 2026
**Author:** Faris Armaly / Parafe

---

## Problem Statement

AI agents are increasingly built on Google's A2A protocol, which defines how agents communicate but provides no standard for establishing trust between them. Developers building multi-agent systems have no way to verify the identity of agents they receive tasks from, enforce scoped permissions on what those agents are allowed to request, or produce auditable proof that an interaction was authorized. Without a trust layer, A2A agents must either blindly trust all incoming requests or build proprietary verification logic themselves — neither of which scales. As A2A adoption grows, Parafe must be present in that ecosystem as the default trust layer.

---

## Goals

1. **Ecosystem presence** — Have `@getparafe/a2a-extension` listed and referenced alongside other A2A extensions (Identity Machines, Twilio, Google Traceability) within 60 days of launch
2. **Zero-friction adoption** — A developer already using Parafe SDK can add A2A trust to an existing agent in under 30 minutes
3. **Offline verifiability** — The receiving agent can verify a Parafe consent token without a server round-trip, using the broker's published public key — a demonstrable architectural advantage over Identity Machines
4. **Standard compliance** — The extension follows the A2A extension spec exactly: URI declaration in AgentCard, header activation, namespaced metadata fields — passing any A2A-conformant validator
5. **Developer education** — The README positions Parafe's approach (cryptographic, broker-neutral) vs. centralized alternatives, making the architectural distinction clear to developers evaluating trust options

---

## Non-Goals

**v1 will NOT include:**

- **Python package** — A2A is multi-language but our stack is Node.js/TypeScript. A Python package is a fast follow but not v1; we ship where our SDK already exists
- **Inline policy evaluation** — Iron Book evaluates OPA/Rego policies as part of their extension. We do not; Parafe consent tokens are pre-minted by the broker and carry their own scope. Policy definition happens at agent registration time, not at request time
- **A2A agent hosting or scaffolding** — We are building a trust extension, not an agent framework. We do not provide base agent classes, routing, or task handlers
- **Browser/frontend support** — A2A agents are server-side processes. No browser bundle needed
- **Automated token refresh** — v1 requires the developer to manage consent token lifecycle. Token refresh helpers are a v2 consideration

---

## User Stories

### Developer: Building a requesting agent (sends tasks to other agents)

- As an A2A agent developer, I want to attach a Parafe consent token to my outgoing A2A requests so that the receiving agent can verify my identity and permissions without calling a central server
- As an A2A agent developer, I want a helper function that builds the correct `params.metadata` fields from my agent ID and consent token so that I don't need to manually construct namespaced keys
- As an A2A agent developer, I want my AgentCard to automatically declare the Parafe extension URI so that receiving agents know they can expect Parafe trust metadata from me

### Developer: Building an executing agent (receives tasks from other agents)

- As an A2A agent developer, I want to extract and validate a Parafe consent token from an incoming A2A request's metadata so that I can verify the requester's identity and permissions before proceeding
- As an A2A agent developer, I want to verify offline (using Parafe's published public key) that a consent token is authentic and has not been tampered with, so that my agent can operate without runtime dependency on Parafe's API
- As an A2A agent developer, I want clear error types when verification fails (expired token, wrong scope, invalid signature, missing metadata) so that I can handle trust failures gracefully
- As an A2A agent developer, I want to optionally call Parafe's `/consent/verify` endpoint for online confirmation when my use case requires it, so that I have both offline and online verification paths

### Enterprise operator: Auditing agent interactions

- As an operator of A2A agents, I want every interaction to reference a Parafe session ID so that I can cross-reference A2A traffic with Parafe's signed interaction receipts
- As an operator, I want receiving agents to record interactions via the Parafe SDK when a session is active so that I have a tamper-proof audit trail of authorized actions

---

## Requirements

### Must-Have (P0)

**Extension constants package**
- `PARAFE_EXTENSION_URI` — the canonical, versioned URI used in AgentCard and `X-A2A-Extensions` header (e.g., `https://github.com/getparafe/a2a-extension/v1`)
- Metadata field name constants: `PARAFE_AGENT_ID_FIELD`, `PARAFE_CONSENT_TOKEN_FIELD`, `PARAFE_SESSION_ID_FIELD`
- Acceptance criteria: constants match the extension URI format used in A2A ecosystem (`https://` URI prefix, namespaced field keys using full URI)

**Requester helpers**
- `buildExtensionMetadata({ agentId, consentToken, sessionId? })` — returns a metadata object with correctly namespaced keys, ready to merge into `params.metadata`
- `getAgentCardExtension()` — returns the extension entry for an AgentCard's `capabilities.extensions[]`
- `activationHeader` — the string value for the `X-A2A-Extensions` header
- Acceptance criteria: output conforms to A2A extension spec; no runtime calls to Parafe broker required

**Executor helpers**
- `extractExtensionMetadata(params.metadata)` — pulls and validates presence of Parafe fields from incoming metadata; returns typed object or throws `MissingParafeExtensionError`
- `verifyConsentTokenOffline(token, brokerPublicKey)` — verifies Ed25519 JWT signature without a network call; returns decoded token claims or throws `InvalidConsentTokenError`
- `verifyConsentTokenOnline(token, options)` — calls Parafe's `/consent/verify` endpoint; returns decision or throws with reason
- Acceptance criteria: offline verification works with a cached broker public key; online verification surfaces Parafe's error response correctly

**Error types**
- `MissingParafeExtensionError` — required metadata fields absent
- `InvalidConsentTokenError` — signature invalid or JWT malformed
- `ExpiredConsentTokenError` — token past expiry
- `ScopeViolationError` — token does not cover the requested scope
- Acceptance criteria: each error type is a named class, catchable distinctly, with a human-readable `.message` and a machine-readable `.code`

**TypeScript types**
- `ParafeExtensionMetadata` — typed shape of the metadata object
- `ParafeConsentClaims` — typed decoded JWT claims from a verified token
- `ParafeAgentCardExtension` — typed AgentCard extension entry

**README**
- Full usage guide: requester side, executor side
- Code samples for both sides (copy-pasteable)
- Explicit section explaining offline verification via public key (with architecture diagram or ASCII flow)
- Side-by-side comparison note explaining why Parafe tokens are verifiable without a server round-trip (unlike centralized alternatives)
- Acceptance criteria: a developer with no prior Parafe knowledge can integrate in under 30 minutes following the README alone

---

### Nice-to-Have (P1)

- **`fetchBrokerPublicKey(brokerUrl)`** — convenience helper to fetch and cache the broker's Ed25519 public key from `/public-key`, refreshing on a configurable TTL
- **`requireParafeExtension()`** — Express/Hono middleware that automatically validates the Parafe extension on incoming A2A requests and attaches the decoded claims to `req.parafe`
- **Integration example repo** — a minimal two-agent demo (TypeScript, no real LLM calls) showing the full round-trip; equivalent to Identity Machines' `a2a_ironbook` demo
- **Published on npm** — `@getparafe/a2a-extension` visible on npmjs.com with correct keywords (`a2a`, `agent-to-agent`, `trust`, `parafe`)

---

### Future Considerations (P2)

- **Python package** — `parafe-a2a-extension` on PyPI, same semantics. Required for full A2A ecosystem coverage since many A2A agents are Python
- **Token refresh helper** — automatically re-mint a consent token before expiry within a long-running A2A session
- **Scoped token minting shortcut** — convenience method that calls the Parafe broker to mint a consent token scoped to a specific A2A target agent, reducing boilerplate for common patterns
- **MCP tool wrapper** — expose Parafe A2A verification as an MCP tool, so any MCP-compatible agent can use it without SDK integration
- **Google A2A extension registry submission** — formal submission to Google's A2A extension directory if one is established

---

## Success Metrics

### Leading (first 30 days post-launch)
- **npm installs** — 50+ installs/week within 30 days (baseline: zero; comparable early-stage dev tools)
- **GitHub stars** — 25+ stars on `getparafe/a2a-extension` within 30 days
- **Integration time** — internal test: an engineer unfamiliar with the code completes a working integration in < 30 minutes following only the README
- **Zero breaking issues** — no bug reports or issues filed against incorrect verification behavior

### Lagging (60-90 days post-launch)
- **Inbound mention** — Parafe referenced alongside Identity Machines/Twilio in at least one external A2A ecosystem resource (article, newsletter, documentation list)
- **Broker activations** — at least 5 new organizations whose first Parafe interaction came through the A2A extension (tracked via API key creation source)
- **Developer conversion** — 25% of developers who install `@getparafe/a2a-extension` also create a Parafe account within 30 days

---

## Open Questions

| Question | Owner | Blocking? |
|---|---|---|
| What should the canonical extension URI be? Options: `https://github.com/getparafe/a2a-extension/v1` (mirrors Identity Machines' pattern) or a docs URL like `https://docs.parafe.ai/a2a-extension/v1`. URI must be stable — cannot change after agents start advertising it | Faris | Yes, before repo creation |
| Should `verifyConsentTokenOffline` accept a raw public key string, or a `CryptoKey` object, or both? Impacts developer ergonomics | Engineering | Yes, before API design |
| Do we want the extension to require an active Parafe session (session_id mandatory), or is a consent token alone sufficient for v1? Requiring session_id gives us better audit trails but adds friction | Faris | Yes, shapes P0 requirements |
| Should the integration demo use Google's official `a2a-sdk` npm package as a peer dependency, or stay dependency-free? Google's SDK may add weight and churn risk for v0.0.x | Engineering | No, can decide during build |
| Do we register this extension with any formal A2A extension registry? Google's article implies the ecosystem is community-driven but doesn't specify a registry | Faris | No |

---

## Timeline Considerations

- **No hard deadline** — this is a strategic ecosystem play, not a customer commitment
- **Dependency:** Requires `@getparafe/sdk` to be stable (it is — v1 published, 41 tests passing)
- **Dependency:** A2A extension URI must be decided before any code is written (it's baked into constants)
- **Suggested phasing:**
  - **Phase 1 (ship):** New repo, package with P0 requirements, README, npm publish
  - **Phase 2 (amplify):** Integration demo repo, P1 middleware helper, outreach to A2A community
  - **Phase 3 (expand):** Python package, token refresh helpers, MCP wrapper

---

## Decisions Needed Before Build Starts

1. **Extension URI** — stable, public, versioned URL
2. **Session ID: required or optional** — shapes the API surface
3. **New repo vs. monorepo** — recommendation is new repo `getparafe/a2a-extension`
