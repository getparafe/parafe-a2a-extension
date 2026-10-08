# Changelog

## 3.2.0 (2026-10-08)

Additive. Broker SPEC-003 part 2 (MUSE-24): an agent card can state who the initiator must be and which AP2 mandate issuers a scope trusts, as fields rather than prose.

- `ScopeRequirement` gains optional `minimum_identity_assurance`, `minimum_verification_tier`, `exclusions` and `trusted_issuers` (`TrustedIssuerRef[]`: `{ name?, iss?, kid?, jkt }`, the issuer named by its RFC 7638 key thumbprint).
- `scopeRequirementsFromPolicies(scopePolicies)` builds the card's `scope_requirements` from the agent's broker scope policies (`GET /agents/{id}/scope-policies`), so the card says what the broker enforces and can't drift from it.
- `parseAgentCardExtension()` refuses a card with an unknown tier or assurance, non-list `exclusions`, or a trusted issuer without `jkt`.

## 3.1.0 (2026-10-01)

Additive. Broker SPEC-002 (operator and principal): consent tokens name who runs each agent (its *operator*) and who it acts for (its *principal*).

- `ParafeConsentClaims` gains `initiator_parties` and `target_parties` (new exported type `Parties`: `{ operator: { type, id? } | null, principal: { type, id?, ref? } | null }`). A person's user ID is never shown; an org shows its `id`; a platform's user (`external`) shows the platform's opaque `ref`.

## 3.0.0 (2026-09-30)

Breaking. Removes what only older brokers and 1.x senders needed (no one runs them). See "Migrating from 2.x" in the README.

- **`requireProof` defaults to true** (AP2 change request Part 7): `verifyMessageConsentToken` refuses a consent token sent without a presentation proof. `requireProof: false` accepts one.
- **Broker keys: JWKS only.** `fetchBrokerPublicKey()`, PEM keys and the `fetchBrokerKeys()` fallback for brokers without a JWKS are removed; only ES256 consent tokens verify.
- **`exclusions` only.** The verifier no longer sets `claims.excluded` (removed from `ParafeConsentClaims`) and refuses a token without `exclusions`; action receipts read `exclusions` only.
- **No v1 data.** `readParafe()` and the extractors read message metadata only (`acceptV1` and `ReadParafeOptions` removed); `parseAgentCardExtension()` ignores the v1 URI; `PARAFE_EXTENSION_URI_V1` and `PARAFE_V1_*` removed.
- **Fix:** agent cards may declare `minimum_identity_assurance: 'claimed'`; `parseAgentCardExtension()` used to return `null` for them.

## 2.3.0 (2026-09-30)

For the Parafé broker's AP2 v0.2 interop (AP2 change request Phase 3). Backward compatible.

- **`delegated` modality** (broker B8). The broker's new level, an AP2 open-mandate chain it checked, ranks between `attested` and `verified` in the offline scope check and in agent-card scope requirements (a 2.2 reader refuses `delegated` tokens against any declared scope, and cards that require it). Consent claims gain `mandate_refs`.
- **AP2 Checkout and Payment Receipts** (A3). `signAp2Receipt(privateKey, { kind, mandate, iss, orderId | paymentId …, error?, errorDescription? })` signs an AP2 v0.2 receipt (ES256, P-256 key), for rejections too; `reference` is the AP2 SDK's form by default (`referenceForm: 'sd_hash'` for the spec's) and `references` gives both (`ap2MandateReferences()`). The action receipt signer's `ap2Receipt(sessionId, input)` signs and files it in the session index. The AP2 Python SDK's `ReceiptClient.verify_receipt` accepts these receipts.
- **The A3 mandate check on acknowledgments.** `fileActionReceipt()` results carry `reference_verified`, `mandate_ref`, `mandate_verified_by` and `mandate_issuer_source` (null when the receipt names no mandate).
- **AP2 artifacts in A2A messages** (A4, **provisional**). `withAp2(message, { checkoutMandate, paymentMandate, checkoutReceipt, paymentReceipt })` / `readAp2(message)` carry them in data parts under the AP2 samples' keys (`ap2.mandates.CheckoutMandateSdJwt`, `ap2.mandates.PaymentMandateSdJwt`, `ap2.PaymentReceipt`; `ap2.CheckoutReceipt` is ours), in the message's part shape (A2A 1.0, 0.3 or `@a2a-js/sdk`), and add `AP2_EXTENSION_URI` (`https://github.com/google-agentic-commerce/ap2/v1`, what the samples declare) to `extensions`. `buildAp2AgentCardExtension()` for the card. AP2 v0.2 has no normative A2A binding; this follows its samples and may change.

## 2.2.0 (2026-09-30)

For the Parafé broker's action receipts (AP2 change request B6). Backward compatible: a 2.1 reader ignores `action_receipts` beside another member, but refuses a message whose only Parafé data is `action_receipts`, so move clients to 2.2 before agents send receipts alone.

- **Action receipts.** `createActionReceiptSigner({ agentId, privateKey, credential })` signs what your agent did or refused (`typ: parafe-action-receipt+jwt`, signed with its own key, bound to the consent token by hash) and files each receipt with the broker in the background (`POST /sessions/:id/action-receipts`, credential + proof of possession); `flush()` waits for filings before you close. `signActionReceipt()`, `fileActionReceipt()` and `actionErrorFor()` as functions.
- **Refusals are receipted automatically.** `verifyMessageConsentToken(..., { receipts })`: when the consent check fails, an error receipt (`excluded`, `not_permitted`, `consent_expired`, `proof_invalid`, `consent_invalid`) is signed, filed and attached to the thrown error (`err.actionReceipt`); `parafeErrorData(err)` returns it in `action_receipts`. On success the result has `completeAction(outcome)` and `consentToken`.
- **Reputation floors in `ScopeRequirement`** (broker B18): `minimum_tenure_days`, `minimum_session_completion_rate`, `maximum_denied_requests_30d`, `minimum_unique_counterparties`, `minimum_handshake_success_rate`, for agent cards. The broker enforces them at the handshake when they're in the agent's registered policy; a token can't carry them, so the offline check doesn't.
- **Forward compatible reading.** `readParafe()` ignores members it doesn't know; Parafé data with only unknown members reads as `null` (no Parafé data) instead of throwing. An empty object is still malformed.
- **`action_receipts` message data.** A list of action receipt JWSs beside any member (`error`, `handshake_complete` …) or alone, so one reply can carry every receipt of a turn. `withActionReceipts()` / `extractActionReceipts()`; `withParafe()` keeps receipts already attached. New type `ParafeMessageMember`.

## 2.1.1 (2026-09-30)

- `createBrokerKeyCache()`: broker keys that refresh themselves. When a token names a key the cache doesn't have (the broker rotated or added a key), it refetches the JWKS once and retries, at most once per minute. Accepted wherever broker keys are (`verifyConsentTokenOffline`, `verifyMessageConsentToken`). A plain `fetchBrokerKeys()` result never updates, so a long-running agent that cached it rejected tokens signed by a newer key (SoHo Donuts FRICTION #68).

## 2.1.0 (2026-09-30)

For the Parafé broker's 2026-09-30 formats (AP2 change request Phase 1). Backward compatible.

- **Broker keys by `kid`.** `fetchBrokerKeys()` returns the broker's JWKS; `verifyConsentTokenOffline` and `verifyMessageConsentToken` take it and verify ES256 tokens by `kid` (EdDSA tokens still verify). A PEM key from `fetchBrokerPublicKey()` still works for tokens issued before 2026-09-30, and says what to do when given an ES256 token. On an older broker, `fetchBrokerKeys()` returns its single Ed25519 key.
- **Consent token v2.** Claims `exclusions` (older tokens: `excluded`; the verifier sets both), `sub`, `aud` (target DID), `cnf.jkt`, `jti`, `initiator_proof`, `initiator_proof_at`. `ScopeRequirement.minimum_initiator_proof` is enforced when declared.
- **Presentation proofs (key binding).** `createPresentationProof(token, privateKey, { messageId })` for initiators; `withConsentToken(message, token, sessionId, proof)` carries it (`consent.proof`). `verifyMessageConsentToken` checks a proof whenever one is sent (key in `cnf.jkt`, fetched from the initiator's DID document unless `initiatorKey` is given; token hash; audience; message ID; 5-minute freshness; single use) and refuses a missing proof with `requireProof: true` (default in 3.0). New `InvalidProofError` (code `INVALID_PROOF`). `verifyConsentTokenOnline` passes `proof` to the broker and reports `keyBound`/`proofVerified`.
- **`session_closed` message.** `withSessionClosed()` / `extractSessionClosed()` carry the session receipt (a JWS) to the participant that didn't close.

## 2.0.0 (2026-09-27)

Follows A2A protocol 1.0. Breaking. See "Migrating from 1.x" in the README.

- New extension URI `https://parafe.ai/extensions/a2a/v2`, where the specification is hosted.
- Parafé data moves from message parts to `message.metadata[<extension URI>]`, with the URI listed in `message.extensions`. Keeps consent tokens out of the content agents feed to language models. 1.x parts were silently emptied by the A2A 1.0 client and never found by 1.x readers on A2A 1.0 servers.
- Writing: `withParafe()`, `withConsentToken()`, `parafeErrorData()`. Replaces `buildHandshakeChallenge()`, `buildHandshakeComplete()`, `buildConsentTokenPart()`.
- Reading: `readParafe()`, `extractHandshakeChallenge()`, `extractHandshakeComplete()`, `extractConsentToken()`, `extractParafeError()`, `hasParafeData()` take the whole message. They also read 1.x data parts in all three wire shapes (A2A 0.3, A2A 1.0, `@a2a-js/sdk`) until 2027-03-31 (`acceptV1: false` to disable).
- Verification: `verifyMessageConsentToken(message, key, { agentId, action?, scopeRequirements? })` requires `agentId` and rejects tokens issued for other agents (`WrongAudienceError`). It checks the message's session matches the token's, and optionally checks the token against your declared scope requirements. `verifyConsentTokenOffline` accepts the same options. `verifyConsentTokenOnline` accepts `agentId`.
- Activation: `activationHeaders()` and `isParafeActivated()`. A2A 1.0 uses `A2A-Extensions`; `X-A2A-Extensions` is only for A2A 0.3.
- `buildAgentCardExtension` requires an explicit `required`. `parseAgentCardExtension` recognizes v2 and v1 URIs.
- `MalformedDataPartError` renamed `MalformedParafeDataError` (code `MALFORMED_PARAFE_DATA`). New `WrongAudienceError`, `isParafeError()`.
- Removed the deprecated `/compat` export.
- Interop tests against a real `@a2a-js/sdk` server (A2A 1.0 client, raw A2A 1.0 and 0.3 JSON-RPC, 1.x senders) run in CI.

## 1.0.0 (2026-03-28)

First stable release.

- Offline and online consent token verification (`verifyConsentTokenOffline`, `verifyConsentTokenOnline`, `verifyMessageConsentToken`)
- AgentCard extension builder and parser (`buildAgentCardExtension`, `parseAgentCardExtension`)
- A2A DataPart helpers for handshake challenge, handshake complete, and consent tokens (`buildHandshakeChallenge`, `buildHandshakeComplete`, `buildConsentTokenPart`, `extractHandshakeChallenge`, `extractHandshakeComplete`, `extractConsentToken`, `hasParafeDataPart`)
- Handshake challenge validation constants (`PARAFE_HANDSHAKE_CHALLENGE`, `PARAFE_HANDSHAKE_COMPLETE`, `PARAFE_TRUST_CONSENT_TOKEN`)
- Error classes for structured error handling (`MissingParafeExtensionError`, `InvalidConsentTokenError`, `ExpiredConsentTokenError`, `ScopeViolationError`, `MalformedDataPartError`)
- Deprecated compatibility module (`@getparafe/a2a-extension/compat`) for v0.2.0 metadata-based API

## 0.1.0, 0.2.0 (2026-03-28)

Pre-releases (0.2.0: the metadata-based API kept in 1.0's `/compat`). Superseded by 1.0.0.
