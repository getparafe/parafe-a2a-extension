# Changelog

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

## 1.0.0 (2026-03-29)

Initial release.

- Offline and online consent token verification (`verifyConsentTokenOffline`, `verifyConsentTokenOnline`, `verifyMessageConsentToken`)
- AgentCard extension builder and parser (`buildAgentCardExtension`, `parseAgentCardExtension`)
- A2A DataPart helpers for handshake challenge, handshake complete, and consent tokens (`buildHandshakeChallenge`, `buildHandshakeComplete`, `buildConsentTokenPart`, `extractHandshakeChallenge`, `extractHandshakeComplete`, `extractConsentToken`, `hasParafeDataPart`)
- Handshake challenge validation constants (`PARAFE_HANDSHAKE_CHALLENGE`, `PARAFE_HANDSHAKE_COMPLETE`, `PARAFE_TRUST_CONSENT_TOKEN`)
- Error classes for structured error handling (`MissingParafeExtensionError`, `InvalidConsentTokenError`, `ExpiredConsentTokenError`, `ScopeViolationError`, `MalformedDataPartError`)
- Deprecated compatibility module (`@getparafe/a2a-extension/compat`) for v0.2.0 metadata-based API
