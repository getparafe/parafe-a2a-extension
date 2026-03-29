# Changelog

## 1.0.0 (2026-03-29)

Initial release.

- Offline and online consent token verification (`verifyConsentTokenOffline`, `verifyConsentTokenOnline`, `verifyMessageConsentToken`)
- AgentCard extension builder and parser (`buildAgentCardExtension`, `parseAgentCardExtension`)
- A2A DataPart helpers for handshake challenge, handshake complete, and consent tokens (`buildHandshakeChallenge`, `buildHandshakeComplete`, `buildConsentTokenPart`, `extractHandshakeChallenge`, `extractHandshakeComplete`, `extractConsentToken`, `hasParafeDataPart`)
- Handshake challenge validation constants (`PARAFE_HANDSHAKE_CHALLENGE`, `PARAFE_HANDSHAKE_COMPLETE`, `PARAFE_TRUST_CONSENT_TOKEN`)
- Error classes for structured error handling (`MissingParafeExtensionError`, `InvalidConsentTokenError`, `ExpiredConsentTokenError`, `ScopeViolationError`, `MalformedDataPartError`)
- Deprecated compatibility module (`@getparafe/a2a-extension/compat`) for v0.2.0 metadata-based API
