# @getparafe/a2a-extension

TypeScript package that adds Parafe trust to the Google A2A (Agent-to-Agent) protocol. Published on npm as `@getparafe/a2a-extension`.

## Project Structure

- `src/index.ts` — Package entry point, re-exports everything.
- `src/verification.ts` — Online and offline consent token verification. Ed25519 signature checks, runtime type guards for JWT claims, HTTPS warnings for non-localhost brokers.
- `src/data-parts.ts` — Builders and parsers for A2A DataParts (handshake, consent, receipt data embedded in A2A messages).
- `src/agent-card.ts` — AgentCard type extensions for Parafe trust metadata.
- `src/errors.ts` — Error types (`InvalidConsentTokenError`, `ExpiredConsentTokenError`).
- `src/types.ts` — TypeScript type definitions.
- `src/constants.ts` — Extension URI and other constants.
- `src/compat/` — Compatibility layer (separate export path `@getparafe/a2a-extension/compat`).
- `tests/unit/` — Unit tests (5 test files covering all source modules).
- `tests/integration/` — Integration tests (`broker.test.ts`, runs against live staging broker).

## Running

```bash
npm install
npm run build          # tsup → CJS + ESM + types
npm test               # Unit tests
npm run test:integration  # Integration tests (requires PARAFE_TEST_BROKER_URL)
```

Integration tests run against the staging broker. Set `PARAFE_TEST_BROKER_URL` or it defaults to `http://localhost:3000`.

## Key Design Decisions

- **Strict TypeScript** — `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess` enabled. Runtime type guards in `verification.ts:60-77` validate JWT claims before trusting type casts.
- **Online + offline verification** — `verifyConsentOnline` calls the broker. `verifyConsentLocally` does Ed25519 verification without network. Both available.
- **Response shape validation** — Online verification validates broker response shape (`verification.ts:163-167`) before trusting it.
- **HTTPS enforcement** — Warns when broker URL is non-HTTPS for non-localhost (`verification.ts:103-111`).
- **Excellent test coverage** — 732 lines of tests for 957 lines of source. This is the most thoroughly tested component in the org.

## When Making Changes

- If modifying verification logic, run both unit and integration tests.
- The `compat/` export is a separate entry point — changes there don't affect the main export and vice versa.
- This package depends on `@getparafe/sdk` for types but does its own HTTP calls for online verification.
- Published via npm. Run `npm run build` and `npm test` before publishing.
