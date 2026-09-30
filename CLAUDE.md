# @getparafe/a2a-extension

TypeScript package that adds Parafe trust to the A2A (Agent-to-Agent) protocol, A2A 1.0 and 0.3. Published on npm as `@getparafe/a2a-extension`. The extension spec is hosted at its URI, https://parafe.ai/extensions/a2a/v2 (source: `website/public/extensions/a2a/v2.html` in `getparafe/website`). Keep the two in sync.

## Project Structure

- `src/index.ts` — Package entry point, re-exports everything.
- `src/message.ts` — Write Parafe data into A2A messages (`withParafe`) and read it back (`readParafe` + extractors). Data lives at `message.metadata[PARAFE_EXTENSION_URI]`, never in parts. Readers also accept v1 data parts in all three shapes (A2A 0.3 `kind`, A2A 1.0 wire, @a2a-js/sdk `content.$case`) until 2027-03-31.
- `src/verification.ts` — Online and offline consent token verification. Broker keys by `kid` from the JWKS (`fetchBrokerKeys`; ES256, EdDSA for older tokens), runtime claim type guards, audience (`target_agent_id`), session match, scope-policy checks, presentation proofs (key-bound tokens: `createPresentationProof`, `verifyPresentationProof`, jti replay cache), HTTPS warning for non-localhost brokers.
- `src/action-receipts.ts` — Action receipts (2.2): `createActionReceiptSigner` (sign with the agent key, file with the broker in the background, receipt refusals), `signActionReceipt`, `fileActionReceipt`, `actionErrorFor`, `jcs`. `verifyMessageConsentToken` takes the signer as `receipts`. Receipts travel as `action_receipts` (a list beside any member, or alone; `withActionReceipts`/`extractActionReceipts`).
- `src/headers.ts` — A2A activation headers (`A2A-Extensions`, and `X-A2A-Extensions` for A2A 0.3).
- `src/agent-card.ts` — AgentCard extension builder and parser (recognizes v2 and v1 URIs).
- `src/errors.ts` — Error types, each with a `code` matching the spec's error codes.
- `src/types.ts` — Structural types (no dependency on any A2A SDK).
- `src/constants.ts` — Extension URIs, header names, v1 data part keys.
- `tests/unit/` — Unit tests.
- `tests/interop/` — Runs the package against a real `@a2a-js/sdk` server and client on localhost (A2A 1.0 client, raw A2A 1.0 and 0.3 JSON-RPC, v1 senders). Part of `npm run test:unit`, so CI runs it. This is what catches A2A protocol drift.
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

- **Strict TypeScript** — `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess` enabled. Runtime type guards in `verification.ts` validate JWT claims before trusting type casts.
- **Metadata, not parts** — agents feed message parts to LLMs and logs; consent tokens must stay out of both.
- **No A2A SDK dependency** — types are structural so the package works with any SDK or raw JSON. `@a2a-js/sdk` is a devDependency for interop tests only.
- **Online + offline verification** — `verifyConsentTokenOnline` calls the broker. `verifyConsentTokenOffline` verifies against the cached JWKS without network. Both available.
- **Key binding (2.1)** — a consent token names the initiator's key (`cnf.jkt`); `verifyMessageConsentToken` checks the presentation proof whenever one is sent, and requires one with `requireProof` (default on in 3.0).
- **Response shape validation** — Online verification validates broker response shape (`verification.ts:163-167`) before trusting it.
- **HTTPS enforcement** — Warns when broker URL is non-HTTPS for non-localhost (`verification.ts:103-111`).

## When Making Changes

- If modifying verification logic, run both unit and integration tests.
- If A2A or `@a2a-js/sdk` changes, bump the devDependency and run `npm run test:interop` first.
- This package does not depend on `@getparafe/sdk` (only `jose`). It makes its own HTTP calls for online verification and fetching the broker key.
- Published via npm. Run `npm run build` and `npm test` before publishing.
