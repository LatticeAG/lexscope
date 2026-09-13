# LatticeAG LexScope

<p align="center">
  <a href="https://github.com/LatticeAG/lexscope/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/LatticeAG/lexscope?style=for-the-badge" alt="License" />
  </a>
  <a href="https://github.com/LatticeAG/lexscope/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/LatticeAG/lexscope/ci.yml?branch=main&style=for-the-badge&label=CI" alt="CI" />
  </a>
  <a href="https://github.com/LatticeAG/lexscope/stargazers">
    <img src="https://img.shields.io/github/stars/LatticeAG/lexscope?style=for-the-badge" alt="GitHub stars" />
  </a>
  <a href="https://github.com/LatticeAG/lexscope/issues">
    <img src="https://img.shields.io/github/issues/LatticeAG/lexscope?style=for-the-badge" alt="GitHub issues" />
  </a>
  <a href="https://github.com/LatticeAG/lexscope">
    <img src="https://img.shields.io/github/languages/top/LatticeAG/lexscope?style=for-the-badge" alt="Top language" />
  </a>
  <a href="https://github.com/LatticeAG/lexscope">
    <img src="https://img.shields.io/badge/TypeScript-5.9-blue?style=for-the-badge&logo=typescript" alt="TypeScript" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  </a>
</p>

**LexScope** is the LatticeAG credential gateway for agent tool calls
(protocol `lexscope/1`). It replaces broad provider API keys with short-lived,
task-scoped tokens: every credential is bound to the caller's public key, to
the exact call hash, to the gateway audience, and (for destructive effects) to
a one-use nonce and a one-shot dispatch reservation. Revocation is durable,
the audit stream is hash-chained and signed, and provider credentials never
enter prompts, model output, or logs.

> A LexScope token means exactly this: **"this subject may perform these
> calls, under this policy revision, for this task, until this expiry."** It
> does not delegate, chain, or survive the task — and the gateway, not the
> caller, is the sole authorization boundary.

## What the gateway enforces

- **Closed EdDSA JWTs** (`Ed25519`), TTL bounded to 30–300 seconds, `cnf.jkt`
  caller-key binding.
- **DPoP-style caller proofs** on every request — bound to method, URI, body
  hash, access-token hash, and the exact call hash.
- **Scope predicates** (`eq`, `in`, `int_range`, `path_prefix`) evaluated
  against canonicalized arguments before dispatch; minted scopes must be
  implied by the principal's grant.
- **One-use destructive nonces** (60 s TTL) and one-shot call reservations —
  a replayed call returns the stored result, never a second dispatch.
- **Durable tombstones** for token, subject, task, and key revocation;
  restoration revokes live tasks without revoking token rows.
- **Signed, hash-chained audit** (`lexscope.audit/1`) with offline
  verification, pinned heads, and rotation-aware trust.
- **Fail-closed Herald binding**: `required` mints and calls check card
  freshness at the gateway; an unavailable or revoked card blocks dispatch.
- **Accepted-risk isolation**: results are AES-256-GCM sealed per tenant with
  bound AAD, adapter output is validated and redacted, and `UNKNOWN` outcomes
  are never redispatched.

## Repository layout

```
src/core/      pure primitives: strict JSON, JCS, Ed25519 JWS, schemas,
               predicates, policy, audit, box, redaction, error taxonomy
src/engine/    store (SQLite single-writer), TenantAuthority, gateway
               pipeline, adapters, Herald binding, deploy
src/sdk.ts     LexScopeClient + opaque TokenHandle
src/cli.ts     lexscope CLI (shared grammar with python -m lexscope)
src/mcp.ts     MCP stdio JSON-RPC shim (documents_read / records_delete)
src/openai.ts  OpenAI function-calling host shim
src/server.ts  lexscope-broker local HTTP host
src/hosted.ts  paid/cloud surfaces — explicit NotImplemented stubs
python/        parity package: same canon, crypto, schemas, SDK, CLI, MCP
conformance/   vectors.json — 10,000 seeded canonicalization objects + crypto
               fixtures, shared by both languages
tests/         75 TV-L conformance vectors + evaluation-matrix suites
examples/      live smoke driver (real broker + real CLI)
```

## Quick start

```bash
npm ci
npm run typecheck   # tsc --noEmit
npm test            # 92 node --test cases (75 TV-L vectors + matrix suites)
npm run smoke       # live broker + CLI happy path on an ephemeral port
npm run test:py     # Python parity suite (18 cases incl. the 10k corpus)
```

The smoke boots `lexscope-broker` on `127.0.0.1:0`, generates real keys, mints
a token through the real CLI (token bytes travel over an inherited FD only),
performs a call, reads back the replayed result, exports and verifies the
audit chain — then verifies the same evidence with `python -m lexscope`.

## CLI

```
lexscope config check --file lexscope.json
lexscope keygen --out caller.pem --public-out caller.jwk.json
lexscope mint --request mint.json --control-key control.pem \
  --control-kid lky_... --caller-key caller.pem --out-fd 3 3>token
lexscope call --request call.json --token-fd 3 --caller-key caller.pem 3<token
lexscope audit export --control-key control.pem --control-kid lky_... --out audit.json
lexscope audit verify --in audit.json --trust trust.json
lexscope mcp serve --token-fd 3 --caller-key caller.pem --task-id lts_...
```

Secret handling is hard-bounded: private keys come from file paths, token
bytes travel only over inherited FDs (pipes or mode-0600 files), FD 1/2 are
refused for token output, and no command overwrites existing key or evidence
files. `python -m lexscope` implements the identical grammar and exit codes
(0, 2–10, 130).

`--control-kid` is the one addition to the printed §8.4 grammar: control
proofs require a JOSE `kid`, and the table lists only `--control-key`. It is
required for every control-signed command.

## Security boundaries

- The **gateway** is the sole authorization boundary. Adapters are fixed,
  typed, and bound to configured service identities — provider credentials
  live only in adapter secret bindings and never reach agent-visible data.
- Token handles are opaque: `toJSON`, `toString`, `repr`, and inspect all
  return `[LexScope credential redacted]`.
- Error surfaces are stable codes only — never upstream bytes, argument
  values, policy fragments, or credentials.
- Cross-mesh token chaining is rejected (`CHAINING_FORBIDDEN`); nested JWTs
  and delegation members are scanned before any signature verification.
- `UNKNOWN` outcomes are never auto-retried or redispatched; recovery is a
  `/results` status lookup on the same call ID.
- No `--insecure`, `--skip-dpop`, `--allow-all`, `--ignore-revocation`, or
  `--force-dispatch` flags exist, anywhere.

## Hosted surfaces

Hosted multi-tenant minting, managed rotation, billing, and federation are
paid LatticeAG surfaces. This repository exposes them only as documented
`NotImplemented` stubs (`src/hosted.ts`, `HostedControlPlane`) — never fake
working code. Real-Herald federation is likewise stubbed until the Herald
wire protocol is pinned.

## License

MIT — see [LICENSE](LICENSE).
