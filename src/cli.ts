// lexscope CLI per §8.4. Shared grammar with `python -m lexscope`.
// Secret handling: private keys come from file paths only; token bytes travel
// over inherited FDs (--token-fd reads, --out-fd writes); secrets are never
// command-line values, env values, or written to FD 1/2.

import { readFileSync, writeFileSync, fstatSync, openSync, closeSync } from "node:fs";
import { createPrivateKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { parseStrict } from "./core/strictjson.ts";
import { jcsString } from "./core/jcs.ts";
import { b64uJson } from "./core/b64.ts";
import { keyObjectToJwk } from "./core/jwt.ts";
import { validateClientConfig } from "./core/schemas.ts";
import {
  LexScopeClient, LexScopeError, TransportError, TokenHandle,
  type WireReq, type WireRes,
} from "./sdk.ts";
import { verifyAudit, parseAuditPage, parseAuditTrust } from "./core/audit.ts";
import { McpServer } from "./mcp.ts";

const VERSION = "1.0.0";

// ---------- exit-code mapping (§8.4) ----------

const EXIT_BY_CODE: Record<string, number> = {
  AUTH_INVALID: 3, AUTH_MALFORMED: 3, AUTH_HEADER_DUP: 3, AUTH_SCHEME: 3,
  TOKEN_TYPE: 3, TOKEN_MALFORMED: 3, TOKEN_SIZE: 3, TOKEN_EXPIRED: 3,
  SIGNATURE_INVALID: 3, ALG_FORBIDDEN: 3, CHAINING_FORBIDDEN: 3, CNF_MISMATCH: 3,
  PROOF_INVALID: 3, PROOF_MALFORMED: 3, PROOF_REPLAY: 3, PROOF_SIZE: 3,
  CLOCK_WINDOW: 3, METHOD_MISMATCH: 3, PATH_MISMATCH: 3, BODY_MISMATCH: 3,
  CALL_HASH_MISMATCH: 3, ATH_MISMATCH: 3, JKT_MISMATCH: 3, SUBJECT_UNKNOWN: 3,
  BINDING_MISMATCH: 3,
  TOKEN_REVOKED: 4, KEY_REVOKED: 4, SUBJECT_REVOKED: 4, TASK_REVOKED: 4,
  TASK_EXPIRED: 4, CONTROL_FORBIDDEN: 4, POLICY_STALE: 4, SCOPE_DENIED: 4,
  HARD_DENY: 4, HERALD_REVOKED: 4,
  TASK_BINDING_CONFLICT: 5, NONCE_REQUIRED: 5, NONCE_INVALID: 5,
  NONCE_CONSUMED: 5, NONCE_EXPIRED: 5, NONCE_MISMATCH: 5, NONCE_SCOPE: 5,
  NONCE_OVERFLOW: 5, CALL_ID_CONFLICT: 5, OP_CONFLICT: 5,
  MINT_RESULT_EXPIRED: 5, REVISION_CONFLICT: 5, KEY_CONFLICT: 5,
  NOT_FOUND: 5, RESULT_GONE: 5, RESULT_UNKNOWN: 5,
  CLOCK_UNSAFE: 6, KEY_UNAVAILABLE: 6, STATE_UNAVAILABLE: 6,
  HERALD_UNAVAILABLE: 6, HERALD_STALE: 6, RATE_LIMITED: 6, CAPACITY: 6,
  COUNTER_EXHAUSTED: 6, TRANSPORT_UNAVAILABLE: 6,
  OUTCOME_UNKNOWN: 7, OUTPUT_REDACTED: 7, OUTPUT_INVALID: 7,
  OUTPUT_TOO_LARGE: 7, TRANSPORT_REDIRECT: 7,
  UPSTREAM_REJECTED: 9,
};

const SCHEMA_CODES = new Set([
  "SCHEMA_INVALID", "VERSION_UNSUPPORTED", "JSON_INVALID", "JSON_DUP_KEY",
  "JSON_UNSAFE_NUMBER", "JSON_DEPTH", "HEADER_TOO_LARGE", "BODY_TOO_LARGE",
  "MEDIA_TYPE", "METHOD_INVALID", "PATH_INVALID", "TENANT_INVALID",
  "QUERY_INVALID", "KEY_INSECURE", "HERALD_INVALID", "CONTROL_KEY_MISSING",
  "CALLER_KEY_MISSING", "ADAPTER_BYPASS", "DESTRUCTIVE_CLASS",
]);

class CliUsage extends Error {}

function exitCode(e: unknown): number {
  if (e instanceof CliUsage) return 2;
  if (e instanceof LexScopeError) {
    if (e.status === 202) return 10;
    const m = EXIT_BY_CODE[e.code];
    if (m !== undefined) return m;
    if (SCHEMA_CODES.has(e.code)) return 2;
    return e.retryable ? 6 : 5;
  }
  return 2;
}

// ---------- arg parsing ----------

interface ParsedArgs {
  cmd: string[];
  flags: Map<string, string | true>;
  json: boolean;
}

const GLOBAL_FLAGS = new Set(["--config", "--json", "--timeout-ms", "--help", "--version"]);

function parseArgs(argv: string[]): ParsedArgs {
  const flags = new Map<string, string | true>();
  const cmd: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) { cmd.push(a); continue; }
    const eq = a.indexOf("=");
    const name = eq === -1 ? a : a.slice(0, eq);
    if (flags.has(name)) throw new CliUsage(`duplicate flag ${name}`);
    if (eq !== -1) { flags.set(name, a.slice(eq + 1)); continue; }
    if (name === "--json" || name === "--help" || name === "--version") { flags.set(name, true); continue; }
    if (i + 1 >= argv.length || argv[i + 1]!.startsWith("--")) throw new CliUsage(`flag ${name} requires a value`);
    flags.set(name, argv[++i]!);
  }
  return { cmd, flags, json: flags.get("--json") === true };
}

function flag(p: ParsedArgs, name: string): string | true | undefined {
  return p.flags.get(name);
}
function need(p: ParsedArgs, name: string): string {
  const v = p.flags.get(name);
  if (v === undefined || v === true) throw new CliUsage(`missing required flag ${name}`);
  return v;
}
function noLeftover(p: ParsedArgs, allowed: string[]): void {
  for (const k of p.flags.keys()) {
    if (!GLOBAL_FLAGS.has(k) && !allowed.includes(k)) throw new CliUsage(`unknown flag ${k}`);
  }
}

// ---------- config / keys / secret FDs ----------

function loadClientConfig(path: string): ReturnType<typeof validateClientConfig> {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new CliUsage(`cannot read config ${path}`);
  }
  try {
    return validateClientConfig(parseStrict(new TextEncoder().encode(raw)));
  } catch (e) {
    throw new CliUsage(`invalid client config: ${e instanceof Error ? e.message : String(e)}`);
  }
}

function loadPrivateKey(path: string): KeyObject {
  let pem: string;
  try {
    pem = readFileSync(path, "utf8");
  } catch {
    throw new CliUsage(`cannot read key ${path}`);
  }
  try {
    return createPrivateKey(pem);
  } catch {
    throw new CliUsage(`key ${path} is not a valid PKCS8 PEM`);
  }
}

// Secret FDs must be inherited pipes or owned mode-0600 regular files, never
// terminal devices; token output to FD 1 or 2 is refused outright.
function secretFd(fd: string, mode: "read" | "write"): number {
  const n = Number(fd);
  if (!Number.isInteger(n) || n < 0) throw new CliUsage(`invalid fd ${fd}`);
  if (mode === "write" && (n === 1 || n === 2)) throw new CliUsage("token output to FD 1 or 2 is forbidden");
  let st;
  try {
    st = fstatSync(n);
  } catch {
    throw new CliUsage(`fd ${n} is not open`);
  }
  if (st.isCharacterDevice() || st.isDirectory() || st.isSocket()) {
    throw new CliUsage(`fd ${n} is not a safe secret channel`);
  }
  if (st.isFile() && (st.mode & 0o777) !== 0o600) throw new CliUsage(`fd ${n} file must be mode 0600`);
  return n;
}

function readTokenFd(fd: string): string {
  const n = secretFd(fd, "read");
  const tok = readFileSync(n).toString("utf8").trim();
  if (tok.length === 0) throw new CliUsage("empty token fd");
  return tok;
}

function writeTokenFd(fd: string, token: string): void {
  writeFileSync(secretFd(fd, "write"), token + "\n");
}

function loadRequest(path: string): unknown {
  let raw: string;
  if (path === "-") {
    raw = readFileSync(0).toString("utf8");
  } else {
    try {
      raw = readFileSync(path, "utf8");
    } catch {
      throw new CliUsage(`cannot read request ${path}`);
    }
  }
  try {
    return parseStrict(new TextEncoder().encode(raw));
  } catch (e) {
    throw new CliUsage(`request is not strict JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ---------- transport (redirects disabled, spec timeouts) ----------

function httpTransport(): (req: WireReq, timeoutMs: number) => Promise<WireRes> {
  return async (req, timeoutMs) => {
    const res = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      body: req.body === null ? null : Buffer.from(req.body, "utf8"),
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, headers, body: new Uint8Array(await res.arrayBuffer()) };
  };
}

// ---------- output ----------

function emit(p: ParsedArgs, value: unknown): void {
  process.stdout.write((p.json ? jcsString(value) : JSON.stringify(value, null, 2)) + "\n");
}

function usage(): string {
  return `lexscope ${VERSION}
usage: lexscope [--config PATH] [--json] [--timeout-ms N] <command> [flags]

commands:
  config check --file PATH
  keygen --out PATH [--public-out PATH]
  mint --request PATH --control-key PATH --control-kid ID --caller-key PATH --out-fd N
  call --request PATH --token-fd N --caller-key PATH
  result --request PATH --token-fd N --caller-key PATH
  revoke --request PATH --control-key PATH --control-kid ID
  inspect --request PATH --control-key PATH --control-kid ID
  policy apply --request PATH --control-key PATH --control-kid ID
  keys rotate --request PATH --control-key PATH --control-kid ID
  audit export --control-key PATH --control-kid ID --out PATH [--after N] [--limit N]
  audit verify --in PATH --trust PATH
  mcp serve --token-fd N --caller-key PATH --task-id ID
`;
}

// Token claims are decoded locally for metadata only — the server is the sole
// verifier; a client-side parse never authenticates anything.
function tokenClaims(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new CliUsage("malformed token on fd");
  const claims = b64uJson(parts[1]!) as Record<string, unknown> | undefined;
  if (claims === undefined || typeof claims !== "object" || claims === null) throw new CliUsage("malformed token on fd");
  return claims;
}

function handleFromToken(token: string): TokenHandle {
  const c = tokenClaims(token);
  return new TokenHandle(token, String(c.jti ?? ""), Number(c.exp ?? 0), String(c.scope_hash ?? ""));
}

function tokenSecret(h: TokenHandle): string {
  return (h as unknown as { secret: string }).secret;
}

// ---------- commands ----------

export async function main(argv: string[]): Promise<number> {
  let p: ParsedArgs;
  try {
    p = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${e instanceof Error ? e.message : e}\n`);
    return 2;
  }
  if (p.flags.get("--help") === true && p.cmd.length === 0) { process.stdout.write(usage()); return 0; }
  if (p.flags.get("--version") === true && p.cmd.length === 0) { process.stdout.write(VERSION + "\n"); return 0; }
  if (p.cmd.length === 0) { process.stderr.write(usage()); return 2; }

  const timeoutFlag = flag(p, "--timeout-ms");
  const timeoutMs = timeoutFlag === undefined ? 25000 : Number(timeoutFlag);
  if (timeoutFlag !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 30000)) {
    process.stderr.write("--timeout-ms must be an integer in [100, 30000]\n");
    return 2;
  }

  try {
    const cfgPath = typeof flag(p, "--config") === "string" ? (flag(p, "--config") as string) : "./lexscope.json";
    const cmd = p.cmd.join(" ");

    switch (cmd) {
      case "config check": {
        noLeftover(p, ["--file"]);
        const cfg = loadClientConfig(need(p, "--file"));
        emit(p, { protocol: "lexscope/1", tenant_id: cfg.tenant_id, valid: true });
        return 0;
      }
      case "keygen": {
        noLeftover(p, ["--out", "--public-out"]);
        const out = need(p, "--out");
        const pub = flag(p, "--public-out");
        const pair = generateKeyPairSync("ed25519");
        const pem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
        const fd = openSync(out, "wx", 0o600); // exclusive create, mode 0600
        writeFileSync(fd, pem);
        closeSync(fd);
        const jwkJson = jcsString(keyObjectToJwk(pair.publicKey)) + "\n";
        if (typeof pub === "string") {
          const pfd = openSync(pub, "wx", 0o644);
          writeFileSync(pfd, jwkJson);
          closeSync(pfd);
          emit(p, { created: out, public_out: pub });
        } else {
          process.stdout.write(jwkJson);
        }
        return 0;
      }
      case "mint": {
        noLeftover(p, ["--request", "--control-key", "--control-kid", "--caller-key", "--out-fd"]);
        const cfg = loadClientConfig(cfgPath);
        const req = loadRequest(need(p, "--request"));
        const controlKey = loadPrivateKey(need(p, "--control-key"));
        const controlKid = need(p, "--control-kid");
        const callerKey = loadPrivateKey(need(p, "--caller-key"));
        const outFd = need(p, "--out-fd");
        // The caller public key derived from --caller-key must equal the mint
        // request's caller_jwk — mismatch fails before any HTTP request.
        const want = keyObjectToJwk(callerKey);
        const got = (req as { caller_jwk?: { x?: string } }).caller_jwk;
        if (!got || got.x !== want.x) throw new CliUsage("--caller-key does not match request caller_jwk");
        const client = new LexScopeClient({
          origin: cfg.origin, tenantId: cfg.tenant_id,
          controlKey, controlKid, callerKey,
          transport: httpTransport(),
        });
        const handle = await client.mint(req as never);
        writeTokenFd(outFd, tokenSecret(handle));
        emit(p, { expires_at: handle.expiresAt, scope_hash: handle.scopeHash, token_id: handle.tokenId });
        return 0;
      }
      case "call": case "result": {
        noLeftover(p, ["--request", "--token-fd", "--caller-key"]);
        const cfg = loadClientConfig(cfgPath);
        const req = loadRequest(need(p, "--request"));
        const token = readTokenFd(need(p, "--token-fd"));
        const callerKey = loadPrivateKey(need(p, "--caller-key"));
        const client = new LexScopeClient({ origin: cfg.origin, tenantId: cfg.tenant_id, callerKey, transport: httpTransport() });
        const handle = handleFromToken(token);
        const res = cmd === "call" ? await client.call(handle, req as never) : await client.result(handle, req as never);
        emit(p, res);
        return 0;
      }
      case "revoke": case "inspect": case "policy apply": case "keys rotate": {
        noLeftover(p, ["--request", "--control-key", "--control-kid"]);
        const cfg = loadClientConfig(cfgPath);
        const req = loadRequest(need(p, "--request"));
        const controlKey = loadPrivateKey(need(p, "--control-key"));
        const controlKid = need(p, "--control-kid");
        const client = new LexScopeClient({
          origin: cfg.origin, tenantId: cfg.tenant_id, controlKey, controlKid, transport: httpTransport(),
        });
        const res =
          cmd === "revoke" ? await client.revoke(req as never) :
          cmd === "inspect" ? await client.inspect(req as never) :
          cmd === "policy apply" ? await client.applyPolicy(req as never) :
          await client.rotate(req as never);
        emit(p, res);
        return 0;
      }
      case "audit export": {
        noLeftover(p, ["--control-key", "--control-kid", "--out", "--after", "--limit"]);
        const cfg = loadClientConfig(cfgPath);
        const controlKey = loadPrivateKey(need(p, "--control-key"));
        const controlKid = need(p, "--control-kid");
        const after = typeof flag(p, "--after") === "string" ? (flag(p, "--after") as string) : "0";
        const limit = typeof flag(p, "--limit") === "string" ? (flag(p, "--limit") as string) : "100";
        const out = need(p, "--out");
        const client = new LexScopeClient({
          origin: cfg.origin, tenantId: cfg.tenant_id, controlKey, controlKid, transport: httpTransport(),
        });
        const page = await client.audit(after, Number(limit));
        const fd = openSync(out, "wx", 0o644); // never overwrites evidence
        writeFileSync(fd, jcsString(page) + "\n");
        closeSync(fd);
        emit(p, { written: out });
        return 0;
      }
      case "audit verify": {
        noLeftover(p, ["--in", "--trust"]);
        const page = parseAuditPage(loadRequest(need(p, "--in")));
        const trust = parseAuditTrust(loadRequest(need(p, "--trust")));
        if (page === null || trust === null) throw new CliUsage("malformed audit page or trust document");
        const v = verifyAudit(page, trust);
        if (!v.valid) {
          if (p.json) emit(p, { code: v.code, valid: false });
          else process.stderr.write(`audit verification failed: ${v.code}\n`);
          return 8;
        }
        emit(p, { entries: v.entries, head: v.head, valid: true });
        return 0;
      }
      case "mcp serve": {
        noLeftover(p, ["--token-fd", "--caller-key", "--task-id"]);
        const cfg = loadClientConfig(cfgPath);
        const token = readTokenFd(need(p, "--token-fd"));
        const callerKey = loadPrivateKey(need(p, "--caller-key"));
        const taskId = need(p, "--task-id");
        const claims = tokenClaims(token);
        if (claims.task_id !== taskId) {
          throw new CliUsage("--task-id does not match token task_id claim");
        }
        const tools = Array.isArray(claims.scopes)
          ? claims.scopes.map((s) => (s as { tool?: unknown }).tool).filter((t): t is never => typeof t === "string")
          : [];
        const client = new LexScopeClient({ origin: cfg.origin, tenantId: cfg.tenant_id, callerKey, transport: httpTransport() });
        new McpServer({ client, handle: handleFromToken(token), taskId, tools: tools as never }).runStdio();
        return 0;
      }
      default:
        process.stderr.write(`unknown command: ${cmd}\n${usage()}`);
        return 2;
    }
  } catch (e) {
    if (e instanceof LexScopeError || e instanceof CliUsage) {
      process.stderr.write(`${e.message}\n`);
    } else {
      process.stderr.write("error\n");
    }
    return exitCode(e);
  }
}
