#!/usr/bin/env node
// Live smoke: boots a real lexscope-broker process on an ephemeral loopback
// port and drives the real `lexscope` CLI binary through the §8.4 happy path:
// config check -> keygen x4 -> mint -> call -> result -> audit export ->
// audit verify (TS CLI and `python -m lexscope`).
//
// The configured origin is the spec test origin; CLI fetch is redirected to
// the local socket by examples/fetch-shim.mjs via NODE_OPTIONS (equivalent to
// a hosts entry — signed htu/aud bindings stay exact).
import { spawnSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, openSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { keyObjectToJwk } from "../src/core/jwt.ts";
import { jcsString } from "../src/core/jcs.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = mkdtempSync(join(tmpdir(), "lexscope-smoke-"));
const ORIGIN = "https://gateway.example.test";
const rid = (p, n = 21) => `${p}_${randomBytes(16).toString("base64url").padEnd(n, "x").slice(0, n)}`;
const writ = (name, data, mode = 0o644) => { const p = join(DIR, name); writeFileSync(p, data); chmodSync(p, mode); return p; };

console.log(`smoke dir: ${DIR}`);

// ---- keys ----
const keys = {};
for (const name of ["token", "audit", "control", "caller"]) {
  const kp = generateKeyPairSync("ed25519");
  keys[name] = {
    pem: kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    jwk: keyObjectToJwk(kp.publicKey),
    kid: rid("lky"),
  };
}
const [G, TEN, U, TASK, OP, CALL, DEL_CALL, RES_OP] =
  [rid("lsg"), rid("ltn"), rid("lsu"), rid("lts"), rid("lop"), rid("lcl"), rid("lcl"), rid("lop")];

const SCOPES = [
  { tool: "documents.read", where: [
    { ptr: "/path", op: "path_prefix", value: "reports" },
    { ptr: "/workspace", op: "eq", value: "demo" }]},
  { tool: "records.delete", where: [{ ptr: "/workspace", op: "eq", value: "demo" }]},
];

const gw = {
  v: 1, mode: "test", origin: ORIGIN, gateway_id: G, tenant_id: TEN,
  tenant_do_binding: "TENANTS",
  policy: { v: 1, revision: "1", hard_deny: [],
    principals: [{ sub: U, scopes: SCOPES, max_ttl_s: 300, herald: "disabled" }] },
  controls: [{ kid: keys.control.kid, jwk: keys.control.jwk,
    roles: ["auditor", "minter", "operator"], subjects: [U] }],
  token_signer: { kid: keys.token.kid, jwk: keys.token.jwk, secret_ref: "TOKEN_SIGNER" },
  audit_signer: { kid: keys.audit.kid, jwk: keys.audit.jwk, secret_ref: "AUDIT_SIGNER" },
  encryption: { key_ref: "TENANT_DATA_KEY", key_version: "1" },
  tools: { documents_read_binding: "DOCS", records_delete_binding: "RECS" },
  herald_sources: [],
};
const client = { v: 1, origin: ORIGIN, gateway_id: G, tenant_id: TEN,
  audit_trust: [{ kid: keys.audit.kid, jwk: keys.audit.jwk }] };
const trust = { v: 1, tenant_id: TEN, initial_kid: keys.audit.kid,
  keys: [{ kid: keys.audit.kid, jwk: keys.audit.jwk }], pinned_head: null, checkpoint: null };
const secrets = { TOKEN_SIGNER: keys.token.pem, AUDIT_SIGNER: keys.audit.pem };

const gwPath = writ("gateway.json", jcsString(gw));
const cliPath = writ("lexscope.json", jcsString(client));
const secPath = writ("secrets.json", jcsString(secrets), 0o600);
const trustPath = writ("trust.json", jcsString(trust));
const dkPath = writ("dk.hex", randomBytes(32).toString("hex"), 0o600);
const docsPath = writ("docs.json", jcsString({ demo: { "reports/a.txt": { text: "Quarterly report", version: 7 } } }));
const recsPath = writ("records.json", jcsString({ demo: { r1: 7 } }));
const controlPem = writ("control.pem", keys.control.pem, 0o600);
const callerPem = writ("caller.pem", keys.caller.pem, 0o600);
const tokenFile = writ("token.txt", "", 0o600);
const auditOut = join(DIR, "audit.json");

const mintReq = writ("mint.json", jcsString({
  v: 1, op_id: OP, sub: U, task_id: TASK, caller_jwk: keys.caller.jwk,
  scopes: SCOPES, ttl_s: 300, herald: null }));
const callReq = writ("call.json", jcsString({
  v: 1, call_id: CALL, task_id: TASK, tool: "documents.read",
  args: { workspace: "demo", path: "reports/a.txt" } }));
const resultReq = writ("result.json", jcsString({ v: 1, task_id: TASK, call_id: CALL }));

// ---- broker ----
const broker = spawn(process.execPath, [join(ROOT, "bin/lexscope-broker.mjs"),
  "--config", gwPath, "--secrets", secPath, "--data-key", dkPath,
  "--docs", docsPath, "--records", recsPath,
  "--db", join(DIR, "broker.db"), "--listen", "127.0.0.1:0"],
  { stdio: ["ignore", "inherit", "pipe"] });
const port = await new Promise((res, rej) => {
  let buf = "";
  broker.stderr.on("data", (d) => {
    buf += d;
    const m = buf.match(/listening on 127\.0\.0\.1:(\d+)/);
    if (m) res(Number(m[1]));
  });
  broker.on("exit", () => rej(new Error("broker exited: " + buf)));
  setTimeout(() => rej(new Error("broker start timeout")), 15000);
});
console.log(`broker pid=${broker.pid} port=${port}`);

// ---- CLI driver ----
const env = {
  ...process.env,
  NODE_OPTIONS: `--import ${join(ROOT, "examples/fetch-shim.mjs")}`,
  LX_SMOKE_TARGET: `http://127.0.0.1:${port}`,
};
function cli(args, { fd3 } = {}) {
  const stdio = ["inherit", "pipe", "pipe"];
  if (fd3 !== undefined) stdio[3] = fd3;
  const r = spawnSync(process.execPath, [join(ROOT, "bin/lexscope.mjs"), "--config", cliPath, "--json", ...args],
    { env, stdio, encoding: "utf8" });
  const label = `lexscope ${args.join(" ")}`;
  console.log(`\n$ ${label}\n  exit=${r.status}`);
  if (r.stdout.trim()) console.log(`  stdout: ${r.stdout.trim()}`);
  if (r.stderr.trim()) console.log(`  stderr: ${r.stderr.trim()}`);
  return r;
}
const t0 = Date.now();
let failures = 0;
const expect = (r, code, what) => {
  if (r.status !== code) { failures++; console.log(`  !! expected exit ${code} for ${what}`); }
};

expect(cli(["config", "check", "--file", cliPath]), 0, "config check");

// mint: token bytes go to fd 3 -> mode-0600 file; never to stdout
{
  const fd = openSync(tokenFile, "w", 0o600);
  const r = cli(["mint", "--request", mintReq, "--control-key", controlPem,
    "--control-kid", keys.control.kid, "--caller-key", callerPem, "--out-fd", "3"], { fd3: fd });
  expect(r, 0, "mint");
}

for (const [req, what] of [[callReq, "call"], [resultReq, "result"]]) {
  const fd = openSync(tokenFile, "r");
  const r = cli([what, "--request", req, "--token-fd", "3", "--caller-key", callerPem], { fd3: fd });
  expect(r, 0, what);
}

expect(cli(["audit", "export", "--control-key", controlPem, "--control-kid", keys.control.kid,
  "--out", auditOut]), 0, "audit export");
expect(cli(["audit", "verify", "--in", auditOut, "--trust", trustPath]), 0, "audit verify");

// cross-language: the Python CLI verifies the same exported evidence
{
  const r = spawnSync("python3", ["-m", "lexscope", "--json", "audit", "verify",
    "--in", auditOut, "--trust", trustPath],
    { env: { ...process.env, PYTHONPATH: join(ROOT, "python") }, encoding: "utf8" });
  console.log(`\n$ python -m lexscope audit verify\n  exit=${r.status}`);
  if (r.stdout.trim()) console.log(`  stdout: ${r.stdout.trim()}`);
  if (r.stderr.trim()) console.log(`  stderr: ${r.stderr.trim()}`);
  if (r.status !== 0) failures++;
}

// negative: token output to FD 1 must be refused
{
  const r = cli(["mint", "--request", mintReq, "--control-key", controlPem,
    "--control-kid", keys.control.kid, "--caller-key", callerPem, "--out-fd", "1"]);
  expect(r, 2, "out-fd 1 refusal");
}

broker.kill("SIGTERM");
const secs = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`\nsmoke ${failures === 0 ? "PASS" : "FAIL"} (${secs}s, dir ${DIR})`);
if (process.env.LX_SMOKE_KEEP !== "1") rmSync(DIR, { recursive: true, force: true });
process.exit(failures === 0 ? 0 : 1);
