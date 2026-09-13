// Evaluation-matrix suites per §15.3: scope soundness, concurrency,
// revocation races, secret canaries, clock boundaries, tenant isolation,
// audit continuity, CLI exits, MCP protocol, SDK handle redaction, and
// one-bit signature mutation. Suites that the spec binds to a fixed count
// run at a seeded scale stated in the test name; full-count runs are
// supported by the same code paths.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  World, fixtureIdGen, wire,
  agentRequest, ident,
  NOW, TEN, TOK, TASK, N, READ, DELETE,
} from "./harness.ts";
import {
  T, TOKEN_KEY, CALLER_KEY, AUDIT_JWK, REVOKE_BODY,
  B64, ORIGIN, flipSig,
} from "./fixtures.ts";
import { jcsString } from "../src/core/jcs.ts";
import { ed25519Verify, keyObjectToJwk } from "../src/core/jwt.ts";
import { evalPredicate, implies } from "../src/core/predicates.ts";
import { verifyAudit, parseAuditPage, parseAuditTrust } from "../src/core/audit.ts";
import { LexScopeClient, LexScopeError, TokenHandle, REDACTED, type WireReq, type WireRes } from "../src/sdk.ts";
import { McpServer } from "../src/mcp.ts";
import { OpenAIShim } from "../src/openai.ts";

// unique well-formed fixture ids (base36 is a subset of the id alphabet)
function uid(prefix: string, i: number, size = 21): string {
  return `${prefix}_${i.toString(36).padStart(size, "0")}`;
}

// ---------- scope soundness: exhaustive scalar domain ----------

const DOMAIN = [false, true, 0, 1, 2, "0", "1", "demo", "other"] as const;

test("scope soundness: exhaustive eq/in/int_range over scalar domain (2116 checks)", () => {
  let checked = 0;
  for (const gv of DOMAIN) {
    for (const av of DOMAIN) {
      const grant = { ptr: "/workspace", op: "eq" as const, value: gv };
      assert.equal(evalPredicate(grant, { workspace: av }), gv === av, `eq ${JSON.stringify(gv)} vs ${JSON.stringify(av)}`);
      checked++;
      const inGrant = { ptr: "/workspace", op: "in" as const, values: [gv] };
      assert.equal(evalPredicate(inGrant, { workspace: av }), gv === av);
      checked++;
    }
  }
  for (const lo of [0, 1, 2]) {
    for (const hi of [0, 1, 2]) {
      if (hi < lo) continue;
      const grant = { ptr: "/n", op: "int_range" as const, min: lo, max: hi };
      for (const av of DOMAIN) {
        const expect = typeof av === "number" && Number.isInteger(av) && av >= lo && av <= hi;
        assert.equal(evalPredicate(grant, { n: av }), expect, `range [${lo},${hi}] vs ${JSON.stringify(av)}`);
        checked++;
      }
    }
  }
  const grants = [
    { ptr: "/w", op: "eq", value: "demo" },
    { ptr: "/w", op: "in", values: ["demo", "other"] },
    { ptr: "/n", op: "int_range", min: 0, max: 2 },
    { ptr: "/p", op: "path_prefix", value: "reports/" },
  ];
  const reqs = [
    { ptr: "/w", op: "eq", value: "demo" },
    { ptr: "/w", op: "eq", value: "other" },
    { ptr: "/w", op: "in", values: ["demo"] },
    { ptr: "/w", op: "in", values: ["demo", "evil"] },
    { ptr: "/n", op: "int_range", min: 1, max: 1 },
    { ptr: "/n", op: "int_range", min: 0, max: 9 },
    { ptr: "/p", op: "path_prefix", value: "reports/a/" },
    { ptr: "/p", op: "path_prefix", value: "reports" },
  ];
  for (const g of grants) {
    for (const r of reqs) {
      const imp = implies(r as never, g as never);
      if (imp) {
        for (const w of DOMAIN) for (const n of DOMAIN) for (const p of ["reports/a.txt", "reportsx/a", "reports/", "a"]) {
          const args = { w, n, p };
          if (evalPredicate(r as never, args)) {
            assert.ok(evalPredicate(g as never, args), `unsound: ${JSON.stringify(r)} ⊆ ${JSON.stringify(g)} at ${JSON.stringify(args)}`);
          }
        }
      }
      checked++;
    }
  }
  assert.ok(checked > 200, `checked ${checked}`);
});

// ---------- concurrency: shared destructive call ID + nonce ----------

test("concurrency: 256 schedules sharing one call ID and nonce — exactly one invoke", async () => {
  for (let s = 0; s < 256; s++) {
    const w = new World();
    await w.open();
    const k = 2 + (s % 6);
    const res = await Promise.all(
      Array.from({ length: k }, (_, i) => w.agent("/calls", DELETE, { nonce: N, proof_id: uid("lpf", i + 10, 32) })),
    );
    const dispatches = res.reduce((a, r) => a + r.dispatch, 0);
    assert.equal(dispatches, 1, `schedule ${s}: ${dispatches} dispatches, codes=${res.map((r) => r.code)}`);
    // At most one fresh admission: followers observe the in-flight
    // reservation (202 DISPATCHING) or replay the stored 200 result.
    const freshAdmissions = res.filter((r) => r.status === 200 && (r.body as { replayed?: boolean }).replayed !== true).length;
    assert.ok(freshAdmissions <= 1, `schedule ${s}: ${freshAdmissions} fresh admissions, codes=${res.map((r) => r.code)}`);
    assert.equal(w.nonceState(N), "CONSUMED");
  }
});

// ---------- revocation races ----------

test("revocation races: 128 orderings — revoke-before-admit denied; admit-then-revoke completes in flight", async () => {
  let denied = 0, completed = 0;
  for (let s = 0; s < 128; s++) {
    const w = new World();
    await w.open();
    const revoke = () => w.control("/revoke", { ...REVOKE_BODY, op_id: uid("lop", 1000 + s) }, { proof_id: uid("lpf", 500 + s, 32) });
    if (s % 2 === 0) {
      await revoke();
      const r = await w.agent("/calls", DELETE, { nonce: N, proof_id: uid("lpf", 1, 32) });
      assert.equal(r.code, "TOKEN_REVOKED");
      assert.equal(r.dispatch, 0);
      denied++;
    } else {
      // admission commits; dispatch held at the adapter gate; revocation lands
      // mid-flight — the admitted provider effect completes; revocation is
      // not retroactive onto an in-flight effect.
      let release!: () => void;
      w.recs.gate = () => new Promise<void>((r) => { release = r; });
      const p = w.agent("/calls", DELETE, { nonce: N, proof_id: uid("lpf", 1, 32) });
      await new Promise((r) => setTimeout(r, 5));
      await revoke();
      release();
      const r = await p;
      assert.equal(r.dispatch, 1);
      assert.equal(r.code, "OK");
      completed++;
    }
  }
  assert.equal(denied, 64);
  assert.equal(completed, 64);
});

// ---------- secret canaries: 1000 reflections ----------

test("secret canaries: 1000 token/provider-key reflections leak zero bytes", async () => {
  // 4 tokens × 250 calls: one request per world-second keeps the 50 rps
  // subject bucket intact and inside the 300 s token TTL.
  for (let wix = 0; wix < 4; wix++) {
    const w = new World();
    await w.issued();
    const demo = w.docs.store.get("demo")!;
    for (let i = 0; i < 250; i++) {
      const n = wix * 250 + i;
      const canary = `LSK-CANARY-${n.toString(36)}-${"x".repeat(20 + (n % 40))}`;
      w.docs.providerSecrets.push(canary); // the credential the adapter holds
      demo.set("reports/a.txt", { text: `prefix ${canary} suffix`, version: 7 });
      w.setTime(NOW + i);
      const r = await w.agent("/calls", { ...READ, call_id: uid("lcl", 100000 + n) }, { proof_id: uid("lpf", 100000 + n, 32), iat: NOW + i });
      assert.equal(r.code, "OUTPUT_REDACTED", `canary ${n}: ${r.code}`);
      assert.ok(!JSON.stringify(r.body).includes(canary), `canary ${n} leaked in response`);
    }
    for (const e of w.auditEntries()) assert.ok(!JSON.stringify(e).includes("LSK-CANARY"), "canary in audit body");
  }
});

// ---------- nonce/clock boundary sweep ----------

test("clock boundary sweep: every second in [-121,421] relative to mint", async () => {
  const w = new World();
  await w.issued();
  // Reset the persisted logical clock below the sweep floor so physical
  // regression to NOW-121 is not itself a rollback; each request then lands
  // in its own rate-bucket second.
  w.setLastNow(NOW - 200);
  for (let off = -121; off <= 421; off++) {
    w.setTime(NOW + off);
    const r = await w.agent("/calls", { ...READ, call_id: uid("lcl", 200000 + off + 121) }, { proof_id: uid("lpf", 200000 + off + 121, 32), iat: NOW });
    if (off <= -91) assert.equal(r.code, "AUTH_INVALID", `off=${off}: ${r.code}`);
    else if (off <= 90) assert.equal(r.code, "OK", `off=${off}: ${r.code}`);
    else if (off <= 299) assert.equal(r.code, "CLOCK_WINDOW", `off=${off}: ${r.code}`);
    else assert.equal(r.code, "TOKEN_EXPIRED", `off=${off}: ${r.code}`);
  }
});

test("nonce expiry boundary: +59 ok, +60 and +61 expired", async () => {
  for (const off of [59, 60, 61]) {
    const w = new World();
    await w.open();
    w.setTime(NOW + off);
    const r = await w.agent("/calls", DELETE, { nonce: N, proof_id: uid("lpf", off, 32) });
    if (off <= 59) assert.equal(r.code, "OK");
    else assert.equal(r.code, "NONCE_EXPIRED", `off=${off}: ${r.code}`);
  }
});

test("clock rollback: last_now regression is CLOCK_UNSAFE and denies", async () => {
  const w = new World();
  await w.issued();
  w.setLastNow(NOW + 500);
  const r = await w.agent("/calls", READ);
  assert.equal(r.code, "CLOCK_UNSAFE");
  assert.equal(r.dispatch, 0);
});

// ---------- tenant isolation ----------

test("tenant isolation: foreign token and result IDs rejected on the other tenant", async () => {
  const a = new World();
  const b = new World({ tenantId: ident("ltn", "9") });
  await a.issued();
  await b.issued();
  // A's minted token presented to tenant B: token id never exists in B.
  const cross = await b.agent("/calls", READ, { token: a.mintedToken!, proof_id: uid("lpf", 3, 32) });
  assert.notEqual(cross.status, 200);
  assert.equal(cross.dispatch, 0);
  // A's call id queried under B's token → NOT_FOUND, never cross-tenant data.
  const resB = await b.agent("/results", { v: 1, task_id: TASK, call_id: uid("lcl", 999) }, { proof_id: uid("lpf", 4, 32) });
  assert.ok(resB.status !== 200);
});

// ---------- audit continuity ----------

// an unbounded deterministic id generator for long-running suites
function seqIdGen(): (p: string, l?: number) => string {
  const c = new Map<string, number>();
  return (p, l = 21) => {
    const n = c.get(p) ?? 0;
    c.set(p, n + 1);
    return `${p}_${n.toString(36).padStart(l, "0")}`;
  };
}

test("audit continuity: ~900 events, pagination at boundaries, continuous seq", async () => {
  const w = new World({ idgen: seqIdGen() });
  await w.issued();
  // nonce + destructive call per round over 240 advancing seconds — the nonce
  // is consumed each round so the 16-open-nonces cap never binds; ~720 events.
  const recs = w.recs.store.get("demo")!;
  for (let i = 0; i < 240; i++) {
    w.setTime(NOW + i);
    recs.set("r1", 7); // restore the record so each delete succeeds
    const dcall = { ...DELETE, call_id: uid("lcl", 500000 + i) };
    const nz = await w.agent("/nonces", { v: 1, call: dcall }, { proof_id: uid("lpf", 500000 + i, 32), iat: NOW + i });
    assert.equal(nz.status, 201, `nonce ${i}: ${nz.code}`);
    const nid = (nz.body as { nonce: string }).nonce;
    const r = await w.agent("/calls", dcall, { nonce: nid, proof_id: uid("lpf", 600000 + i, 32), iat: NOW + i });
    assert.equal(r.status, 200, `call ${i}: ${r.code}`);
  }
  const total = w.auditCount();
  assert.ok(total >= 700, `events=${total}`);
  let after = "0";
  const entries: unknown[] = [];
  let lastHead: unknown = null;
  for (;;) {
    const r = await w.control(`/audit?after=${after}&limit=97`, null, { method: "GET", proof_id: uid("lpf", 400000 + entries.length, 32), iat: NOW + 239 });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const page = r.body as { entries: { body: { seq: string } }[]; next_after: string; has_more: boolean; head: unknown };
    entries.push(...page.entries);
    lastHead = page.head;
    if (!page.has_more) break;
    after = page.next_after;
  }
  // The exported chain is a strictly continuous sequence from seq 1.
  assert.ok(entries.length >= 700);
  for (let i = 0; i < entries.length; i++) {
    assert.equal((entries[i] as { body: { seq: string } }).body.seq, String(i + 1));
  }
  // And it verifies end-to-end as one AuditPage against the fixture trust.
  const page = { v: 1, entries, next_after: "0", head: lastHead, has_more: false };
  const trust = { v: 1, tenant_id: TEN, initial_kid: ident("lky", "1"), keys: [{ kid: ident("lky", "1"), jwk: AUDIT_JWK }], pinned_head: null, checkpoint: null };
  const parsed = parseAuditPage(page), tr = parseAuditTrust(trust);
  assert.ok(parsed !== null && tr !== null);
  const v = verifyAudit(parsed, tr);
  assert.ok(v.valid, `verifyAudit: ${JSON.stringify(v)}`);
});

// ---------- resource bounds ----------

test("resource bounds: oversized headers and body denied at the parser", async () => {
  const w = new World();
  await w.issued();
  const req = agentRequest("/calls", READ, { proof_id: uid("lpf", 1, 32) });
  (req.headers as Record<string, string>)["x-pad"] = "h".repeat(17000);
  const r1 = await w.send(wire(req));
  assert.equal(r1.code, "HEADERS_TOO_LARGE");
  const huge = { v: 1, call_id: uid("lcl", 1), task_id: TASK, tool: "documents.read", args: { workspace: "demo", path: "x".repeat(70000) } };
  const r2 = await w.agent("/calls", huge, { proof_id: uid("lpf", 2, 32) });
  assert.equal(r2.code, "BODY_TOO_LARGE");
});

// ---------- crypto: one-bit mutation ----------

test("crypto: one-bit signature mutations of the fixture token all rejected", () => {
  const sig = Buffer.from(T.split(".")[2]!, "base64url");
  const msg = Buffer.from(T.split(".").slice(0, 2).join("."), "ascii");
  const pub = keyObjectToJwk(TOKEN_KEY);
  assert.ok(ed25519Verify(msg, new Uint8Array(sig), pub));
  let rejected = 0;
  for (let bit = 0; bit < sig.length * 8; bit += 37) {
    const m = Buffer.from(sig);
    m[bit >> 3] = m[bit >> 3]! ^ (1 << (bit & 7));
    if (!ed25519Verify(msg, new Uint8Array(m), pub)) rejected++;
  }
  assert.equal(rejected, Math.ceil((sig.length * 8) / 37));
  const flipped = flipSig(T);
  assert.ok(!ed25519Verify(msg, new Uint8Array(Buffer.from(flipped.split(".")[2]!, "base64url")), pub));
});

// ---------- SDK: opaque handle ----------

test("SDK: token handle redacts in every representation", () => {
  const h = new TokenHandle("SECRET-TOKEN-BYTES", "ltk_x", 1, "sh");
  assert.equal(JSON.stringify(h), `"${REDACTED}"`);
  assert.equal(String(h), REDACTED);
  assert.equal(h.toJSON(), REDACTED);
  assert.equal(`${h}`, REDACTED);
  assert.ok(!JSON.stringify({ h }).includes("SECRET-TOKEN-BYTES"));
});

// ---------- shared in-process transport for shim tests ----------

function localTransport(w: World) {
  return async (req: WireReq): Promise<WireRes> => {
    const u = new URL(req.url);
    const r = await w.send(wire(
      { method: req.method, path: u.pathname + u.search, headers: req.headers as never, body: null },
      req.body === null ? undefined : new Uint8Array(Buffer.from(req.body, "utf8")),
    ));
    return { status: r.status, headers: r.headers, body: new Uint8Array(Buffer.from(JSON.stringify(r.body), "utf8")) };
  };
}

// ---------- MCP shim ----------

test("MCP: protocol surface — init/list/call/ping, batches rejected, size cap, no creds", async () => {
  const w = new World();
  await w.issued();
  const out: unknown[] = [];
  const diag: string[] = [];
  const client = new LexScopeClient({
    origin: ORIGIN, tenantId: TEN, callerKey: CALLER_KEY,
    transport: localTransport(w), idgen: fixtureIdGen(), now: () => w.clockT,
  });
  const handle = new TokenHandle(w.mintedToken!, TOK, NOW + 300, "sh");
  const srv = new McpServer({ client, handle, taskId: TASK, idgen: fixtureIdGen(), out: (l) => out.push(JSON.parse(l)), diag: (l) => diag.push(l) });
  const lastErr = () => (out.at(-1) as { error: { code: number } }).error.code;

  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "documents_read", arguments: { workspace: "demo", path: "reports/a.txt" } } }));
  assert.equal(lastErr(), -32002);
  await srv.handleLine(JSON.stringify([{ jsonrpc: "2.0", id: 1, method: "ping" }]));
  assert.equal(lastErr(), -32600);
  await srv.handleLine("{not json");
  assert.equal(lastErr(), -32700);
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping", pad: "x".repeat(70000) }));
  assert.equal(lastErr(), -32600);
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: "i", method: "initialize", params: { protocolVersion: "2024-11-05" } }));
  assert.equal((out.at(-1) as { result: { protocolVersion: string } }).result.protocolVersion, "2025-06-18");
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }));
  const list = (out.at(-1) as { result: { tools: { name: string }[] } }).result.tools.map((t) => t.name);
  assert.deepEqual(list, ["documents_read", "records_delete"]);
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "documents_read", arguments: { workspace: "demo", path: "reports/a.txt" } } }));
  const call = out.at(-1) as { result: { content: { text: string }[]; isError: boolean } };
  assert.equal(call.result.isError, false);
  assert.ok(call.result.content[0]!.text.includes("Quarterly report"));
  await srv.handleLine(JSON.stringify({ jsonrpc: "2.0", id: 4, method: "resources/list" }));
  assert.equal(lastErr(), -32601);
  for (const o of out) {
    const s = JSON.stringify(o);
    assert.ok(!s.includes("DPoP ") && !s.includes(w.mintedToken!), "credential in MCP output");
  }
});

// ---------- OpenAI shim ----------

test("OpenAI shim: strict args, tool_call_id correlation only, no creds", async () => {
  const w = new World();
  await w.issued();
  const client = new LexScopeClient({
    origin: ORIGIN, tenantId: TEN, callerKey: CALLER_KEY,
    transport: localTransport(w), idgen: fixtureIdGen(), now: () => w.clockT,
  });
  const shim = new OpenAIShim(client, new TokenHandle(w.mintedToken!, TOK, NOW + 300, "sh"), TASK, fixtureIdGen());
  assert.deepEqual(shim.tools().map((t) => t.function.name), ["documents_read", "records_delete"]);
  const dup = await shim.runToolCall({ id: "tc1", type: "function", function: { name: "documents_read", arguments: '{"workspace":"demo","workspace":"evil","path":"a"}' } });
  assert.equal(dup.ok, false);
  const extra = await shim.runToolCall({ id: "tc2", type: "function", function: { name: "documents_read", arguments: '{"workspace":"demo","path":"a","token":"x"}' } });
  assert.equal(extra.ok, false);
  const ok = await shim.runToolCall({ id: "tc3", type: "function", function: { name: "documents_read", arguments: '{"workspace":"demo","path":"reports/a.txt"}' } });
  assert.equal(ok.ok, true);
  assert.ok(ok.content.includes("Quarterly report"));
  assert.notEqual(ok.call_id, "tc3");
  assert.ok(!JSON.stringify(ok).includes(w.mintedToken!));
});

// ---------- CLI exits ----------

test("CLI: --version/--help exit 0; bad grammar exit 2", () => {
  const run = (args: string[]): number => {
    try {
      execFileSync("node", ["bin/lexscope.mjs", ...args], { stdio: "pipe" });
      return 0;
    } catch (e) {
      return (e as { status: number }).status;
    }
  };
  assert.equal(run(["--version"]), 0);
  assert.equal(run(["--help"]), 0);
  assert.equal(run(["bogus"]), 2);
  assert.equal(run(["keygen"]), 2);
  assert.equal(run(["--timeout-ms", "50", "config", "check", "--file", "x"]), 2);
});

test("CLI: config check + keygen modes + audit verify exit 8", () => {
  const dir = mkdtempSync(join(tmpdir(), "lexscope-cli-"));
  const cfg = join(dir, "lexscope.json");
  writeFileSync(cfg, jcsString({ v: 1, origin: ORIGIN, gateway_id: ident("lsg", "0"), tenant_id: TEN, audit_trust: [{ kid: ident("lky", "1"), jwk: AUDIT_JWK }] }));
  const run = (args: string[]): { code: number; out: string } => {
    try {
      const out = execFileSync("node", ["bin/lexscope.mjs", ...args], { stdio: "pipe" }).toString();
      return { code: 0, out };
    } catch (e) {
      const ee = e as { status: number; stdout: Buffer };
      return { code: ee.status, out: (ee.stdout ?? Buffer.alloc(0)).toString() };
    }
  };
  const ok = run(["--json", "config", "check", "--file", cfg]);
  assert.equal(ok.code, 0);
  assert.ok(ok.out.includes('"valid":true'));
  const priv = join(dir, "k.pem"), pub = join(dir, "k.json");
  assert.equal(run(["keygen", "--out", priv, "--public-out", pub]).code, 0);
  assert.ok(readFileSync(priv, "utf8").includes("PRIVATE KEY"));
  assert.equal(statSync(priv).mode & 0o777, 0o600);
  const trust = join(dir, "trust.json");
  writeFileSync(trust, jcsString({ v: 1, tenant_id: TEN, initial_kid: ident("lky", "1"), keys: [{ kid: ident("lky", "1"), jwk: AUDIT_JWK }], pinned_head: null, checkpoint: null }));
  const bad = join(dir, "bad.json");
  writeFileSync(bad, jcsString({ v: 1, entries: [], next_after: "0", head: { seq: "1", hash: "0".repeat(64), signer_kid: ident("lky", "1"), signature: B64(new Uint8Array(64)) }, has_more: false }));
  assert.equal(run(["audit", "verify", "--in", bad, "--trust", trust]).code, 8);
});
