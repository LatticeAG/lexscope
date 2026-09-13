// Generates conformance/vectors.json — the shared two-language corpus:
//   * 10,000 seeded integer-JSON objects with canonical bytes + sha256
//   * the §15 crypto fixtures (keys, token, audit chain) so Python can verify
//     signatures independently of the TS implementation.
//
// Seeded with 1800000000 per §15.3. Regenerate with: node conformance/gen.mjs

import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { jcsString } from "../src/core/jcs.ts";
import * as fx from "../tests/fixtures.ts";

const SEED = 1800000000;

// mulberry32 — small deterministic PRNG, identical in TS and Python.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rnd = prng(SEED);

function genInt() {
  const m = rnd();
  if (m < 0.3) return Math.floor(rnd() * 10); // small
  if (m < 0.6) return Math.floor(rnd() * 2 ** 32) * (rnd() < 0.5 ? -1 : 1);
  if (m < 0.8) return Math.floor(rnd() * (2 ** 53 - 1)); // safe-integer edge
  return Math.floor(rnd() * 2 ** 31); // 32-bit
}

const WORDS = ["a", "b", "ab", "path", "demo", "wörk", "réports", "é", "é", "Z", "z", "key_9", "😀", "x"];
function genStr() {
  const n = 1 + Math.floor(rnd() * 3);
  return Array.from({ length: n }, () => WORDS[Math.floor(rnd() * WORDS.length)]).join("/");
}

function genValue(depth) {
  const m = rnd();
  if (depth >= 4 || m < 0.5) return genInt();
  if (m < 0.65) return genStr();
  if (m < 0.8) return Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => genValue(depth + 1));
  const o = {};
  const n = 1 + Math.floor(rnd() * 5);
  for (let i = 0; i < n; i++) {
    // keys intentionally out of order to exercise canonical sorting
    const k = `${genStr()}_${Math.floor(rnd() * 97)}`;
    o[k] = genValue(depth + 1);
  }
  return o;
}

const objects = [];
for (let i = 0; i < 10000; i++) {
  const v = genValue(0);
  const input = JSON.stringify(v); // insertion-order input
  const canonical = jcsString(v);
  objects.push({
    i,
    input,
    canonical,
    sha256: createHash("sha256").update(canonical, "utf8").digest("hex"),
  });
}

const fixtures = {
  now: fx.NOW,
  origin: fx.ORIGIN,
  ids: { gateway: fx.G, tenant: fx.TEN, subject: fx.U, task: fx.TASK, token: fx.TOK, call: fx.CALL, op: fx.OP, request: fx.RID, nonce: fx.N, proof: fx.PJ },
  key_seeds: { token: "01", caller: "02", control: "03", audit: "04", next: "05" },
  keys: {
    token_jwk: fx.TOKEN_JWK, caller_jwk: fx.CALLER_JWK, control_jwk: fx.CONTROL_JWK, audit_jwk: fx.AUDIT_JWK, next_jwk: fx.NEXT_JWK,
    caller_jkt: fx.JKT,
  },
  policy: fx.POLICY,
  scopes: fx.SCOPES,
  policy_hash: fx.PH,
  scope_hash: fx.SH,
  mint: fx.MINT,
  claims: fx.CLAIMS,
  token_header: fx.TH,
  token: fx.T,
  minted: fx.MINTED,
  read_call: fx.READ,
  delete_call: fx.DELETE,
  success: fx.SUCCESS,
  audit: { entries: [fx.E1, fx.E2, fx.E3, fx.E4], head: fx.HEAD4 },
};

const doc = { v: 1, seed: SEED, protocol: "lexscope/1", canon_objects: objects, fixtures };
writeFileSync(new URL("./vectors.json", import.meta.url), JSON.stringify(doc));
console.log(`wrote conformance/vectors.json: ${objects.length} canon objects + fixtures`);
