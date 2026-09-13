// Deterministic fixtures — TS port of the normative Python generator in §15.
// Identical byte outputs are required for cross-implementation parity.

import { privateKeyFromSeed, keyObjectToJwk, jwsCompact, jkt, type PublicJwk } from "../src/core/jwt.ts";
import { jcs } from "../src/core/jcs.ts";
import { domainHash, sha256 } from "../src/core/hash.ts";
import { b64uEncode } from "../src/core/b64.ts";
import type { KeyObject } from "node:crypto";

export function B64(data: Uint8Array): string {
  return b64uEncode(data);
}
export function J(value: unknown): Buffer {
  return jcs(value);
}
export function D(tag: string, value: unknown): string {
  return domainHash(tag, value);
}
export function ident(prefix: string, char: string, size = 21): string {
  return prefix + "_" + char.repeat(size);
}
export function key(byte: number): KeyObject {
  return privateKeyFromSeed(new Uint8Array(32).fill(byte));
}
export function jwk(priv: KeyObject): PublicJwk {
  return keyObjectToJwk(priv);
}
export function jwt(header: unknown, payload: unknown, priv: KeyObject): string {
  return jwsCompact(header, payload, priv);
}

export const NOW = 1800000000;
export const ORIGIN = "https://gateway.example.test";
export const G = ident("lsg", "0");
export const TEN = ident("ltn", "0");
export const U = ident("lsu", "0");
export const TASK = ident("lts", "0");
export const TOK = ident("ltk", "0");
export const CALL = ident("lcl", "0");
export const OP = ident("lop", "0");
export const RID = ident("lrq", "0");
export const KID = ident("lky", "0");
export const AKID = ident("lky", "1");
export const CKID = ident("lky", "2");
export const KID2 = ident("lky", "3");
export const N = ident("lnn", "0", 32);
export const PJ = ident("lpf", "0", 32);
export const TOKEN_KEY = key(1);
export const CALLER_KEY = key(2);
export const CONTROL_KEY = key(3);
export const AUDIT_KEY = key(4);
export const NEXT_KEY = key(5);
export const TOKEN_JWK = jwk(TOKEN_KEY);
export const CALLER_JWK = jwk(CALLER_KEY);
export const CONTROL_JWK = jwk(CONTROL_KEY);
export const AUDIT_JWK = jwk(AUDIT_KEY);
export const NEXT_JWK = jwk(NEXT_KEY);
export const JKT = jkt(CALLER_JWK);
export const P = "/v1/tenants/" + TEN;

export const READ_SCOPE = {
  tool: "documents.read",
  where: [
    { ptr: "/path", op: "path_prefix", value: "reports" },
    { ptr: "/workspace", op: "eq", value: "demo" },
  ],
};
export const DELETE_SCOPE = { tool: "records.delete", where: [{ ptr: "/workspace", op: "eq", value: "demo" }] };
export const SCOPES = [READ_SCOPE, DELETE_SCOPE].sort((a, b) => Buffer.compare(J(a), J(b)));
export const POLICY = {
  v: 1,
  revision: "1",
  hard_deny: [] as string[],
  principals: [{ sub: U, scopes: SCOPES, max_ttl_s: 300, herald: "disabled" }],
};
export const POLICY2 = { ...POLICY, revision: "2" };
export const PH = D("LEXSCOPE-POLICY/1", POLICY);
export const SH = D("LEXSCOPE-SCOPES/1", SCOPES);

export const MINT = {
  v: 1, op_id: OP, sub: U, task_id: TASK, caller_jwk: CALLER_JWK,
  scopes: SCOPES, ttl_s: 300, herald: null,
};
export const CLAIMS = {
  v: 1, iss: "urn:lexscope:gateway:" + G, aud: ORIGIN + P,
  tenant_id: TEN, sub: U, task_id: TASK, jti: TOK,
  iat: NOW, nbf: NOW, exp: NOW + 300, cnf: { jkt: JKT },
  scopes: SCOPES, policy_hash: PH, herald: null,
};
export const TH = { alg: "EdDSA", typ: "lexscope+jwt", kid: KID };
export const T = jwt(TH, CLAIMS, TOKEN_KEY);
export const MINTED = {
  v: 1, access_token: T, token_type: "DPoP", token_id: TOK,
  expires_at: NOW + 300, scope_hash: SH, audit_seq: "2",
};
export const READ = {
  v: 1, call_id: CALL, task_id: TASK, tool: "documents.read",
  args: { workspace: "demo", path: "reports/a.txt" },
};
export const DELETE = {
  v: 1, call_id: ident("lcl", "1"), task_id: TASK,
  tool: "records.delete",
  args: { workspace: "demo", record_id: "r1", expected_version: 7 },
};
export const SUCCESS = {
  v: 1, call_id: CALL, state: "SUCCEEDED",
  result: { text: "Quarterly report", version: 7 }, audit_seq: "4", replayed: false,
};
export const HB = {
  source: "herald_local", card_id: "card-demo-1",
  card_hash: D("LEXSCOPE-HERALD-CARD-FIXTURE/1", { id: "card-demo-1" }),
};
export const KEY_VIEW = { kid: KID, purpose: "token", jwk: TOKEN_JWK, state: "ACTIVE", not_before: NOW, verify_until: null };
export const AUDIT_KEY_VIEW = { kid: AKID, purpose: "audit", jwk: AUDIT_JWK, state: "ACTIVE", not_before: NOW, verify_until: null };

export const REVOKE_BODY = { v: 1, op_id: ident("lop", "1"), target: { kind: "token", id: TOK }, reason: "compromised" };
export const POLICY_BODY = { v: 1, op_id: ident("lop", "2"), expected_revision: "1", policy: POLICY2 };
export const ROTATE_BODY = { v: 1, op_id: ident("lop", "3"), expected_kid: KID, new_kid: KID2, new_jwk: NEXT_JWK, secret_ref: "TOKEN_SIGNER_NEXT" };

export interface AgentRequestOpts {
  nonce?: string | null;
  iat?: number;
  proof_id?: string;
  token?: string;
  signer?: KeyObject;
  tenant?: string;
}

export function agentRequest(suffix: string, body: unknown, opts: AgentRequestOpts = {}) {
  const { nonce = null, iat = NOW, proof_id = PJ, token = T, signer = CALLER_KEY, tenant = TEN } = opts;
  const base = "/v1/tenants/" + tenant;
  const call = suffix === "/calls" ? body : suffix === "/nonces" ? (body as { call: unknown }).call : null;
  const proof = {
    v: 1, htm: "POST", htu: ORIGIN + base + suffix, iat,
    jti: proof_id, ath: B64(sha256(Buffer.from(token, "ascii"))),
    bht: D("LEXSCOPE-BODY/1", body),
    call_hash: call !== null ? D("LEXSCOPE-CALL/1", call) : null,
    nonce,
  };
  const signed = jwt({ alg: "EdDSA", typ: "dpop+jwt", jwk: jwk(signer) }, proof, signer);
  return {
    method: "POST",
    path: base + suffix,
    headers: {
      "Content-Type": "application/json",
      Authorization: "DPoP " + token,
      DPoP: signed,
    },
    body,
  };
}

export function controlRequest(suffix: string, body: unknown, opts: { method?: string; iat?: number; proof_id?: string; signer?: KeyObject; kid?: string; tenant?: string } = {}) {
  const { method = "POST", iat = NOW, proof_id = PJ, signer = CONTROL_KEY, kid = CKID, tenant = TEN } = opts;
  const proof = {
    v: 1, tenant_id: tenant, htm: method, htu: ORIGIN + "/v1/tenants/" + tenant + suffix,
    iat, jti: proof_id,
    bht: D("LEXSCOPE-BODY/1", body),
    op_id: body !== null && typeof body === "object" && body !== null ? (body as Record<string, unknown>).op_id ?? null : null,
  };
  const signed = jwt({ alg: "EdDSA", typ: "lexscope-control+jwt", kid }, proof, signer);
  return {
    method,
    path: "/v1/tenants/" + tenant + suffix,
    headers: { "Content-Type": "application/json", "LexScope-Control": signed },
    body,
  };
}

// fresh(n): proof IDs from the spec alphabet, indexed from zero.
const FRESH_ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";
export function fresh(n: number): string {
  return ident("lpf", FRESH_ALPHA[n]!, 32);
}

// patch/add/drop operate on existing dotted dict paths per §15.1.
export function patch<T>(x: T, dotted: string, value: unknown): T {
  const c = JSON.parse(JSON.stringify(x));
  const parts = dotted.split(".");
  let o = c;
  for (let i = 0; i < parts.length - 1; i++) o = o[parts[i]!];
  if (!(parts[parts.length - 1]! in o)) throw new Error("patch path absent: " + dotted);
  o[parts[parts.length - 1]!] = value;
  return c;
}
export function add<T>(x: T, keyName: string, value: unknown): T {
  const c = JSON.parse(JSON.stringify(x));
  if (keyName in c) throw new Error("add would overwrite");
  c[keyName] = value;
  return c;
}
export function drop<T>(x: T, keyName: string): T {
  const c = JSON.parse(JSON.stringify(x));
  delete c[keyName];
  return c;
}

// sign(claims, header=TH): rebuilds a token over the fixture signer.
export function sign(claims: unknown, header: unknown = TH): string {
  return jwt(header, claims, TOKEN_KEY);
}

// resign_proof: decode DPoP, replace one claim, re-sign with CALLER_KEY.
export function resignProof<T extends { headers: Record<string, string> }>(req: T, field: string, value: unknown): T {
  const dpop = req.headers.DPoP!;
  const [h, p] = dpop.split(".");
  const header = JSON.parse(Buffer.from(h!, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(p!, "base64url").toString("utf8"));
  payload[field] = value;
  const signed = jwt(header, payload, CALLER_KEY);
  return { ...req, headers: { ...req.headers, DPoP: signed } };
}

export function flipSig(token: string): string {
  const parts = token.split(".");
  const sig = Buffer.from(parts[2]!, "base64url");
  sig[0] = sig[0]! ^ 1;
  return `${parts[0]!}.${parts[1]!}.${sig.toString("base64url")}`;
}

// ---------- fixture audit entries ----------

import type { AuditEntry, AuditHead, AuditBody } from "../src/core/audit.ts";
import { ed25519Sign } from "../src/core/jwt.ts";
import { unhex } from "../src/core/hash.ts";

export function auditEntry(seq: number, kind: string, prev: string, fields: Partial<AuditBody> = {}): AuditEntry {
  const body: AuditBody = {
    v: 1, schema: "lexscope.audit/1", tenant_id: TEN, seq: String(seq),
    event_id: ident("lev", String(seq)), ts: NOW, prev, signer_kid: AKID,
    kind, sub: null, task_id: null, token_id: null, call_id: null,
    request_id: null, control_kid: null, policy_hash: null, code: "OK",
    call_hash: null, scope_hash: null, nonce_id: null, target: null,
    revision: null, key_id: null, ...fields,
  };
  const digest = D("LEXSCOPE-AUDIT/1", body);
  const signature = ed25519Sign(Buffer.concat([Buffer.from("LEXSCOPE-AUDIT-SIGN/1", "ascii"), Buffer.from([0]), unhex(digest)!]), AUDIT_KEY);
  return { body, hash: digest, signature: B64(signature) };
}

export const E1 = auditEntry(1, "deployment.installed", "0".repeat(64), { policy_hash: PH, revision: "1" });
export const E2 = auditEntry(2, "token.minted", E1.hash, { sub: U, task_id: TASK, token_id: TOK, policy_hash: PH, scope_hash: SH, request_id: RID, control_kid: CKID });
export const CALL_FIELDS = {
  sub: U, task_id: TASK, token_id: TOK, call_id: CALL,
  request_id: RID, policy_hash: PH, scope_hash: SH, call_hash: D("LEXSCOPE-CALL/1", READ),
};
export const E3 = auditEntry(3, "call.admitted", E2.hash, CALL_FIELDS);
export const E4 = auditEntry(4, "call.succeeded", E3.hash, CALL_FIELDS);
const headBody4 = { tenant_id: TEN, seq: "4", hash: E4.hash, signer_kid: AKID };
export const HEAD4: AuditHead = {
  seq: "4", hash: E4.hash, signer_kid: AKID,
  signature: B64(ed25519Sign(Buffer.concat([Buffer.from("LEXSCOPE-HEAD/1", "ascii"), Buffer.from([0]), J(headBody4)]), AUDIT_KEY)),
};

export const GATEWAY_CONFIG = {
  v: 1,
  mode: "test",
  origin: ORIGIN,
  gateway_id: G,
  tenant_id: TEN,
  tenant_do_binding: "TENANTS",
  policy: POLICY,
  controls: [{ kid: CKID, jwk: CONTROL_JWK, roles: ["auditor", "minter", "operator"], subjects: [U] }],
  token_signer: { kid: KID, jwk: TOKEN_JWK, secret_ref: "TOKEN_SIGNER" },
  audit_signer: { kid: AKID, jwk: AUDIT_JWK, secret_ref: "AUDIT_SIGNER" },
  encryption: { key_ref: "DATA_KEY", key_version: "1" },
  tools: { documents_read_binding: "DOCS", records_delete_binding: "RECS" },
  herald_sources: [{ name: "herald_local", binding: "HERALD", trust_key: jwk(key(9)) }],
};

export function fixtureSecrets(): Map<string, KeyObject> {
  return new Map([
    ["TOKEN_SIGNER", TOKEN_KEY],
    ["AUDIT_SIGNER", AUDIT_KEY],
    ["TOKEN_SIGNER_NEXT", NEXT_KEY],
  ]);
}

export const DATA_KEY = new Uint8Array(32).fill(7);
