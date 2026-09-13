// Closed runtime validators for every §4 wire type and §4.1 scalar refinement.
// All objects are closed: unknown members are errors. Validators walk object
// members in UTF-16 key order and throw the first violation, so the reported
// pointer is the lexicographically-first offending JSON pointer.

import { isId, isCounter, idValidators } from "./ids.ts";
import { jcs, jcsString, utf16Compare, type Json } from "./jcs.ts";
import { b64uDecode } from "./b64.ts";

export class SchemaIssue extends Error {
  ptr: string;
  code: "SCHEMA_INVALID" | "VERSION_UNSUPPORTED" | "CHAINING_FORBIDDEN" | "SCOPE_TOO_LARGE" | "TTL_INVALID";
  constructor(ptr: string, msg: string, code: SchemaIssue["code"] = "SCHEMA_INVALID") {
    super(msg);
    this.ptr = ptr;
    this.code = code;
  }
}

function issue(ptr: string, msg: string): never {
  throw new SchemaIssue(ptr, msg);
}

export function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Closed object check: required members present, no unknown members; iterates
// sorted keys so nested violations surface in UTF-16 pointer order.
function closed(v: unknown, ptr: string, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!isObj(v)) issue(ptr || "/", "expected object");
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(v).sort(utf16Compare);
  for (const k of keys) if (!allowed.has(k)) issue(`${ptr}/${k}`, "unknown member");
  for (const k of required) if (!(k in v)) issue(`${ptr}/${k}`, "missing member");
  return v;
}

function typ(v: unknown, t: string, ptr: string): void {
  if (t === "string" && typeof v !== "string") issue(ptr, "expected string");
  if (t === "number" && (typeof v !== "number" || !Number.isSafeInteger(v))) issue(ptr, "expected safe integer");
  if (t === "boolean" && typeof v !== "boolean") issue(ptr, "expected boolean");
  if (t === "array" && !Array.isArray(v)) issue(ptr, "expected array");
  if (t === "object" && !isObj(v)) issue(ptr, "expected object");
  if (t === "scalar" && !(typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isSafeInteger(v))))
    issue(ptr, "expected scalar");
}

function idField(v: unknown, prefix: string, ptr: string, size = 21): string {
  if (!isId(v, prefix, size)) issue(ptr, `expected ${prefix}_ id`);
  return v;
}

function hashField(v: unknown, ptr: string): string {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) issue(ptr, "expected 64-hex hash");
  return v;
}

export function isHash(v: unknown): v is string {
  return typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
}

function b64u32(v: unknown, ptr: string): string {
  if (typeof v !== "string") issue(ptr, "expected b64u");
  const b = b64uDecode(v);
  if (b === null || b.length !== 32) issue(ptr, "expected 32-byte b64u");
  return v;
}

function counterField(v: unknown, ptr: string): string {
  if (!isCounter(v)) issue(ptr, "expected decimal counter");
  return v;
}

// ---------- scalar grammars ----------

export const IDENT_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/; // workspace / record_id
const PATH_SEG_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PTR_SEG_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
export const TOOL_NAME_RE = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/;

export function isWorkspace(v: unknown): v is string {
  return typeof v === "string" && IDENT_RE.test(v);
}

export function isPath(v: unknown): v is string {
  if (typeof v !== "string") return false;
  if (v.length === 0 || Buffer.byteLength(v, "utf8") > 512) return false;
  if (/%|\\/.test(v)) return false;
  if (!/^[\x20-\x7e]+$/.test(v)) return false; // ASCII only
  if (v.startsWith("/") || v.endsWith("/")) return false;
  const segs = v.split("/");
  if (segs.length < 1 || segs.length > 16) return false;
  for (const s of segs) {
    if (s === "." || s === ".." || !PATH_SEG_RE.test(s)) return false;
  }
  return true;
}

export function isPointer(v: unknown): v is string {
  if (typeof v !== "string" || !v.startsWith("/")) return false;
  const segs = v.slice(1).split("/");
  if (segs.length < 1 || segs.length > 8) return false;
  return segs.every((s) => PTR_SEG_RE.test(s));
}

// ---------- tool registry ----------

export type ToolName = "documents.read" | "records.delete";
export const TOOLS: Record<ToolName, { destructive: boolean }> = {
  "documents.read": { destructive: false },
  "records.delete": { destructive: true },
};

export function isToolName(v: unknown): v is ToolName {
  return typeof v === "string" && Object.prototype.hasOwnProperty.call(TOOLS, v);
}

// ---------- predicates ----------

export type Predicate =
  | { ptr: string; op: "eq"; value: string | number | boolean }
  | { ptr: string; op: "in"; values: (string | number | boolean)[] }
  | { ptr: string; op: "int_range"; min: number; max: number }
  | { ptr: string; op: "path_prefix"; value: string };

// The complete predicate domain (§4.1): pointer -> allowed operators + operand rule.
export const PREDICATE_DOMAIN: Record<ToolName, Record<string, { ops: string[]; operand: (v: unknown) => boolean }>> = {
  "documents.read": {
    "/workspace": { ops: ["eq", "in"], operand: isWorkspace },
    "/path": { ops: ["eq", "in", "path_prefix"], operand: isPath },
  },
  "records.delete": {
    "/workspace": { ops: ["eq", "in"], operand: isWorkspace },
    "/record_id": { ops: ["eq", "in"], operand: IDENT_RE.test.bind(IDENT_RE) as (v: unknown) => boolean },
    "/expected_version": {
      ops: ["eq", "in", "int_range"],
      operand: (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0,
    },
  },
};

function validPredicateShape(v: unknown, ptr: string): Predicate {
  const o = closed(v, ptr, ["ptr", "op"], ["value", "values", "min", "max"]);
  if (!isPointer(o.ptr)) issue(`${ptr}/ptr`, "bad pointer");
  const op = o.op;
  if (op === "eq") {
    closed(v, ptr, ["ptr", "op", "value"]);
    typ(o.value, "scalar", `${ptr}/value`);
  } else if (op === "in") {
    closed(v, ptr, ["ptr", "op", "values"]);
    typ(o.values, "array", `${ptr}/values`);
    const vals = o.values as unknown[];
    if (vals.length < 1 || vals.length > 16) issue(`${ptr}/values`, "1..16 members");
    let t: string | null = null;
    for (let i = 0; i < vals.length; i++) {
      typ(vals[i], "scalar", `${ptr}/values/${i}`);
      const vt = typeof vals[i];
      if (t === null) t = vt;
      else if (vt !== t) issue(`${ptr}/values/${i}`, "mixed types");
    }
    // sorted by UTF-8 bytes of JCS encodings; duplicates rejected
    const enc = vals.map((x) => jcs(x as Json));
    for (let i = 1; i < enc.length; i++) {
      const cmp = Buffer.compare(enc[i - 1]!, enc[i]!);
      if (cmp === 0) issue(`${ptr}/values/${i}`, "duplicate");
      if (cmp > 0) issue(`${ptr}/values`, "not sorted");
    }
  } else if (op === "int_range") {
    closed(v, ptr, ["ptr", "op", "min", "max"]);
    typ(o.min, "number", `${ptr}/min`);
    typ(o.max, "number", `${ptr}/max`);
    if ((o.min as number) > (o.max as number)) issue(`${ptr}/max`, "min>max");
  } else if (op === "path_prefix") {
    closed(v, ptr, ["ptr", "op", "value"]);
    typ(o.value, "string", `${ptr}/value`);
  } else issue(`${ptr}/op`, "unknown operator");
  return v as unknown as Predicate;
}

// Full predicate validation including the pointer domain and operand grammar.
export function validatePredicate(v: unknown, tool: ToolName, ptr: string): Predicate {
  const p = validPredicateShape(v, ptr);
  const dom = PREDICATE_DOMAIN[tool][p.ptr];
  if (!dom) issue(`${ptr}/ptr`, "pointer outside domain");
  if (!dom.ops.includes(p.op)) issue(`${ptr}/op`, "operator not allowed at pointer");
  // operand grammar on literal values
  if (p.op === "eq" || p.op === "path_prefix") {
    if (!dom.operand(p.value)) issue(`${ptr}/value`, "operand grammar");
  } else if (p.op === "in") {
    for (let i = 0; i < p.values.length; i++)
      if (!dom.operand(p.values[i])) issue(`${ptr}/values/${i}`, "operand grammar");
  } else if (p.op === "int_range") {
    if (!dom.operand(p.min)) issue(`${ptr}/min`, "operand grammar");
    if (!dom.operand(p.max)) issue(`${ptr}/max`, "operand grammar");
  }
  return p;
}

// Shape-only validation (domain-independent), used where the tool is fixed later.
export function validatePredicateShape(v: unknown, ptr: string): Predicate {
  return validPredicateShape(v, ptr);
}

// ---------- scopes ----------

export interface Scope {
  tool: ToolName;
  where: Predicate[];
}

export function validateScope(v: unknown, ptr: string): Scope {
  const o = closed(v, ptr, ["tool", "where"]);
  if (!isToolName(o.tool)) issue(`${ptr}/tool`, "unregistered tool");
  typ(o.where, "array", `${ptr}/where`);
  const where = o.where as unknown[];
  if (where.length > 8) issue(`${ptr}/where`, "too many predicates");
  const preds: Predicate[] = [];
  const seenPtr = new Set<string>();
  // must arrive sorted by pointer then UTF-8 bytes of J(predicate)
  let prevKey = "";
  for (let i = 0; i < where.length; i++) {
    const p = validatePredicate(where[i], o.tool as ToolName, `${ptr}/where/${i}`);
    if (seenPtr.has(p.ptr)) issue(`${ptr}/where/${i}`, "duplicate pointer");
    seenPtr.add(p.ptr);
    const key = p.ptr + "" + jcsString(where[i]);
    if (i > 0 && prevKey >= key) issue(`${ptr}/where/${i}`, "where not sorted");
    prevKey = key;
    preds.push(p);
  }
  return { tool: o.tool as ToolName, where: preds };
}

export function validateScopeSet(v: unknown, ptr: string): Scope[] {
  typ(v, "array", ptr);
  const arr = v as unknown[];
  if (arr.length < 1 || arr.length > 8) issue(ptr, "1..8 scopes");
  const scopes = arr.map((s, i) => validateScope(s, `${ptr}/${i}`));
  const enc = arr.map((s) => jcs(s as Json));
  for (let i = 1; i < enc.length; i++) {
    const cmp = Buffer.compare(enc[i - 1]!, enc[i]!);
    if (cmp === 0) issue(`${ptr}/${i}`, "duplicate scope");
    if (cmp > 0) issue(ptr, "scopes not sorted");
  }
  const total = Buffer.concat(enc).length + 2 + Math.max(0, enc.length - 1);
  if (total > 4096) throw new SchemaIssue(ptr, "scope set too large", "SCOPE_TOO_LARGE");
  return scopes;
}

// ---------- jwk ----------

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export function validatePublicJwk(v: unknown, ptr: string): PublicJwk {
  const o = closed(v, ptr, ["kty", "crv", "x"]);
  if (o.kty !== "OKP") issue(`${ptr}/kty`, "kty");
  if (o.crv !== "Ed25519") issue(`${ptr}/crv`, "crv");
  b64u32(o.x, `${ptr}/x`);
  return o as unknown as PublicJwk;
}

// ---------- herald ----------

export interface HeraldBinding {
  source: string;
  card_id: string;
  card_hash: string;
}

const HERALD_SOURCE_RE = /^[a-z][a-z0-9_-]{0,31}$/;

export function validateHeraldBinding(v: unknown, ptr: string): HeraldBinding {
  const o = closed(v, ptr, ["source", "card_id", "card_hash"]);
  if (typeof o.source !== "string" || !HERALD_SOURCE_RE.test(o.source)) issue(`${ptr}/source`, "bad source");
  if (
    typeof o.card_id !== "string" ||
    o.card_id.length === 0 ||
    Buffer.byteLength(o.card_id, "utf8") > 128 ||
    // eslint-disable-next-line no-control-regex
    /[\x00-\x1f\x7f-\x9f]/.test(o.card_id)
  )
    issue(`${ptr}/card_id`, "bad card_id");
  hashField(o.card_hash, `${ptr}/card_hash`);
  return o as unknown as HeraldBinding;
}

// ---------- mint ----------

export interface MintRequest {
  v: 1;
  op_id: string;
  sub: string;
  task_id: string;
  caller_jwk: PublicJwk;
  scopes: Scope[];
  ttl_s: number;
  herald: HeraldBinding | null;
}

export function validateMintRequest(v: unknown): MintRequest {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "op_id", "sub", "task_id", "caller_jwk", "scopes", "ttl_s", "herald"]);
  idField(o.op_id, "lop", "/op_id");
  idField(o.sub, "lsu", "/sub");
  idField(o.task_id, "lts", "/task_id");
  validatePublicJwk(o.caller_jwk, "/caller_jwk");
  const scopes = validateScopeSet(o.scopes, "/scopes");
  typ(o.ttl_s, "number", "/ttl_s");
  if (o.herald !== null) validateHeraldBinding(o.herald, "/herald");
  return { ...(o as unknown as MintRequest), scopes };
}

// ---------- token ----------

export interface TokenClaims {
  v: 1;
  iss: string;
  aud: string;
  tenant_id: string;
  sub: string;
  task_id: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  cnf: { jkt: string };
  scopes: Scope[];
  policy_hash: string;
  herald: HeraldBinding | null;
}

const FORBIDDEN_DELEGATION = new Set(["chain", "parent", "delegation", "act", "may_act"]);

// Checks forbidden delegation members and nested JWTs in a decoded header or
// claims object. Runs before closed-schema checks per §5.3 sub-order.
export function checkNoChaining(o: Record<string, unknown>, ptr: string): void {
  for (const k of Object.keys(o).sort(utf16Compare)) {
    if (FORBIDDEN_DELEGATION.has(k)) throw new SchemaIssue(`${ptr}/${k}`, "delegation member", "CHAINING_FORBIDDEN");
    const val = o[k];
    if (typeof val === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(val))
      throw new SchemaIssue(`${ptr}/${k}`, "nested jwt", "CHAINING_FORBIDDEN");
  }
}

export function validateTokenHeader(v: unknown): { kid: string } {
  const o = closed(v, "", ["alg", "typ", "kid"]);
  if (o.alg !== "EdDSA") issue("/alg", "alg");
  if (o.typ !== "lexscope+jwt") issue("/typ", "typ");
  idField(o.kid, "lky", "/kid");
  return { kid: o.kid as string };
}

export function validateTokenClaims(v: unknown): TokenClaims {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "iss", "aud", "tenant_id", "sub", "task_id", "jti", "iat", "nbf", "exp", "cnf", "scopes", "policy_hash", "herald"]);
  typ(o.iss, "string", "/iss");
  typ(o.aud, "string", "/aud");
  idField(o.tenant_id, "ltn", "/tenant_id");
  idField(o.sub, "lsu", "/sub");
  idField(o.task_id, "lts", "/task_id");
  idField(o.jti, "ltk", "/jti");
  typ(o.iat, "number", "/iat");
  typ(o.nbf, "number", "/nbf");
  typ(o.exp, "number", "/exp");
  const cnf = closed(o.cnf, "/cnf", ["jkt"]);
  b64u32(cnf.jkt, "/cnf/jkt");
  const scopes = validateScopeSet(o.scopes, "/scopes");
  hashField(o.policy_hash, "/policy_hash");
  if (o.herald !== null) validateHeraldBinding(o.herald, "/herald");
  return { ...(o as unknown as TokenClaims), scopes };
}

// ---------- proofs ----------

export interface CallerProof {
  v: 1;
  htm: "POST";
  htu: string;
  iat: number;
  jti: string;
  ath: string;
  bht: string;
  call_hash: string | null;
  nonce: string | null;
}

export function validateProofHeader(v: unknown): PublicJwk {
  const o = closed(v, "", ["alg", "typ", "jwk"]);
  if (o.alg !== "EdDSA") issue("/alg", "alg");
  if (o.typ !== "dpop+jwt") issue("/typ", "typ");
  return validatePublicJwk(o.jwk, "/jwk");
}

export function validateCallerProof(v: unknown): CallerProof {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "htm", "htu", "iat", "jti", "ath", "bht", "call_hash", "nonce"]);
  if (o.htm !== "POST") issue("/htm", "htm");
  typ(o.htu, "string", "/htu");
  typ(o.iat, "number", "/iat");
  idField(o.jti, "lpf", "/jti", 32);
  b64u32(o.ath, "/ath");
  hashField(o.bht, "/bht");
  if (o.call_hash !== null) hashField(o.call_hash, "/call_hash");
  if (o.nonce !== null) idField(o.nonce, "lnn", "/nonce", 32);
  return o as unknown as CallerProof;
}

export function validateControlHeader(v: unknown): { kid: string } {
  const o = closed(v, "", ["alg", "typ", "kid"]);
  if (o.alg !== "EdDSA") issue("/alg", "alg");
  if (o.typ !== "lexscope-control+jwt") issue("/typ", "typ");
  idField(o.kid, "lky", "/kid");
  return { kid: o.kid as string };
}

export interface ControlProof {
  v: 1;
  tenant_id: string;
  htm: "GET" | "POST";
  htu: string;
  iat: number;
  jti: string;
  bht: string;
  op_id: string | null;
}

export function validateControlProof(v: unknown): ControlProof {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "tenant_id", "htm", "htu", "iat", "jti", "bht", "op_id"]);
  idField(o.tenant_id, "ltn", "/tenant_id");
  if (o.htm !== "GET" && o.htm !== "POST") issue("/htm", "htm");
  typ(o.htu, "string", "/htu");
  typ(o.iat, "number", "/iat");
  idField(o.jti, "lpf", "/jti", 32);
  hashField(o.bht, "/bht");
  if (o.op_id !== null) idField(o.op_id, "lop", "/op_id");
  return o as unknown as ControlProof;
}

// ---------- tool calls ----------

export interface ReadArgs {
  workspace: string;
  path: string;
}
export interface DeleteArgs {
  workspace: string;
  record_id: string;
  expected_version: number;
}
export type ToolCall =
  | { v: 1; call_id: string; task_id: string; tool: "documents.read"; args: ReadArgs }
  | { v: 1; call_id: string; task_id: string; tool: "records.delete"; args: DeleteArgs };

export function validateArgs(v: unknown, tool: ToolName, ptr: string): ReadArgs | DeleteArgs {
  if (tool === "documents.read") {
    const o = closed(v, ptr, ["workspace", "path"]);
    if (!isWorkspace(o.workspace)) issue(`${ptr}/workspace`, "workspace grammar");
    if (!isPath(o.path)) issue(`${ptr}/path`, "path grammar");
    return o as unknown as ReadArgs;
  }
  const o = closed(v, ptr, ["workspace", "record_id", "expected_version"]);
  if (!isWorkspace(o.workspace)) issue(`${ptr}/workspace`, "workspace grammar");
  if (typeof o.record_id !== "string" || !IDENT_RE.test(o.record_id)) issue(`${ptr}/record_id`, "record id grammar");
  typ(o.expected_version, "number", `${ptr}/expected_version`);
  if ((o.expected_version as number) < 0) issue(`${ptr}/expected_version`, "negative");
  return o as unknown as DeleteArgs;
}

export function validateToolCall(v: unknown, ptr = ""): ToolCall {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue(`${ptr}/v`, "version", "VERSION_UNSUPPORTED");
  const o = closed(v, ptr, ["v", "call_id", "task_id", "tool", "args"]);
  idField(o.call_id, "lcl", `${ptr}/call_id`);
  idField(o.task_id, "lts", `${ptr}/task_id`);
  if (!isToolName(o.tool)) issue(`${ptr}/tool`, "unregistered tool");
  validateArgs(o.args, o.tool as ToolName, `${ptr}/args`);
  return o as unknown as ToolCall;
}

export function validateNonceRequest(v: unknown): { v: 1; call: ToolCall } {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "call"]);
  const call = validateToolCall(o.call, "/call");
  return { v: 1, call };
}

export function validateResultRequest(v: unknown): { v: 1; task_id: string; call_id: string } {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "task_id", "call_id"]);
  idField(o.task_id, "lts", "/task_id");
  idField(o.call_id, "lcl", "/call_id");
  return o as unknown as { v: 1; task_id: string; call_id: string };
}

// ---------- control bodies ----------

export type RevokeTarget =
  | { kind: "token"; id: string }
  | { kind: "task"; id: string }
  | { kind: "subject"; id: string }
  | { kind: "signing_key"; id: string };

const TARGET_PREFIX: Record<string, string> = {
  token: "ltk",
  task: "lts",
  subject: "lsu",
  signing_key: "lky",
};

export function validateRevokeTarget(v: unknown, ptr: string): RevokeTarget {
  const o = closed(v, ptr, ["kind", "id"]);
  if (typeof o.kind !== "string" || !(o.kind in TARGET_PREFIX)) issue(`${ptr}/kind`, "bad kind");
  idField(o.id, TARGET_PREFIX[o.kind as string]!, `${ptr}/id`);
  return o as unknown as RevokeTarget;
}

const REVOKE_REASONS = new Set(["task_finished", "compromised", "operator_request"]);

export interface RevokeRequest {
  v: 1;
  op_id: string;
  target: RevokeTarget;
  reason: string;
}

export function validateRevokeRequest(v: unknown): RevokeRequest {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "op_id", "target", "reason"]);
  idField(o.op_id, "lop", "/op_id");
  validateRevokeTarget(o.target, "/target");
  if (typeof o.reason !== "string" || !REVOKE_REASONS.has(o.reason)) issue("/reason", "bad reason");
  return o as unknown as RevokeRequest;
}

export function validateTokenInspectRequest(v: unknown): { v: 1; token_id: string } {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "token_id"]);
  idField(o.token_id, "ltk", "/token_id");
  return o as unknown as { v: 1; token_id: string };
}

// ---------- policy ----------

export interface Principal {
  sub: string;
  scopes: Scope[];
  max_ttl_s: number;
  herald: "disabled" | "required";
}

export interface Policy {
  v: 1;
  revision: string;
  hard_deny: string[];
  principals: Principal[];
}

export function validatePolicy(v: unknown, ptr = ""): Policy {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue(`${ptr}/v`, "version", "VERSION_UNSUPPORTED");
  const o = closed(v, ptr, ["v", "revision", "hard_deny", "principals"]);
  counterField(o.revision, `${ptr}/revision`);
  typ(o.hard_deny, "array", `${ptr}/hard_deny`);
  const hd = o.hard_deny as unknown[];
  if (hd.length > 2) issue(`${ptr}/hard_deny`, "at most two");
  for (let i = 0; i < hd.length; i++) {
    if (!isToolName(hd[i])) issue(`${ptr}/hard_deny/${i}`, "unregistered tool");
    if (i > 0 && (hd[i - 1] as string) >= (hd[i] as string)) issue(`${ptr}/hard_deny/${i}`, "not sorted/duplicate");
  }
  typ(o.principals, "array", `${ptr}/principals`);
  const prins = o.principals as unknown[];
  if (prins.length > 128) issue(`${ptr}/principals`, "at most 128");
  let prevSub = "";
  const out: Principal[] = [];
  for (let i = 0; i < prins.length; i++) {
    const p = closed(prins[i], `${ptr}/principals/${i}`, ["sub", "scopes", "max_ttl_s", "herald"]);
    idField(p.sub, "lsu", `${ptr}/principals/${i}/sub`);
    if (i > 0 && prevSub >= (p.sub as string)) issue(`${ptr}/principals/${i}/sub`, "not sorted/duplicate");
    prevSub = p.sub as string;
    const scopes = validateScopeSet(p.scopes, `${ptr}/principals/${i}/scopes`);
    typ(p.max_ttl_s, "number", `${ptr}/principals/${i}/max_ttl_s`);
    if (p.herald !== "disabled" && p.herald !== "required") issue(`${ptr}/principals/${i}/herald`, "bad herald mode");
    out.push({ sub: p.sub as string, scopes, max_ttl_s: p.max_ttl_s as number, herald: p.herald as "disabled" | "required" });
  }
  return { v: 1, revision: o.revision as string, hard_deny: hd as string[], principals: out };
}

export interface PolicyApplyRequest {
  v: 1;
  op_id: string;
  expected_revision: string;
  policy: Policy;
}

export function validatePolicyApplyRequest(v: unknown): PolicyApplyRequest {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "op_id", "expected_revision", "policy"]);
  idField(o.op_id, "lop", "/op_id");
  counterField(o.expected_revision, "/expected_revision");
  const policy = validatePolicy(o.policy, "/policy");
  return { v: 1, op_id: o.op_id as string, expected_revision: o.expected_revision as string, policy };
}

export interface RotateRequest {
  v: 1;
  op_id: string;
  expected_kid: string;
  new_kid: string;
  new_jwk: PublicJwk;
  secret_ref: string;
}

export const SECRET_REF_RE = /^[A-Z][A-Z0-9_]{0,63}$/;

export function validateRotateRequest(v: unknown): RotateRequest {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "op_id", "expected_kid", "new_kid", "new_jwk", "secret_ref"]);
  idField(o.op_id, "lop", "/op_id");
  idField(o.expected_kid, "lky", "/expected_kid");
  idField(o.new_kid, "lky", "/new_kid");
  validatePublicJwk(o.new_jwk, "/new_jwk");
  if (typeof o.secret_ref !== "string" || !SECRET_REF_RE.test(o.secret_ref)) issue("/secret_ref", "bad secret ref");
  return o as unknown as RotateRequest;
}

// ---------- results (adapter-reported) ----------

export function validateToolResult(v: unknown, tool: ToolName): ReadResultT | DeleteResultT {
  if (tool === "documents.read") {
    const o = closed(v, "", ["text", "version"]);
    typ(o.text, "string", "/text");
    typ(o.version, "number", "/version");
    if ((o.version as number) < 0) issue("/version", "negative");
    return o as unknown as ReadResultT;
  }
  const o = closed(v, "", ["deleted", "version"]);
  typ(o.deleted, "boolean", "/deleted");
  typ(o.version, "number", "/version");
  if ((o.version as number) < 0) issue("/version", "negative");
  return o as unknown as DeleteResultT;
}

export interface ReadResultT {
  text: string;
  version: number;
}
export interface DeleteResultT {
  deleted: boolean;
  version: number;
}

// ---------- configuration ----------

export interface ControlEnrollment {
  kid: string;
  jwk: PublicJwk;
  roles: ("minter" | "operator" | "auditor")[];
  subjects: string[];
}

export interface GatewayConfigT {
  v: 1;
  mode: "production" | "test";
  origin: string;
  gateway_id: string;
  tenant_id: string;
  tenant_do_binding: "TENANTS";
  policy: Policy;
  controls: ControlEnrollment[];
  token_signer: { kid: string; jwk: PublicJwk; secret_ref: string };
  audit_signer: { kid: string; jwk: PublicJwk; secret_ref: string };
  encryption: { key_ref: string; key_version: string };
  tools: { documents_read_binding: string; records_delete_binding: string };
  herald_sources: { name: string; binding: string; trust_key: PublicJwk }[];
}

const ROLES = new Set(["minter", "operator", "auditor"]);

export function validateOrigin(v: unknown, ptr: string): string {
  if (typeof v !== "string") issue(ptr, "expected string");
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    issue(ptr, "bad origin");
  }
  if (u!.protocol !== "https:" && v !== "http://127.0.0.1:8787") issue(ptr, "origin must be https");
  if (u!.username || u!.password || u!.search || u!.hash) issue(ptr, "origin decoration");
  if (u!.pathname !== "/" || v.endsWith("/")) issue(ptr, "origin path/slash");
  if (u!.hostname !== u!.hostname.toLowerCase()) issue(ptr, "origin case");
  if ((u!.protocol === "https:" && u!.port === "443") || (u!.protocol === "http:" && u!.port === "80")) issue(ptr, "default port");
  return v;
}

export function validateGatewayConfig(v: unknown): GatewayConfigT {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "mode", "origin", "gateway_id", "tenant_id", "tenant_do_binding", "policy", "controls", "token_signer", "audit_signer", "encryption", "tools", "herald_sources"]);
  if (o.mode !== "production" && o.mode !== "test") issue("/mode", "bad mode");
  validateOrigin(o.origin, "/origin");
  if (o.mode === "production" && typeof o.origin === "string" && !o.origin.startsWith("https:")) issue("/origin", "production requires https");
  idField(o.gateway_id, "lsg", "/gateway_id");
  idField(o.tenant_id, "ltn", "/tenant_id");
  if (o.tenant_do_binding !== "TENANTS") issue("/tenant_do_binding", "bad binding");
  const policy = validatePolicy(o.policy, "/policy");
  typ(o.controls, "array", "/controls");
  const controls = o.controls as unknown[];
  let prevKid = "";
  const cOut: ControlEnrollment[] = [];
  for (let i = 0; i < controls.length; i++) {
    const c = closed(controls[i], `/controls/${i}`, ["kid", "jwk", "roles", "subjects"]);
    idField(c.kid, "lky", `/controls/${i}/kid`);
    if (i > 0 && prevKid >= (c.kid as string)) issue(`/controls/${i}/kid`, "not sorted/duplicate");
    prevKid = c.kid as string;
    validatePublicJwk(c.jwk, `/controls/${i}/jwk`);
    typ(c.roles, "array", `/controls/${i}/roles`);
    const roles = c.roles as unknown[];
    if (roles.length < 1) issue(`/controls/${i}/roles`, "empty roles");
    for (let r = 0; r < roles.length; r++) {
      if (typeof roles[r] !== "string" || !ROLES.has(roles[r] as string)) issue(`/controls/${i}/roles/${r}`, "bad role");
      if (r > 0 && (roles[r - 1] as string) >= (roles[r] as string)) issue(`/controls/${i}/roles/${r}`, "roles not sorted/duplicate");
    }
    typ(c.subjects, "array", `/controls/${i}/subjects`);
    const subs = c.subjects as unknown[];
    for (let s = 0; s < subs.length; s++) {
      idField(subs[s], "lsu", `/controls/${i}/subjects/${s}`);
      if (s > 0 && (subs[s - 1] as string) >= (subs[s] as string)) issue(`/controls/${i}/subjects/${s}`, "subjects not sorted/duplicate");
    }
    cOut.push(c as unknown as ControlEnrollment);
  }
  const ts = closed(o.token_signer, "/token_signer", ["kid", "jwk", "secret_ref"]);
  idField(ts.kid, "lky", "/token_signer/kid");
  validatePublicJwk(ts.jwk, "/token_signer/jwk");
  if (typeof ts.secret_ref !== "string" || !SECRET_REF_RE.test(ts.secret_ref)) issue("/token_signer/secret_ref", "bad ref");
  const as_ = closed(o.audit_signer, "/audit_signer", ["kid", "jwk", "secret_ref"]);
  idField(as_.kid, "lky", "/audit_signer/kid");
  validatePublicJwk(as_.jwk, "/audit_signer/jwk");
  if (typeof as_.secret_ref !== "string" || !SECRET_REF_RE.test(as_.secret_ref)) issue("/audit_signer/secret_ref", "bad ref");
  const enc = closed(o.encryption, "/encryption", ["key_ref", "key_version"]);
  if (typeof enc.key_ref !== "string" || !SECRET_REF_RE.test(enc.key_ref)) issue("/encryption/key_ref", "bad ref");
  counterField(enc.key_version, "/encryption/key_version");
  const tools = closed(o.tools, "/tools", ["documents_read_binding", "records_delete_binding"]);
  typ(tools.documents_read_binding, "string", "/tools/documents_read_binding");
  typ(tools.records_delete_binding, "string", "/tools/records_delete_binding");
  typ(o.herald_sources, "array", "/herald_sources");
  const hs = o.herald_sources as unknown[];
  let prevName = "";
  for (let i = 0; i < hs.length; i++) {
    const h = closed(hs[i], `/herald_sources/${i}`, ["name", "binding", "trust_key"]);
    if (typeof h.name !== "string" || !HERALD_SOURCE_RE.test(h.name)) issue(`/herald_sources/${i}/name`, "bad name");
    if (i > 0 && prevName >= (h.name as string)) issue(`/herald_sources/${i}/name`, "not sorted/duplicate");
    prevName = h.name as string;
    typ(h.binding, "string", `/herald_sources/${i}/binding`);
    validatePublicJwk(h.trust_key, `/herald_sources/${i}/trust_key`);
  }
  // cross-field: no Ed25519 public key may repeat across purposes
  const seen = new Map<string, string>();
  const note = (x: string, where: string) => {
    if (seen.has(x)) issue(where, "key reused across purposes");
    seen.set(x, where);
  };
  note((ts.jwk as PublicJwk).x, "/token_signer/jwk");
  note((as_.jwk as PublicJwk).x, "/audit_signer/jwk");
  cOut.forEach((c, i) => note(c.jwk.x, `/controls/${i}/jwk`));
  (o.herald_sources as unknown[]).forEach((h, i) =>
    note(((h as Record<string, unknown>).trust_key as PublicJwk).x, `/herald_sources/${i}/trust_key`),
  );
  return { ...(o as unknown as GatewayConfigT), policy, controls: cOut };
}

export interface ClientConfigT {
  v: 1;
  origin: string;
  gateway_id: string;
  tenant_id: string;
  audit_trust: { kid: string; jwk: PublicJwk }[];
}

export function validateClientConfig(v: unknown): ClientConfigT {
    if (isObj(v) && "v" in v && v.v !== 1) throw new SchemaIssue("/v", "version", "VERSION_UNSUPPORTED");
  const o = closed(v, "", ["v", "origin", "gateway_id", "tenant_id", "audit_trust"]);
  validateOrigin(o.origin, "/origin");
  idField(o.gateway_id, "lsg", "/gateway_id");
  idField(o.tenant_id, "ltn", "/tenant_id");
  typ(o.audit_trust, "array", "/audit_trust");
  const at = o.audit_trust as unknown[];
  let prevKid = "";
  for (let i = 0; i < at.length; i++) {
    const a = closed(at[i], `/audit_trust/${i}`, ["kid", "jwk"]);
    idField(a.kid, "lky", `/audit_trust/${i}/kid`);
    if (i > 0 && prevKid >= (a.kid as string)) issue(`/audit_trust/${i}/kid`, "not sorted/duplicate");
    prevKid = a.kid as string;
    validatePublicJwk(a.jwk, `/audit_trust/${i}/jwk`);
  }
  return o as unknown as ClientConfigT;
}

// ---------- audit wire types ----------

export function validateAuditQuery(raw: string | null): { after: bigint; limit: number } {
  // Canonical order: after then limit; absent/duplicate/unknown/reordered are errors.
  if (raw === null || raw === "") issue("?after", "missing query");
  if (!/^after=(0|[1-9][0-9]*)&limit=(0|[1-9][0-9]*)$/.test(raw!)) issue("?query", "bad audit query");
  const m = /^after=(0|[1-9][0-9]*)&limit=(0|[1-9][0-9]*)$/.exec(raw!)!;
  const after = BigInt(m[1]!);
  const limit = BigInt(m[2]!);
  if (after > 9223372036854775807n) issue("?after", "range");
  if (limit < 1n || limit > 1000n) issue("?limit", "1..1000");
  return { after, limit: Number(limit) };
}

export { idValidators };
