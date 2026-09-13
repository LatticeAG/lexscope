// Signed hash-chained audit per §11.1.
// entry.hash = D("LEXSCOPE-AUDIT/1", body)
// signature   = Ed25519(UTF8("LEXSCOPE-AUDIT-SIGN/1") || 0x00 || U(hash))
// head sig    = Ed25519(UTF8("LEXSCOPE-HEAD/1") || 0x00 || J({tenant_id,seq,hash,signer_kid}))

import { KeyObject } from "node:crypto";
import { domainHash, unhex } from "./hash.ts";
import { jcs } from "./jcs.ts";
import { b64uEncode, b64uDecode } from "./b64.ts";
import { ed25519Sign, ed25519Verify, type PublicJwk } from "./jwt.ts";
import type { ErrorCode } from "./errors.ts";
import { isId, isCounter, idValidators } from "./ids.ts";
import { utf16Compare } from "./jcs.ts";

export const EVENT_KINDS = new Set([
  "deployment.installed", "token.minted", "token.expired", "task.expired",
  "nonce.issued", "nonce.expired", "call.admitted", "call.succeeded",
  "call.failed", "call.unknown", "call.output_blocked", "result.read",
  "access.denied", "inspect.read", "revocation.applied", "policy.applied",
  "key.rotated", "key.retired", "audit.read", "nonce.read", "control.replayed",
  "storage.migrated",
]);
export type EventKind = string;

export interface AuditBody {
  v: 1;
  schema: "lexscope.audit/1";
  tenant_id: string;
  seq: string;
  event_id: string;
  ts: number;
  prev: string;
  signer_kid: string;
  kind: EventKind;
  sub: string | null;
  task_id: string | null;
  token_id: string | null;
  call_id: string | null;
  request_id: string | null;
  control_kid: string | null;
  policy_hash: string | null;
  code: ErrorCode | "OK";
  call_hash: string | null;
  scope_hash: string | null;
  nonce_id: string | null;
  target: { kind: string; id: string } | null;
  revision: string | null;
  key_id: string | null;
}

export interface AuditEntry {
  body: AuditBody;
  hash: string;
  signature: string;
}

export interface AuditHead {
  seq: string;
  hash: string;
  signer_kid: string;
  signature: string;
}

export interface AuditPage {
  v: 1;
  entries: AuditEntry[];
  next_after: string;
  head: AuditHead;
  has_more: boolean;
}

export interface AuditTrust {
  v: 1;
  tenant_id: string;
  initial_kid: string;
  keys: { kid: string; jwk: PublicJwk }[];
  pinned_head: AuditHead | null;
  checkpoint: AuditEntry | null;
}

export type AuditVerifyResult =
  | { valid: true; entries: number; head: string }
  | {
      valid: false;
      code: "AUDIT_HASH_MISMATCH" | "AUDIT_INCOMPLETE" | "AUDIT_SIGNATURE_INVALID" | "AUDIT_SEQUENCE_INVALID" | "AUDIT_TRUST_INVALID";
      seq: string;
    };

export const GENESIS_PREV = "0".repeat(64);

export function makeAuditBody(partial: Partial<AuditBody> & Pick<AuditBody, "tenant_id" | "seq" | "event_id" | "ts" | "prev" | "signer_kid" | "kind">): AuditBody {
  return {
    v: 1,
    schema: "lexscope.audit/1",
    sub: null,
    task_id: null,
    token_id: null,
    call_id: null,
    request_id: null,
    control_kid: null,
    policy_hash: null,
    code: "OK",
    call_hash: null,
    scope_hash: null,
    nonce_id: null,
    target: null,
    revision: null,
    key_id: null,
    ...partial,
  };
}

export function entryHash(body: AuditBody): string {
  return domainHash("LEXSCOPE-AUDIT/1", body);
}

export function signEntry(body: AuditBody, key: KeyObject): AuditEntry {
  const hash = entryHash(body);
  const sig = ed25519Sign(Buffer.concat([Buffer.from("LEXSCOPE-AUDIT-SIGN/1", "ascii"), Buffer.from([0]), unhex(hash)!]), key);
  return { body, hash, signature: b64uEncode(sig) };
}

export function verifyEntry(entry: AuditEntry, jwk: PublicJwk): boolean {
  const sig = b64uDecode(entry.signature);
  const digest = unhex(entry.hash);
  if (sig === null || sig.length !== 64 || digest === null) return false;
  return ed25519Verify(
    Buffer.concat([Buffer.from("LEXSCOPE-AUDIT-SIGN/1", "ascii"), Buffer.from([0]), digest]),
    sig,
    jwk,
  );
}

export function signHead(tenantId: string, seq: string, hash: string, signerKid: string, key: KeyObject): AuditHead {
  const msg = Buffer.concat([
    Buffer.from("LEXSCOPE-HEAD/1", "ascii"),
    Buffer.from([0]),
    jcs({ tenant_id: tenantId, seq, hash, signer_kid: signerKid }),
  ]);
  return { seq, hash, signer_kid: signerKid, signature: b64uEncode(ed25519Sign(msg, key)) };
}

export function verifyHead(head: AuditHead, tenantId: string, jwk: PublicJwk): boolean {
  const sig = b64uDecode(head.signature);
  if (sig === null || sig.length !== 64) return false;
  const msg = Buffer.concat([
    Buffer.from("LEXSCOPE-HEAD/1", "ascii"),
    Buffer.from([0]),
    jcs({ tenant_id: tenantId, seq: head.seq, hash: head.hash, signer_kid: head.signer_kid }),
  ]);
  return ed25519Verify(msg, sig, jwk);
}

// ---------- structural validation of exported artifacts ----------

function isAuditBody(v: unknown): v is AuditBody {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const b = v as Record<string, unknown>;
  return (
    b.v === 1 &&
    b.schema === "lexscope.audit/1" &&
    isId(b.tenant_id, "ltn") &&
    isCounter(b.seq) &&
    isId(b.event_id, "lev") &&
    typeof b.ts === "number" &&
    typeof b.prev === "string" &&
    isId(b.signer_kid, "lky") &&
    typeof b.kind === "string" &&
    EVENT_KINDS.has(b.kind as string)
  );
}

function isAuditEntry(v: unknown): v is AuditEntry {
  if (v === null || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return isAuditBody(e.body) && typeof e.hash === "string" && /^[0-9a-f]{64}$/.test(e.hash) && typeof e.signature === "string";
}

function isAuditHead(v: unknown): v is AuditHead {
  if (v === null || typeof v !== "object") return false;
  const h = v as Record<string, unknown>;
  return isCounter(h.seq) && typeof h.hash === "string" && /^[0-9a-f]{64}$/.test(h.hash) && isId(h.signer_kid, "lky") && typeof h.signature === "string";
}

export function parseAuditTrust(v: unknown): AuditTrust | null {
  if (v === null || typeof v !== "object") return null;
  const t = v as Record<string, unknown>;
  if (t.v !== 1 || !isId(t.tenant_id, "ltn") || !isId(t.initial_kid, "lky") || !Array.isArray(t.keys)) return null;
  const keys = t.keys as unknown[];
  let prev = "";
  for (const k of keys) {
    if (k === null || typeof k !== "object") return null;
    const kk = k as Record<string, unknown>;
    if (!isId(kk.kid, "lky")) return null;
    const j = kk.jwk as Record<string, unknown> | undefined;
    if (!j || j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.x !== "string" || b64uDecode(j.x)?.length !== 32) return null;
    if (prev !== "" && prev >= (kk.kid as string)) return null;
    prev = kk.kid as string;
  }
  if (t.pinned_head !== null && !isAuditHead(t.pinned_head)) return null;
  if (t.checkpoint !== null && !isAuditEntry(t.checkpoint)) return null;
  return t as unknown as AuditTrust;
}

export function parseAuditPage(v: unknown): AuditPage | null {
  if (v === null || typeof v !== "object") return null;
  const p = v as Record<string, unknown>;
  if (p.v !== 1 || !Array.isArray(p.entries) || !isCounter(p.next_after) || !isAuditHead(p.head) || typeof p.has_more !== "boolean") return null;
  for (const e of p.entries) if (!isAuditEntry(e)) return null;
  return p as unknown as AuditPage;
}

// ---------- offline verification (§11.1 tail) ----------

// Verifies a complete AuditPage (as produced by `audit export`) against an
// AuditTrust. Completeness requires reaching the signed head AND matching any
// independently pinned head.
export function verifyAudit(page: AuditPage, trust: AuditTrust): AuditVerifyResult {
  if (trust.tenant_id !== "" ) {
    // tenant must match the entries' tenant; head sig checked below
  }
  const keyOf = (kid: string) => trust.keys.find((k) => k.kid === kid)?.jwk ?? null;
  const fail = (code: "AUDIT_HASH_MISMATCH" | "AUDIT_INCOMPLETE" | "AUDIT_SIGNATURE_INVALID" | "AUDIT_SEQUENCE_INVALID" | "AUDIT_TRUST_INVALID", seq: string): AuditVerifyResult => ({ valid: false, code, seq });

  // Entry sequence start: genesis unless a trusted checkpoint anchors it.
  let expectSeq: bigint;
  let expectPrev: string;
  let signer: string;
  if (trust.checkpoint !== null) {
    const cp = trust.checkpoint;
    if (!isAuditBody(cp.body) || entryHash(cp.body) !== cp.hash) return fail("AUDIT_HASH_MISMATCH", String(cp.body?.seq ?? "0"));
    const cpJwk = keyOf(cp.body.signer_kid);
    if (!cpJwk) return fail("AUDIT_TRUST_INVALID", cp.body.seq);
    if (!verifyEntry(cp, cpJwk)) return fail("AUDIT_SIGNATURE_INVALID", cp.body.seq);
    if (cp.body.tenant_id !== trust.tenant_id) return fail("AUDIT_TRUST_INVALID", cp.body.seq);
    expectSeq = BigInt(cp.body.seq) + 1n;
    expectPrev = cp.hash;
    signer = cp.body.signer_kid;
  } else {
    expectSeq = 1n;
    expectPrev = GENESIS_PREV;
    signer = trust.initial_kid;
  }
  if (!keyOf(signer)) return fail("AUDIT_TRUST_INVALID", "0");

  let last: AuditEntry | null = null;
  for (const e of page.entries) {
    const b = e.body;
    const seqStr = String(b.seq);
    if (!isCounter(b.seq) || BigInt(b.seq) !== expectSeq) return fail("AUDIT_SEQUENCE_INVALID", seqStr);
    if (b.tenant_id !== trust.tenant_id || b.schema !== "lexscope.audit/1" || b.v !== 1) return fail("AUDIT_TRUST_INVALID", seqStr);
    if (b.prev !== expectPrev) return fail("AUDIT_HASH_MISMATCH", seqStr);
    if (entryHash(b) !== e.hash) return fail("AUDIT_HASH_MISMATCH", seqStr);
    // signer timeline: current signer, or a rotation boundary event
    if (b.signer_kid !== signer) {
      if (b.kind === "key.rotated" && keyOf(b.signer_kid) && b.key_id === b.signer_kid) {
        signer = b.signer_kid;
      } else return fail("AUDIT_TRUST_INVALID", seqStr);
    }
    const jwk = keyOf(b.signer_kid);
    if (!jwk) return fail("AUDIT_TRUST_INVALID", seqStr);
    if (!verifyEntry(e, jwk)) return fail("AUDIT_SIGNATURE_INVALID", seqStr);
    expectSeq += 1n;
    expectPrev = e.hash;
    last = e;
  }

  // The signed page head must be exactly the last verified entry.
  const head = page.head;
  const headJwk = keyOf(head.signer_kid);
  if (!headJwk) return fail("AUDIT_TRUST_INVALID", head.seq);
  if (!verifyHead(head, trust.tenant_id, headJwk)) return fail("AUDIT_SIGNATURE_INVALID", head.seq);
  if (last === null) {
    // empty retained history verifies only against a matching signed checkpoint/head
    if (trust.checkpoint === null || trust.checkpoint.hash !== head.hash || trust.checkpoint.body.seq !== head.seq)
      return fail("AUDIT_INCOMPLETE", head.seq);
  } else {
    if (head.seq !== last.body.seq || head.hash !== last.hash) return fail("AUDIT_INCOMPLETE", String(BigInt(last.body.seq) + 1n));
  }
  if (trust.pinned_head !== null) {
    if (trust.pinned_head.seq !== head.seq || trust.pinned_head.hash !== head.hash || trust.pinned_head.signer_kid !== head.signer_kid)
      return fail("AUDIT_INCOMPLETE", head.seq);
  }
  return { valid: true, entries: page.entries.length, head: head.hash };
}
