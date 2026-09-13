// TenantAuthority — the TenantDO equivalent. Single-writer SQLite authority
// owning admission, mint journal, replay records, task ownership, revocations,
// call state, key status, and ordered audit commits (§2, §5.3, §6, §10).

import type { KeyObject } from "node:crypto";
import { LexError, type ErrorCode } from "../core/errors.ts";
import { domainHash, sha256Hex, unhex } from "../core/hash.ts";
import { jcs, jcsString } from "../core/jcs.ts";
import { b64uEncode } from "../core/b64.ts";
import type { IdGen } from "../core/ids.ts";
import type { PhysicalClock } from "../core/clock.ts";
import {
  PROOF_LEEWAY, NONCE_TTL, TOKEN_TTL_MAX, TOKEN_TTL_MIN, TASK_TTL,
  ADAPTER_DEADLINE, PROOF_RETENTION, RESULT_RETENTION, OPERATION_RETENTION,
  ALARM_BATCH,
} from "../core/clock.ts";
import {
  ed25519Sign, ed25519Verify, jwsCompact, jkt as jwkThumbprint,
  type PublicJwk,
} from "../core/jwt.ts";
import {
  type GatewayConfigT, type MintRequest, type Policy, type RevokeTarget,
  type TokenClaims, type ToolCall, TOOLS, type CallerProof, type ControlProof,
  type ControlEnrollment, validateToolResult,
} from "../core/schemas.ts";
import { argsPermitted, checkMintScopes } from "../core/predicates.ts";
import {
  makeAuditBody, signHead, entryHash, GENESIS_PREV,
  type AuditBody, type AuditEntry, type AuditHead, type AuditPage,
} from "../core/audit.ts";
import { type RowCipher, rowAad } from "../core/box.ts";
import { scanForCredentials } from "../core/redact.ts";
import { Store } from "./store.ts";
import type { ToolAdapter, Invocation, AdapterReply, ServiceIdentity } from "./adapters.ts";
import { validateObservation, type HeraldAdapter, type HeraldCheck } from "./herald.ts";

export interface Secrets {
  get(ref: string): KeyObject | undefined;
}

export interface AuthorityDeps {
  store: Store;
  config: GatewayConfigT;
  secrets: Secrets;
  cipher: RowCipher;
  adapters: Map<string, ToolAdapter>;
  heraldAdapters: Map<string, HeraldAdapter>; // keyed by configured binding name
  clock: PhysicalClock;
  idgen: IdGen;
  auditSign?: (body: AuditBody) => Uint8Array; // injectable signer (test failure)
}

export interface AgentCtx {
  requestId: string;
  token: string;
  claims: TokenClaims;
  tokenKid: string;
  callerJwk: PublicJwk;
  callerJkt: string;
  proof: CallerProof;
}

export interface ControlCtx {
  requestId: string;
  kid: string;
  proof: ControlProof;
  body: unknown;
}

export interface Reply {
  status: number;
  body: unknown;
  callState?: string;
}

const SCHEMA_VERSION = 1;
const CALLER_SUB_RATE = 50;
const CALLER_TENANT_RATE = 500;
const CONTROL_RATE = 50;
const MAX_INFLIGHT_CALLS = 64;
const MAX_LIVE_TASKS = 10000;
const MAX_OPEN_NONCES_TOKEN = 16;
const MAX_OPEN_NONCES_TENANT = 20000;
const STORAGE_CAPACITY = 512 * 1024 * 1024;

interface TaskRow {
  id: string; sub: string; jkt: string; herald: string | null;
  created_at: number | bigint; expires_at: number | bigint; state: string;
}
interface TokenRow {
  id: string; task_id: string; sub: string; kid: string; digest: string;
  scope_hash: string; policy_hash: string; issued_at: number | bigint;
  expires_at: number | bigint; state: string;
}
interface NonceRow {
  id: string; token_id: string; call_hash: string; issued_at: number | bigint;
  expires_at: number | bigint; state: string;
}
interface CallRow {
  id: string; task_id: string; sub: string; jkt: string; token_id: string;
  scope_hash: string; call_hash: string; state: string; admitted_at: number | bigint;
  completed_at: number | bigint | null; result_cipher: string | null;
  error_code: string | null; audit_seq: number | bigint; purge_at: number | bigint;
}
interface SigningKeyRow {
  kid: string; jwk: string; secret_ref: string | null; state: string;
  last_exp: number | bigint; activated_at: number | bigint;
}
interface RevocationRow {
  kind: string; target_id: string; effective_at: number | bigint;
  reason: string; audit_seq: number | bigint;
}
interface OperationRow {
  kid: string; op_id: string; digest: string; response_cipher: string; expires_at: number | bigint;
}

const n = (v: number | bigint): number => Number(v);

export class CrashFault extends Error {}

export class TenantAuthority {
  store: Store;
  cfg: GatewayConfigT;
  secrets: Secrets;
  cipher: RowCipher;
  adapters: Map<string, ToolAdapter>;
  heraldAdapters: Map<string, HeraldAdapter>;
  clock: PhysicalClock;
  idgen: IdGen;
  auditSign: (body: AuditBody) => Uint8Array;
  controlInflight = 0;
  // test injection points
  failNextCompletion = false;
  skipDispatchOnce = false;
  maintenanceMode = false;
  // emits fixture-style event ids (lev_<seq zero-padded to 21>) for
  // deterministic conformance runs; production uses random ids.
  fixtureIds = false;
  preAdmissionHook: (() => void) | null = null;

  constructor(d: AuthorityDeps) {
    this.store = d.store;
    this.cfg = d.config;
    this.secrets = d.secrets;
    this.cipher = d.cipher;
    this.adapters = d.adapters;
    this.heraldAdapters = d.heraldAdapters;
    this.clock = d.clock;
    this.idgen = d.idgen;
    const auditSecret = d.secrets.get(d.config.audit_signer.secret_ref);
    this.auditSign = d.auditSign ?? ((body) => {
      if (!auditSecret) throw new Error("audit signer unavailable");
      return ed25519Sign(
        Buffer.concat([Buffer.from("LEXSCOPE-AUDIT-SIGN/1", "ascii"), Buffer.from([0]), unhex(entryHash(body))!]),
        auditSecret,
      );
    });
  }

  // ---------- bootstrap ----------

  bootstrap(now: number): void {
    const cfg = this.cfg;
    const bootHash = domainHash("LEXSCOPE-BOOTSTRAP/1", JSON.parse(jcsString(cfg)));
    this.store.tx(() => {
      const existing = this.store.meta("bootstrap_hash");
      if (existing !== undefined) {
        if (existing !== bootHash) throw new Error("bootstrap hash mismatch: immutable deployment identity");
        return;
      }
      const s = this.store;
      s.setMeta("schema_version", String(SCHEMA_VERSION));
      s.setMeta("gateway_id", cfg.gateway_id);
      s.setMeta("tenant_id", cfg.tenant_id);
      s.setMeta("bootstrap_hash", bootHash);
      s.setMeta("active_policy_revision", cfg.policy.revision);
      s.setMeta("active_token_kid", cfg.token_signer.kid);
      s.setMeta("active_audit_kid", cfg.audit_signer.kid);
      s.setMeta("audit_seq", "0");
      s.setMeta("audit_head", GENESIS_PREV);
      s.setMeta("last_now", String(now));
      s.setMeta("mode", cfg.mode);
      s.setMeta("audit_checkpoint", "");
      const ph = domainHash("LEXSCOPE-POLICY/1", JSON.parse(jcsString(cfg.policy)));
      s.run("INSERT INTO policies(revision,hash,body) VALUES(?,?,?)", BigInt(cfg.policy.revision), ph, jcsString(cfg.policy));
      s.run("INSERT INTO signing_keys(kid,jwk,secret_ref,state,last_exp,activated_at) VALUES(?,?,?,?,?,?)",
        cfg.token_signer.kid, jcsString(cfg.token_signer.jwk), cfg.token_signer.secret_ref, "ACTIVE", 0, now);
      s.run("INSERT INTO audit_keys(kid,jwk,activation_seq,activated_at,retired_seq,secret_ref) VALUES(?,?,?,?,?,?)",
        cfg.audit_signer.kid, jcsString(cfg.audit_signer.jwk), 1, now, null, cfg.audit_signer.secret_ref);
      this.appendEvent({ kind: "deployment.installed", policy_hash: ph, revision: cfg.policy.revision }, now);
    });
  }

  // ---------- time ----------

  now(): number {
    const phys = this.clock.nowSeconds();
    const last = Number(this.store.meta("last_now") ?? "0");
    return Math.max(phys, last);
  }

  checkClockSafe(): void {
    const phys = this.clock.nowSeconds();
    const last = Number(this.store.meta("last_now") ?? "0");
    if (phys < last - PROOF_LEEWAY) throw new LexError("CLOCK_UNSAFE");
  }

  private bumpNow(now: number): void {
    const last = Number(this.store.meta("last_now") ?? "0");
    if (now > last) this.store.setMeta("last_now", String(now));
  }

  // ---------- audit append (inside the caller's transaction) ----------

  private appendEvent(fields: Partial<AuditBody> & { kind: string }, now: number): AuditEntry {
    const seq = BigInt(this.store.meta("audit_seq")!) + 1n;
    const body = makeAuditBody({
      tenant_id: this.cfg.tenant_id,
      seq: seq.toString(),
      event_id: this.fixtureIds ? `lev_${String(seq).padStart(21, "0")}` : this.idgen("lev"),
      ts: now,
      prev: this.store.meta("audit_head")!,
      signer_kid: this.store.meta("active_audit_kid")!,
      ...fields,
    });
    const sig = this.auditSign(body); // failure -> caller maps to STATE_UNAVAILABLE
    const entry: AuditEntry = { body, hash: entryHash(body), signature: b64uEncode(sig) };
    this.store.run(
      "INSERT INTO audit(seq,event_id,body,hash,signature,created_at) VALUES(?,?,?,?,?,?)",
      seq, entry.body.event_id, jcsString(entry.body), entry.hash, entry.signature, now,
    );
    this.store.setMeta("audit_seq", seq.toString());
    this.store.setMeta("audit_head", entry.hash);
    return entry;
  }

  private signCurrentHead(): AuditHead {
    const kid = this.store.meta("active_audit_kid")!;
    const row = this.store.get<{ secret_ref: string | null }>("SELECT secret_ref FROM audit_keys WHERE kid=?", kid);
    const key = row?.secret_ref ? this.secrets.get(row.secret_ref) : undefined;
    if (!key) throw new LexError("KEY_UNAVAILABLE");
    return signHead(this.cfg.tenant_id, this.store.meta("audit_seq")!, this.store.meta("audit_head")!, kid, key);
  }

  // ---------- shared helpers ----------

  private revocation(kind: string, id: string): RevocationRow | undefined {
    return this.store.get<RevocationRow>("SELECT * FROM revocations WHERE kind=? AND target_id=?", kind, id);
  }

  private proofSeen(kind: string, signer: string, jti: string): boolean {
    return !!this.store.get("SELECT 1 FROM proofs WHERE kind=? AND signer=? AND jti=?", kind, signer, jti);
  }

  private claimProof(kind: string, signer: string, jti: string, now: number): void {
    if (this.proofSeen(kind, signer, jti)) throw new LexError("PROOF_REPLAY");
    this.store.run("INSERT INTO proofs(kind,signer,jti,expires_at) VALUES(?,?,?,?)", kind, signer, jti, now + PROOF_RETENTION);
  }

  private bumpBucket(kind: string, subject: string, second: number, limit: number): void {
    const row = this.store.get<{ count: number | bigint }>(
      "SELECT count FROM buckets WHERE kind=? AND subject=? AND second=?", kind, subject, second);
    if (n(row?.count ?? 0) >= limit) throw new LexError("RATE_LIMITED");
    this.store.run(
      "INSERT INTO buckets(kind,subject,second,count) VALUES(?,?,?,1) ON CONFLICT(kind,subject,second) DO UPDATE SET count=count+1",
      kind, subject, second);
  }

  private callerBudget(sub: string, now: number): void {
    this.bumpBucket("caller", sub, now, CALLER_SUB_RATE);
    this.bumpBucket("caller", this.cfg.tenant_id, now, CALLER_TENANT_RATE);
  }

  private checkStorageCapacity(): void {
    if (this.store.storageBytes() >= STORAGE_CAPACITY) throw new LexError("CAPACITY");
  }

  private inflightCalls(): number {
    return n(this.store.get<{ c: number | bigint }>("SELECT COUNT(*) c FROM calls WHERE state='DISPATCHING'")!.c);
  }

  private currentPolicy(): { policy: Policy; hash: string } {
    const row = this.store.get<{ body: string; hash: string }>(
      "SELECT body,hash FROM policies WHERE revision=?", BigInt(this.store.meta("active_policy_revision")!))!;
    return { policy: JSON.parse(row.body) as Policy, hash: row.hash };
  }

  // Denial path for authenticated requests: claims the proof JTI and appends
  // one bounded access.denied event. A replayed proof converts to PROOF_REPLAY.
  deny(kind: "caller" | "control", signer: string, jti: string, err: LexError, ctx: {
    sub?: string | null; task_id?: string | null; token_id?: string | null;
    call_id?: string | null; request_id: string; control_kid?: string | null; call_hash?: string | null;
  }): LexError {
    try {
      return this.store.tx(() => {
        // A regressed physical clock must not collapse the original error into
        // STATE_UNAVAILABLE: the denial event timestamps at the persisted
        // logical clock instead.
        let now: number;
        try {
          now = this.now();
        } catch {
          now = Number(this.store.meta("last_now")!);
        }
        if (this.proofSeen(kind, signer, jti)) return new LexError("PROOF_REPLAY", { callId: ctx.call_id ?? null });
        this.store.run("INSERT INTO proofs(kind,signer,jti,expires_at) VALUES(?,?,?,?)", kind, signer, jti, now + PROOF_RETENTION);
        this.appendEvent({
          kind: "access.denied", code: err.code,
          sub: ctx.sub ?? null, task_id: ctx.task_id ?? null, token_id: ctx.token_id ?? null,
          call_id: ctx.call_id ?? null, request_id: ctx.request_id,
          control_kid: ctx.control_kid ?? null, call_hash: ctx.call_hash ?? null,
        }, now);
        this.bumpNow(now);
        return err;
      });
    } catch {
      return new LexError("STATE_UNAVAILABLE");
    }
  }

  // ---------- agent precheck: §5.3 steps 4-5 ----------

  private agentPrecheck(ctx: AgentCtx, routeTaskId: string | null, mismatchIs404: boolean): { now: number; token: TokenRow } {
    const s = this.store;
    const now = this.now();
    this.checkClockSafe();
    // authoritative token row + digest (correct signature alone is not authority)
    const token = s.get<TokenRow>("SELECT * FROM tokens WHERE id=?", ctx.claims.jti);
    if (!token || token.digest !== sha256Hex(ctx.token)) throw new LexError("AUTH_INVALID");
    if (ctx.claims.tenant_id !== this.cfg.tenant_id) throw new LexError("AUTH_INVALID");
    // time windows first
    if (now >= n(token.expires_at)) throw new LexError("TOKEN_EXPIRED");
    const task = s.get<TaskRow>("SELECT * FROM tasks WHERE id=?", ctx.claims.task_id);
    if (task && now >= n(task.expires_at)) throw new LexError("TASK_EXPIRED");
    if (ctx.claims.iat > now + PROOF_LEEWAY || ctx.claims.nbf > now + PROOF_LEEWAY) throw new LexError("AUTH_INVALID");
    if (Math.abs(now - ctx.proof.iat) > PROOF_LEEWAY) throw new LexError("CLOCK_WINDOW");
    // committed revocations: token, key, subject, task
    if (token.state === "REVOKED" || this.revocation("token", token.id)) throw new LexError("TOKEN_REVOKED");
    const keyRow = s.get<SigningKeyRow>("SELECT * FROM signing_keys WHERE kid=?", token.kid);
    if (!keyRow || keyRow.state === "COMPROMISED" || keyRow.state === "RETIRED" || this.revocation("signing_key", token.kid))
      throw new LexError("KEY_REVOKED");
    if (this.revocation("subject", token.sub)) throw new LexError("SUBJECT_REVOKED");
    if ((task && task.state === "REVOKED") || this.revocation("task", ctx.claims.task_id)) throw new LexError("TASK_REVOKED");
    // task status and binding
    if (!task || task.state !== "ACTIVE") throw new LexError("TASK_REVOKED");
    if (
      task.sub !== ctx.claims.sub ||
      task.jkt !== ctx.callerJkt ||
      jcsString(JSON.parse(task.herald ?? "null")) !== jcsString(ctx.claims.herald)
    )
      throw new LexError(mismatchIs404 ? "NOT_FOUND" : "TASK_BINDING_CONFLICT");
    if (routeTaskId !== null && routeTaskId !== ctx.claims.task_id)
      throw new LexError(mismatchIs404 ? "NOT_FOUND" : "TASK_BINDING_CONFLICT");
    // policy freshness
    if (token.policy_hash !== this.currentPolicy().hash) throw new LexError("POLICY_STALE");
    return { now, token };
  }

  private scopeCheck(policy: Policy, claims: TokenClaims, call: ToolCall): void {
    if (policy.hard_deny.includes(call.tool)) throw new LexError("HARD_DENY");
    if (!argsPermitted(claims.scopes, call.tool, call.args)) throw new LexError("SCOPE_DENIED");
  }

  private async heraldCheckAsync(binding: NonNullable<TokenClaims["herald"]>, sub: string, jkt: string, challenge: string, mode: "fresh" | "bounded_cache", now: number): Promise<void> {
    const src = this.cfg.herald_sources.find((h) => h.name === binding.source);
    if (!src) throw new LexError("SCHEMA_INVALID");
    const adapter = this.heraldAdapters.get(src.binding);
    if (!adapter) throw new LexError("HERALD_UNAVAILABLE");
    const input: HeraldCheck = { v: 1, tenant_id: this.cfg.tenant_id, sub, caller_jkt: jkt, binding, challenge, mode, now };
    let obs;
    try {
      obs = await adapter.check(input);
    } catch {
      throw new LexError("HERALD_UNAVAILABLE");
    }
    const verdict = validateObservation(input, obs);
    if (verdict === "revoked") throw new LexError("HERALD_REVOKED");
    if (verdict !== "active") throw new LexError("HERALD_UNAVAILABLE");
  }

  private callHash(call: ToolCall): string {
    return domainHash("LEXSCOPE-CALL/1", JSON.parse(jcsString(call)));
  }
  private scopeHashOf(claims: TokenClaims): string {
    return domainHash("LEXSCOPE-SCOPES/1", JSON.parse(jcsString(claims.scopes)));
  }

  private denyCaller(ctx: AgentCtx, err: LexError, callId: string | null, callHash: string | null): LexError {
    return this.deny("caller", ctx.callerJkt, ctx.proof.jti, err, {
      sub: ctx.claims.sub, task_id: ctx.claims.task_id, token_id: ctx.claims.jti,
      call_id: callId, request_id: ctx.requestId, call_hash: callHash,
    });
  }

  // ---------- POST /calls ----------

  async handleCall(ctx: AgentCtx, call: ToolCall): Promise<Reply> {
    const ch = this.callHash(call);
    try {
      return await this.callInner(ctx, call, ch);
    } catch (e) {
      if (e instanceof CrashFault) throw e;
      const err = e instanceof LexError ? e : new LexError("STATE_UNAVAILABLE");
      throw this.denyCaller(ctx, err, call.call_id, ch);
    }
  }

  private async callInner(ctx: AgentCtx, call: ToolCall, callHash: string): Promise<Reply> {
    const { now } = this.agentPrecheck(ctx, call.task_id, false);
    const { policy } = this.currentPolicy();
    this.scopeCheck(policy, ctx.claims, call);
    const destructive = TOOLS[call.tool].destructive;
    if (!destructive && ctx.proof.nonce !== null) throw new LexError("NONCE_NOT_REQUIRED");
    if (ctx.claims.herald !== null) {
      const challenge = destructive ? ctx.proof.nonce! : ctx.requestId;
      await this.heraldCheckAsync(ctx.claims.herald, ctx.claims.sub, ctx.callerJkt, challenge, destructive ? "fresh" : "bounded_cache", now);
    }
    this.checkStorageCapacity();
    if (this.preAdmissionHook) this.preAdmissionHook();

    interface Admission {
      kind: "admitted" | "replay";
      admissionSeq?: string;
      reply?: Reply;
    }
    let admission: Admission;
    try {
      admission = this.store.tx(() => {
        const now2 = this.now();
        this.agentPrecheck(ctx, call.task_id, false); // repeat mutable checks
        this.scopeCheck(this.currentPolicy().policy, ctx.claims, call);
        this.claimProof("caller", ctx.callerJkt, ctx.proof.jti, now2);
        this.callerBudget(ctx.claims.sub, now2);
        const existing = this.store.get<CallRow>("SELECT * FROM calls WHERE id=?", call.call_id);
        if (existing) {
          if (
            existing.call_hash !== callHash || existing.task_id !== call.task_id ||
            existing.sub !== ctx.claims.sub || existing.jkt !== ctx.callerJkt
          )
            throw new LexError("CALL_CONFLICT", { callId: call.call_id });
          // matching retry: nonce claim is uninterpreted on this path
          return { kind: "replay", reply: this.replayReplyInTx(existing, ctx) } as Admission;
        }
        if (this.inflightCalls() >= MAX_INFLIGHT_CALLS) throw new LexError("CAPACITY");
        let nonceRow: NonceRow | undefined;
        if (destructive) {
          if (ctx.proof.nonce === null) throw new LexError("NONCE_REQUIRED", { callId: call.call_id });
          nonceRow = this.store.get<NonceRow>("SELECT * FROM nonces WHERE id=?", ctx.proof.nonce);
          if (!nonceRow || nonceRow.token_id !== ctx.claims.jti || nonceRow.call_hash !== callHash)
            throw new LexError("NONCE_INVALID", { callId: call.call_id });
          if (nonceRow.state === "CONSUMED") throw new LexError("NONCE_USED", { callId: call.call_id });
          if (nonceRow.state === "EXPIRED" || now2 >= n(nonceRow.expires_at)) {
            if (nonceRow.state === "OPEN") {
              this.store.run("UPDATE nonces SET state='EXPIRED' WHERE id=?", nonceRow.id);
              this.appendEvent({ kind: "nonce.expired", nonce_id: nonceRow.id, call_hash: nonceRow.call_hash, token_id: nonceRow.token_id }, now2);
            }
            throw new LexError("NONCE_EXPIRED", { callId: call.call_id });
          }
        }
        const ev = this.appendEvent({
          kind: "call.admitted", sub: ctx.claims.sub, task_id: ctx.claims.task_id,
          token_id: ctx.claims.jti, call_id: call.call_id, request_id: ctx.requestId,
          policy_hash: ctx.claims.policy_hash, scope_hash: this.scopeHashOf(ctx.claims),
          call_hash: callHash, nonce_id: nonceRow?.id ?? null,
        }, now2);
        const taskExp = n(this.store.get<TaskRow>("SELECT expires_at FROM tasks WHERE id=?", call.task_id)!.expires_at);
        this.store.run(
          "INSERT INTO calls(id,task_id,sub,jkt,token_id,scope_hash,call_hash,state,admitted_at,completed_at,result_cipher,error_code,audit_seq,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          call.call_id, call.task_id, ctx.claims.sub, ctx.callerJkt, ctx.claims.jti,
          this.scopeHashOf(ctx.claims), callHash, "DISPATCHING", now2, null, null, null,
          BigInt(ev.body.seq), taskExp + RESULT_RETENTION,
        );
        if (nonceRow) this.store.run("UPDATE nonces SET state='CONSUMED' WHERE id=?", nonceRow.id);
        this.bumpNow(now2);
        return { kind: "admitted", admissionSeq: ev.body.seq } as Admission;
      });
    } catch (e) {
      if (e instanceof LexError) throw e;
      throw new LexError("STATE_UNAVAILABLE", { callId: call.call_id });
    }
    if (admission.kind === "replay") return admission.reply!;
    return this.dispatchAndComplete(ctx, call, callHash, admission.admissionSeq!);
  }

  // Saved terminal reply or stored error envelope; runs inside the admission txn.
  private replayReplyInTx(row: CallRow, ctx: AgentCtx): Reply {
    const now = this.now();
    if (row.state === "DISPATCHING")
      return { status: 202, body: { v: 1, call_id: row.id, state: "DISPATCHING", retry_after_s: 1 }, callState: "DISPATCHING" };
    if (row.state === "SUCCEEDED") {
      if (row.result_cipher === null) throw new LexError("RESULT_GONE", { callId: row.id });
      const plain = this.cipher.decrypt(rowAad(this.cfg.tenant_id, "calls", row.id, SCHEMA_VERSION), row.result_cipher);
      if (plain === null) throw new LexError("STATE_UNAVAILABLE", { callId: row.id });
      const result = JSON.parse(Buffer.from(plain).toString("utf8"));
      this.appendEvent({
        kind: "result.read", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
        call_id: row.id, request_id: ctx.requestId, call_hash: row.call_hash, scope_hash: row.scope_hash,
      }, now);
      return {
        status: 200,
        body: { v: 1, call_id: row.id, state: "SUCCEEDED", result, audit_seq: String(row.audit_seq), replayed: true },
        callState: "SUCCEEDED",
      };
    }
    const code = (row.error_code ?? "OUTCOME_UNKNOWN") as ErrorCode;
    const outcome = row.state === "FAILED" ? "FAILED" : "UNKNOWN";
    this.appendEvent({
      kind: "result.read", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
      call_id: row.id, request_id: ctx.requestId, call_hash: row.call_hash, scope_hash: row.scope_hash,
    }, now);
    return {
      status: code === "OUTCOME_UNKNOWN" ? 504 : 502,
      body: { v: 1, error: { code, request_id: ctx.requestId, retryable: false }, call_id: row.id, outcome },
      callState: row.state,
    };
  }

  private async dispatchAndComplete(ctx: AgentCtx, call: ToolCall, callHash: string, admissionSeq: string): Promise<Reply> {
    const bindingName = call.tool === "documents.read" ? this.cfg.tools.documents_read_binding : this.cfg.tools.records_delete_binding;
    const adapter = this.adapters.get(bindingName);
    const now = this.now();
    const deadline = now + ADAPTER_DEADLINE;
    const frozenCall = deepFreeze(JSON.parse(jcsString(call)) as ToolCall);
    const invocation: Invocation = {
      v: 1, tenant_id: this.cfg.tenant_id, call: frozenCall, call_hash: callHash,
      admission_seq: admissionSeq, idempotency_key: `${this.cfg.tenant_id}:${call.call_id}`, deadline,
    };
    const identity: ServiceIdentity = { binding: bindingName, gateway: this.cfg.gateway_id };
    const secrets = [ctx.token];
    if (this.skipDispatchOnce) {
      this.skipDispatchOnce = false;
      throw new CrashFault("crash after admission before dispatch");
    }
    if (!adapter) {
      this.completeCall(call.call_id, "UNKNOWN", "OUTCOME_UNKNOWN", null);
      return this.unknownReply(ctx.requestId, call.call_id);
    }
    let reply: AdapterReply;
    try {
      reply = await withDeadline(adapter.invoke(invocation, identity), deadline - this.clock.nowSeconds());
    } catch {
      this.completeCall(call.call_id, "UNKNOWN", "OUTCOME_UNKNOWN", null);
      return this.unknownReply(ctx.requestId, call.call_id);
    }
    if (reply.status === "rejected") {
      this.completeCall(call.call_id, "FAILED", "UPSTREAM_REJECTED", null);
      return {
        status: 502,
        body: { v: 1, error: { code: "UPSTREAM_REJECTED", request_id: ctx.requestId, retryable: false }, call_id: call.call_id, outcome: "FAILED" },
        callState: "FAILED",
      };
    }
    if (reply.status !== "ok") {
      this.completeCall(call.call_id, "UNKNOWN", "OUTCOME_UNKNOWN", null);
      return this.unknownReply(ctx.requestId, call.call_id);
    }
    const outErr = (code: ErrorCode): Reply => {
      this.completeCall(call.call_id, "OUTPUT_BLOCKED", code, null);
      return {
        status: 502,
        body: { v: 1, error: { code, request_id: ctx.requestId, retryable: false }, call_id: call.call_id, outcome: "UNKNOWN" },
        callState: "OUTPUT_BLOCKED",
      };
    };
    let serialized: string;
    try {
      serialized = jcsString(reply.result);
    } catch {
      return outErr("OUTPUT_INVALID");
    }
    if (Buffer.byteLength(serialized, "utf8") > 65536) return outErr("OUTPUT_TOO_LARGE");
    try {
      validateToolResult(reply.result, call.tool);
    } catch {
      return outErr("OUTPUT_INVALID");
    }
    const adapterSecrets = "providerSecrets" in (adapter as object) ? ((adapter as { providerSecrets?: string[] }).providerSecrets ?? []) : [];
    if (scanForCredentials(reply.result, serialized, [...secrets, ...adapterSecrets])) return outErr("OUTPUT_REDACTED");
    const enc = this.cipher.encrypt(rowAad(this.cfg.tenant_id, "calls", call.call_id, SCHEMA_VERSION), Buffer.from(serialized, "utf8"));
    const seq = this.completeCall(call.call_id, "SUCCEEDED", null, enc);
    if (seq === null) {
      this.completeCall(call.call_id, "UNKNOWN", "OUTCOME_UNKNOWN", null);
      return this.unknownReply(ctx.requestId, call.call_id);
    }
    return {
      status: 200,
      body: { v: 1, call_id: call.call_id, state: "SUCCEEDED", result: reply.result, audit_seq: seq, replayed: false },
      callState: "SUCCEEDED",
    };
  }

  private unknownReply(requestId: string, callId: string): Reply {
    return {
      status: 504,
      body: { v: 1, error: { code: "OUTCOME_UNKNOWN", request_id: requestId, retryable: false }, call_id: callId, outcome: "UNKNOWN" },
      callState: "UNKNOWN",
    };
  }

  private completeCall(callId: string, state: "SUCCEEDED" | "FAILED" | "UNKNOWN" | "OUTPUT_BLOCKED", errorCode: string | null, resultCipher: string | null): string | null {
    try {
      return this.store.tx(() => {
        if (this.failNextCompletion) {
          this.failNextCompletion = false;
          throw new Error("injected completion failure");
        }
        const now = this.now();
        const row = this.store.get<CallRow>("SELECT * FROM calls WHERE id=?", callId);
        if (!row || row.state !== "DISPATCHING") return null;
        const kind =
          state === "SUCCEEDED" ? "call.succeeded" : state === "FAILED" ? "call.failed" : state === "OUTPUT_BLOCKED" ? "call.output_blocked" : "call.unknown";
        const ev = this.appendEvent({
          kind, code: "OK", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
          call_id: callId, call_hash: row.call_hash, scope_hash: row.scope_hash,
        }, now);
        this.store.run(
          "UPDATE calls SET state=?, completed_at=?, result_cipher=?, error_code=?, audit_seq=?, purge_at=? WHERE id=?",
          state, now, resultCipher, errorCode, BigInt(ev.body.seq),
          state === "SUCCEEDED" ? now + RESULT_RETENTION : row.purge_at, callId,
        );
        this.bumpNow(now);
        return ev.body.seq;
      });
    } catch {
      return null;
    }
  }

  // ---------- POST /nonces ----------

  async handleNonce(ctx: AgentCtx, call: ToolCall): Promise<Reply> {
    const ch = this.callHash(call);
    try {
      this.agentPrecheck(ctx, call.task_id, false);
      if (!TOOLS[call.tool].destructive) throw new LexError("NONCE_NOT_REQUIRED");
      this.scopeCheck(this.currentPolicy().policy, ctx.claims, call);
      this.checkStorageCapacity();
      return this.store.tx(() => {
        const now2 = this.now();
        this.agentPrecheck(ctx, call.task_id, false);
        this.scopeCheck(this.currentPolicy().policy, ctx.claims, call);
        this.claimProof("caller", ctx.callerJkt, ctx.proof.jti, now2);
        this.callerBudget(ctx.claims.sub, now2);
        const existing = this.store.get<CallRow>("SELECT * FROM calls WHERE id=?", call.call_id);
        if (existing)
          throw new LexError(existing.call_hash === ch ? "CALL_EXISTS" : "CALL_CONFLICT", { callId: call.call_id });
        const open = this.store.get<NonceRow>(
          "SELECT * FROM nonces WHERE token_id=? AND call_hash=? AND state='OPEN'", ctx.claims.jti, ch);
        if (open && now2 < n(open.expires_at)) {
          this.appendEvent({
            kind: "nonce.read", sub: ctx.claims.sub, task_id: ctx.claims.task_id, token_id: ctx.claims.jti,
            call_id: call.call_id, request_id: ctx.requestId, call_hash: ch, nonce_id: open.id,
          }, now2);
          this.bumpNow(now2);
          return { status: 200, body: { v: 1, nonce: open.id, call_hash: ch, expires_at: n(open.expires_at) } };
        }
        if (open) {
          this.store.run("UPDATE nonces SET state='EXPIRED' WHERE id=?", open.id);
          this.appendEvent({ kind: "nonce.expired", nonce_id: open.id, call_hash: ch, token_id: open.token_id }, now2);
        }
        const openForToken = n(this.store.get<{ c: number | bigint }>("SELECT COUNT(*) c FROM nonces WHERE token_id=? AND state='OPEN'", ctx.claims.jti)!.c);
        const openForTenant = n(this.store.get<{ c: number | bigint }>("SELECT COUNT(*) c FROM nonces WHERE state='OPEN'")!.c);
        if (openForToken >= MAX_OPEN_NONCES_TOKEN || openForTenant >= MAX_OPEN_NONCES_TENANT) throw new LexError("CAPACITY");
        let nonceId = this.idgen("lnn", 32);
        // generated-ID collisions are retried before commit, never surfaced
        for (let attempt = 0; ; attempt++) {
          try {
            this.store.run("INSERT INTO nonces(id,token_id,call_hash,issued_at,expires_at,state) VALUES(?,?,?,?,?,'OPEN')",
              nonceId, ctx.claims.jti, ch, now2, now2 + NONCE_TTL);
            break;
          } catch {
            if (attempt >= 7) throw new LexError("STATE_UNAVAILABLE");
            nonceId = this.idgen("lnn", 32);
          }
        }
        this.appendEvent({
          kind: "nonce.issued", sub: ctx.claims.sub, task_id: ctx.claims.task_id, token_id: ctx.claims.jti,
          call_id: call.call_id, request_id: ctx.requestId, call_hash: ch, nonce_id: nonceId,
        }, now2);
        this.bumpNow(now2);
        return { status: 201, body: { v: 1, nonce: nonceId, call_hash: ch, expires_at: now2 + NONCE_TTL } };
      });
    } catch (e) {
      const err = e instanceof LexError ? e : new LexError("STATE_UNAVAILABLE");
      throw this.denyCaller(ctx, err, call.call_id, ch);
    }
  }

  // ---------- POST /results ----------

  async handleResult(ctx: AgentCtx, body: { task_id: string; call_id: string }): Promise<Reply> {
    try {
      this.agentPrecheck(ctx, body.task_id, true);
      return this.store.tx(() => {
        const now2 = this.now();
        this.agentPrecheck(ctx, body.task_id, true);
        this.claimProof("caller", ctx.callerJkt, ctx.proof.jti, now2);
        this.callerBudget(ctx.claims.sub, now2);
        const row = this.store.get<CallRow>("SELECT * FROM calls WHERE id=?", body.call_id);
        const scopeHash = this.scopeHashOf(ctx.claims);
        if (!row || row.sub !== ctx.claims.sub || row.jkt !== ctx.callerJkt || row.task_id !== ctx.claims.task_id || row.scope_hash !== scopeHash)
          throw new LexError("NOT_FOUND", { callId: body.call_id });
        this.bumpNow(now2);
        if (row.state === "DISPATCHING")
          return { status: 202, body: { v: 1, call_id: row.id, state: "DISPATCHING", retry_after_s: 1 }, callState: "DISPATCHING" };
        if (row.state === "SUCCEEDED") {
          if (row.result_cipher === null) throw new LexError("RESULT_GONE", { callId: row.id });
          const plain = this.cipher.decrypt(rowAad(this.cfg.tenant_id, "calls", row.id, SCHEMA_VERSION), row.result_cipher);
          if (plain === null) throw new LexError("STATE_UNAVAILABLE", { callId: row.id });
          const result = JSON.parse(Buffer.from(plain).toString("utf8"));
          this.appendEvent({
            kind: "result.read", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
            call_id: row.id, request_id: ctx.requestId, call_hash: row.call_hash, scope_hash: row.scope_hash,
          }, now2);
          return {
            status: 200,
            body: { v: 1, call_id: row.id, state: "SUCCEEDED", result, audit_seq: String(row.audit_seq), replayed: true },
            callState: "SUCCEEDED",
          };
        }
        const code = (row.error_code ?? "OUTCOME_UNKNOWN") as ErrorCode;
        const outcome = row.state === "FAILED" ? "FAILED" : "UNKNOWN";
        this.appendEvent({
          kind: "result.read", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
          call_id: row.id, request_id: ctx.requestId, call_hash: row.call_hash, scope_hash: row.scope_hash,
        }, now2);
        return {
          status: code === "OUTCOME_UNKNOWN" ? 504 : 502,
          body: { v: 1, error: { code, request_id: ctx.requestId, retryable: false }, call_id: row.id, outcome },
          callState: row.state,
        };
      });
    } catch (e) {
      const err = e instanceof LexError ? e : new LexError("STATE_UNAVAILABLE");
      throw this.denyCaller(ctx, err, body.call_id, null);
    }
  }

  // ---------- control plumbing ----------

  private enrollment(kid: string): ControlEnrollment | undefined {
    return this.cfg.controls.find((c) => c.kid === kid);
  }

  private hasRole(en: ControlEnrollment | undefined, roles: string[]): en is ControlEnrollment {
    return !!en && roles.some((r) => en.roles.includes(r as never));
  }

  private controlDeny(ctx: ControlCtx, err: LexError): LexError {
    return this.deny("control", ctx.kid, ctx.proof.jti, err, { request_id: ctx.requestId, control_kid: ctx.kid });
  }

  // Runs the control transaction: proof claim, control budget, role, op
  // idempotency, then mutator(now). LexError exits through the denial path.
  private controlOp<T extends object>(
    ctx: ControlCtx,
    roles: string[],
    opId: string | null,
    mutator: (now: number) => { response: T; save: boolean },
    onReplay?: (saved: T, now: number) => void,
  ): T {
    try {
      return this.store.tx(() => {
        const now = this.now();
        this.checkClockSafe();
        if (Math.abs(now - ctx.proof.iat) > PROOF_LEEWAY) throw new LexError("CLOCK_WINDOW");
        this.claimProof("control", ctx.kid, ctx.proof.jti, now);
        this.bumpBucket("control", ctx.kid, now, CONTROL_RATE);
        if (!this.hasRole(this.enrollment(ctx.kid), roles)) throw new LexError("CONTROL_FORBIDDEN");
        if (opId !== null) {
          const op = this.store.get<OperationRow>("SELECT * FROM operations WHERE kid=? AND op_id=?", ctx.kid, opId);
          if (op) {
            const digest = domainHash("LEXSCOPE-BODY/1", ctx.body);
            if (op.digest !== digest) throw new LexError("OP_CONFLICT");
            const plain = this.cipher.decrypt(rowAad(this.cfg.tenant_id, "operations", `${ctx.kid}:${opId}`, SCHEMA_VERSION), op.response_cipher);
            if (plain === null) throw new LexError("STATE_UNAVAILABLE");
            const saved = JSON.parse(Buffer.from(plain).toString("utf8")) as T & { replayed?: boolean };
            if (onReplay) onReplay(saved, now);
            this.appendEvent({ kind: "control.replayed", control_kid: ctx.kid, request_id: ctx.requestId }, now);
            this.bumpNow(now);
            if ("replayed" in saved) saved.replayed = true;
            return saved as T;
          }
        }
        const { response, save } = mutator(now);
        if (opId !== null && save) {
          const enc = this.cipher.encrypt(
            rowAad(this.cfg.tenant_id, "operations", `${ctx.kid}:${opId}`, SCHEMA_VERSION),
            Buffer.from(jcsString(response), "utf8"),
          );
          this.store.run("INSERT INTO operations(kid,op_id,digest,response_cipher,expires_at) VALUES(?,?,?,?,?)",
            ctx.kid, opId, domainHash("LEXSCOPE-BODY/1", ctx.body), enc, now + OPERATION_RETENTION);
        }
        this.bumpNow(now);
        return response;
      });
    } catch (e) {
      if (e instanceof LexError) throw this.controlDeny(ctx, e);
      throw new LexError("STATE_UNAVAILABLE");
    }
  }

  private peekOperation(kid: string, opId: string): boolean {
    return !!this.store.get("SELECT 1 FROM operations WHERE kid=? AND op_id=?", kid, opId);
  }

  // ---------- POST /mint ----------

  async handleMint(ctx: ControlCtx, req: MintRequest): Promise<Reply> {
    const replayPath = this.peekOperation(ctx.kid, req.op_id);
    if (!replayPath) {
      const en = this.enrollment(ctx.kid);
      if (!this.hasRole(en, ["minter"])) throw this.controlDeny(ctx, new LexError("CONTROL_FORBIDDEN"));
      if (!en.subjects.includes(req.sub)) throw this.controlDeny(ctx, new LexError("CONTROL_FORBIDDEN"));
      const { policy } = this.currentPolicy();
      const principal = policy.principals.find((p) => p.sub === req.sub);
      if (principal) {
        if (principal.herald === "required" && req.herald === null)
          throw this.controlDeny(ctx, new LexError("CONTROL_FORBIDDEN"));
        if (principal.herald === "disabled" && req.herald !== null)
          throw this.controlDeny(ctx, new LexError("CONTROL_FORBIDDEN"));
      }
      if (req.herald !== null && !this.cfg.herald_sources.some((h) => h.name === req.herald!.source))
        throw this.controlDeny(ctx, new LexError("SCHEMA_INVALID"));
      if (req.herald !== null) {
        try {
          await this.heraldCheckAsync(req.herald, req.sub, jwkThumbprint(req.caller_jwk), ctx.requestId, "fresh", this.now());
        } catch (e) {
          throw this.controlDeny(ctx, e instanceof LexError ? e : new LexError("HERALD_UNAVAILABLE"));
        }
      }
    }
    const body = this.controlOp<Record<string, unknown>>(ctx, ["minter"], req.op_id, (now) => {
      if (this.revocation("task", req.task_id)) throw new LexError("TASK_REVOKED");
      const task = this.store.get<TaskRow>("SELECT * FROM tasks WHERE id=?", req.task_id);
      if (task && now >= n(task.expires_at)) throw new LexError("TASK_EXPIRED");
      if (this.revocation("subject", req.sub)) throw new LexError("SUBJECT_REVOKED");
      const { policy, hash: policyHash } = this.currentPolicy();
      const principal = policy.principals.find((p) => p.sub === req.sub);
      if (!principal) throw new LexError("SCOPE_DENIED");
      const scopeRes = checkMintScopes(req.scopes, principal.scopes, policy.hard_deny);
      if (!scopeRes.ok) throw new LexError(scopeRes.hardDenied ? "HARD_DENY" : "SCOPE_DENIED");
      if (req.ttl_s < TOKEN_TTL_MIN || req.ttl_s > TOKEN_TTL_MAX || req.ttl_s > principal.max_ttl_s)
        throw new LexError("TTL_INVALID");
      this.checkStorageCapacity();
      const jkt = jwkThumbprint(req.caller_jwk);
      if (task) {
        if (task.state !== "ACTIVE") throw new LexError(task.state === "EXPIRED" ? "TASK_EXPIRED" : "TASK_REVOKED");
        if (task.sub !== req.sub || task.jkt !== jkt || jcsString(JSON.parse(task.herald ?? "null")) !== jcsString(req.herald))
          throw new LexError("TASK_BINDING_CONFLICT");
        if (now + req.ttl_s > n(task.expires_at)) throw new LexError("TTL_INVALID");
      } else {
        if (n(this.store.get<{ c: number | bigint }>("SELECT COUNT(*) c FROM tasks WHERE state='ACTIVE'")!.c) >= MAX_LIVE_TASKS)
          throw new LexError("CAPACITY");
        this.store.run(
          "INSERT INTO tasks(id,sub,jkt,herald,created_at,expires_at,state) VALUES(?,?,?,?,?,?,'ACTIVE')",
          req.task_id, req.sub, jkt, req.herald === null ? null : jcsString(req.herald), now, now + TASK_TTL,
        );
      }
      const activeKid = this.store.meta("active_token_kid")!;
      const keyRow = this.store.get<SigningKeyRow>("SELECT * FROM signing_keys WHERE kid=?", activeKid);
      if (!keyRow || keyRow.state !== "ACTIVE" || !keyRow.secret_ref) throw new LexError("KEY_UNAVAILABLE");
      const secret = this.secrets.get(keyRow.secret_ref);
      if (!secret) throw new LexError("KEY_UNAVAILABLE");
      const scopeHash = domainHash("LEXSCOPE-SCOPES/1", JSON.parse(jcsString(req.scopes)));
      const claims: TokenClaims = {
        v: 1, iss: `urn:lexscope:gateway:${this.cfg.gateway_id}`,
        aud: `${this.cfg.origin}/v1/tenants/${this.cfg.tenant_id}`,
        tenant_id: this.cfg.tenant_id, sub: req.sub, task_id: req.task_id,
        jti: "", iat: now, nbf: now, exp: now + req.ttl_s,
        cnf: { jkt }, scopes: req.scopes, policy_hash: policyHash, herald: req.herald,
      };
      let tokenId = "";
      for (let attempt = 0; ; attempt++) {
        tokenId = this.idgen("ltk");
        if (!this.store.get("SELECT 1 FROM tokens WHERE id=?", tokenId)) break;
        if (attempt >= 7) throw new LexError("COUNTER_EXHAUSTED");
      }
      claims.jti = tokenId;
      const token = jwsCompact({ alg: "EdDSA", typ: "lexscope+jwt", kid: activeKid }, claims, secret);
      this.store.run(
        "INSERT INTO tokens(id,task_id,sub,kid,digest,scope_hash,policy_hash,issued_at,expires_at,state) VALUES(?,?,?,?,?,?,?,?,?,'ACTIVE')",
        tokenId, req.task_id, req.sub, activeKid, sha256Hex(token), scopeHash, policyHash, now, claims.exp,
      );
      this.store.run("UPDATE signing_keys SET last_exp=MAX(last_exp,?) WHERE kid=?", claims.exp, activeKid);
      const ev = this.appendEvent({
        kind: "token.minted", sub: req.sub, task_id: req.task_id, token_id: tokenId,
        request_id: ctx.requestId, control_kid: ctx.kid, policy_hash: policyHash, scope_hash: scopeHash,
      }, now);
      return {
        response: {
          v: 1, access_token: token, token_type: "DPoP", token_id: tokenId,
          expires_at: claims.exp, scope_hash: scopeHash, audit_seq: ev.body.seq,
        },
        save: true,
      };
    }, (saved, now) => {
      // repeated mint after its saved token expires -> MINT_RESULT_EXPIRED
      const tokenId = (saved as { token_id?: string }).token_id;
      const row = tokenId ? this.store.get<TokenRow>("SELECT expires_at FROM tokens WHERE id=?", tokenId) : undefined;
      if (!row || now >= n(row.expires_at)) throw new LexError("MINT_RESULT_EXPIRED");
    });
    return { status: 201, body };
  }

  // ---------- POST /revoke ----------

  handleRevoke(ctx: ControlCtx, req: { op_id: string; target: RevokeTarget; reason: string }): Reply {
    const res = this.controlOp<Record<string, unknown>>(ctx, ["operator"], req.op_id, (now) => {
      const { kind, id } = req.target;
      if (kind === "token" && !this.store.get("SELECT 1 FROM tokens WHERE id=?", id)) throw new LexError("NOT_FOUND");
      if (kind === "task" && !this.store.get("SELECT 1 FROM tasks WHERE id=?", id)) throw new LexError("NOT_FOUND");
      if (kind === "signing_key" && !this.store.get("SELECT 1 FROM signing_keys WHERE kid=?", id)) throw new LexError("NOT_FOUND");
      if (kind === "subject") {
        const known =
          this.currentPolicy().policy.principals.some((p) => p.sub === id) ||
          !!this.store.get("SELECT 1 FROM tasks WHERE sub=?", id) ||
          !!this.store.get("SELECT 1 FROM tokens WHERE sub=?", id);
        if (!known) throw new LexError("NOT_FOUND");
      }
      const prior = this.revocation(kind, id);
      if (prior) {
        return {
          response: {
            v: 1, target: req.target, state: "REVOKED",
            effective_at: n(prior.effective_at), audit_seq: String(prior.audit_seq), replayed: true,
          },
          save: true,
        };
      }
      const seq = BigInt(this.store.meta("audit_seq")!) + 1n;
      this.store.run("INSERT INTO revocations(kind,target_id,effective_at,reason,audit_seq) VALUES(?,?,?,?,?)",
        kind, id, now, req.reason, seq);
      if (kind === "token") this.store.run("UPDATE tokens SET state='REVOKED' WHERE id=? AND state='ACTIVE'", id);
      if (kind === "task") this.store.run("UPDATE tasks SET state='REVOKED' WHERE id=? AND state='ACTIVE'", id);
      if (kind === "subject") this.store.run("UPDATE tasks SET state='REVOKED' WHERE sub=? AND state='ACTIVE'", id);
      if (kind === "signing_key")
        this.store.run("UPDATE signing_keys SET state='COMPROMISED' WHERE kid=? AND state IN ('ACTIVE','VERIFY_ONLY')", id);
      const ev = this.appendEvent({ kind: "revocation.applied", target: req.target, control_kid: ctx.kid, request_id: ctx.requestId }, now);
      return {
        response: {
          v: 1, target: req.target, state: "REVOKED",
          effective_at: now, audit_seq: ev.body.seq, replayed: false,
        },
        save: true,
      };
    });
    return { status: 200, body: res };
  }

  // ---------- POST /inspect ----------

  handleInspect(ctx: ControlCtx, req: { token_id: string }): Reply {
    const res = this.controlOp<Record<string, unknown>>(ctx, ["minter", "auditor"], null, (now) => {
      const row = this.store.get<TokenRow>("SELECT * FROM tokens WHERE id=?", req.token_id);
      if (!row) throw new LexError("NOT_FOUND");
      const en = this.enrollment(ctx.kid)!;
      if (!en.roles.includes("auditor") && !en.subjects.includes(row.sub)) throw new LexError("CONTROL_FORBIDDEN");
      const state = this.derivedTokenState(row, now);
      const task = this.store.get<TaskRow>("SELECT herald FROM tasks WHERE id=?", row.task_id);
      this.appendEvent({
        kind: "inspect.read", sub: row.sub, task_id: row.task_id, token_id: row.id,
        control_kid: ctx.kid, request_id: ctx.requestId, scope_hash: row.scope_hash,
      }, now);
      return {
        response: {
          v: 1, token_id: row.id, sub: row.sub, task_id: row.task_id, expires_at: n(row.expires_at),
          state, scope_hash: row.scope_hash,
          herald_required: task?.herald != null && task.herald !== "null",
        },
        save: false,
      };
    });
    return { status: 200, body: res };
  }

  private derivedTokenState(row: TokenRow, now: number): "ACTIVE" | "REVOKED" | "EXPIRED" | "POLICY_STALE" {
    const revoked =
      row.state === "REVOKED" ||
      !!this.revocation("token", row.id) ||
      !!this.revocation("task", row.task_id) ||
      !!this.revocation("subject", row.sub) ||
      !!this.revocation("signing_key", row.kid) ||
      this.store.get<SigningKeyRow>("SELECT state FROM signing_keys WHERE kid=?", row.kid)?.state === "COMPROMISED";
    if (revoked) return "REVOKED";
    if (now >= n(row.expires_at)) return "EXPIRED";
    if (row.policy_hash !== this.currentPolicy().hash) return "POLICY_STALE";
    return "ACTIVE";
  }

  // ---------- POST /policy ----------

  handlePolicy(ctx: ControlCtx, req: { op_id: string; expected_revision: string; policy: Policy }): Reply {
    const res = this.controlOp<Record<string, unknown>>(ctx, ["operator"], req.op_id, (now) => {
      const cur = this.store.meta("active_policy_revision")!;
      if (req.expected_revision !== cur || req.policy.revision !== String(BigInt(cur) + 1n))
        throw new LexError("REVISION_CONFLICT");
      const hash = domainHash("LEXSCOPE-POLICY/1", JSON.parse(jcsString(req.policy)));
      if (this.store.get("SELECT 1 FROM policies WHERE hash=?", hash)) throw new LexError("REVISION_CONFLICT");
      this.store.run("INSERT INTO policies(revision,hash,body) VALUES(?,?,?)", BigInt(req.policy.revision), hash, jcsString(req.policy));
      this.store.setMeta("active_policy_revision", req.policy.revision);
      const ev = this.appendEvent({
        kind: "policy.applied", revision: req.policy.revision, policy_hash: hash,
        control_kid: ctx.kid, request_id: ctx.requestId,
      }, now);
      return { response: { v: 1, revision: req.policy.revision, policy_hash: hash, audit_seq: ev.body.seq, replayed: false }, save: true };
    });
    return { status: 200, body: res };
  }

  // ---------- POST /rotate ----------

  handleRotate(ctx: ControlCtx, req: { op_id: string; expected_kid: string; new_kid: string; new_jwk: PublicJwk; secret_ref: string }): Reply {
    const res = this.controlOp<Record<string, unknown>>(ctx, ["operator"], req.op_id, (now) => {
      const activeKid = this.store.meta("active_token_kid")!;
      if (req.expected_kid !== activeKid || req.new_kid === activeKid) throw new LexError("KEY_CONFLICT");
      const kidUsed =
        !!this.store.get("SELECT 1 FROM signing_keys WHERE kid=?", req.new_kid) ||
        !!this.store.get("SELECT 1 FROM audit_keys WHERE kid=?", req.new_kid) ||
        this.cfg.controls.some((c) => c.kid === req.new_kid);
      if (kidUsed) throw new LexError("KEY_CONFLICT");
      const keyUsed =
        this.store.all<{ jwk: string }>("SELECT jwk FROM signing_keys").some((r) => (JSON.parse(r.jwk) as PublicJwk).x === req.new_jwk.x) ||
        this.store.all<{ jwk: string }>("SELECT jwk FROM audit_keys").some((r) => (JSON.parse(r.jwk) as PublicJwk).x === req.new_jwk.x) ||
        this.cfg.controls.some((c) => c.jwk.x === req.new_jwk.x) ||
        this.cfg.token_signer.jwk.x === req.new_jwk.x ||
        this.cfg.audit_signer.jwk.x === req.new_jwk.x;
      if (keyUsed) throw new LexError("KEY_CONFLICT");
      const secret = this.secrets.get(req.secret_ref);
      if (!secret) throw new LexError("KEY_UNAVAILABLE");
      const challenge = Buffer.concat([
        Buffer.from("LEXSCOPE-ROTATE/1", "ascii"), Buffer.from([0]),
        jcsStringToBuf({ tenant_id: this.cfg.tenant_id, new_kid: req.new_kid }),
      ]);
      const sig = ed25519Sign(challenge, secret);
      if (!ed25519Verify(challenge, sig, req.new_jwk)) throw new LexError("KEY_CONFLICT");
      void sig;
      const old = this.store.get<SigningKeyRow>("SELECT * FROM signing_keys WHERE kid=?", activeKid)!;
      const prevState = old.state === "COMPROMISED" ? "COMPROMISED" : "VERIFY_ONLY";
      if (old.state === "ACTIVE") this.store.run("UPDATE signing_keys SET state='VERIFY_ONLY' WHERE kid=?", activeKid);
      this.store.run("INSERT INTO signing_keys(kid,jwk,secret_ref,state,last_exp,activated_at) VALUES(?,?,?,?,?,?)",
        req.new_kid, jcsString(req.new_jwk), req.secret_ref, "ACTIVE", 0, now);
      this.store.setMeta("active_token_kid", req.new_kid);
      const ev = this.appendEvent({ kind: "key.rotated", key_id: req.new_kid, control_kid: ctx.kid, request_id: ctx.requestId }, now);
      return {
        response: { v: 1, active_kid: req.new_kid, previous_kid: activeKid, previous_state: prevState, audit_seq: ev.body.seq, replayed: false },
        save: true,
      };
    });
    return { status: 200, body: res };
  }

  // ---------- GET /audit ----------

  handleAudit(ctx: ControlCtx, after: bigint, limit: number): Reply {
    const res = this.controlOp<AuditPage>(ctx, ["auditor"], null, (now) => {
      const headSeq = BigInt(this.store.meta("audit_seq")!);
      const cp = this.store.meta("audit_checkpoint");
      if (cp && after < BigInt(cp)) throw new LexError("RESULT_GONE");
      const rows = this.store.all<{ seq: number | bigint; body: string; hash: string; signature: string }>(
        "SELECT seq,body,hash,signature FROM audit WHERE seq>? ORDER BY seq ASC LIMIT ?", after, limit);
      const entries: AuditEntry[] = rows.map((r) => ({ body: JSON.parse(r.body) as AuditBody, hash: r.hash, signature: r.signature }));
      const head = this.signCurrentHead();
      const lastSeq = entries.length > 0 ? BigInt(entries[entries.length - 1]!.body.seq) : null;
      const nextAfter = lastSeq !== null ? lastSeq.toString() : (after < headSeq ? after.toString() : headSeq.toString());
      const page: AuditPage = { v: 1, entries, next_after: nextAfter, head, has_more: lastSeq !== null && lastSeq < headSeq };
      this.appendEvent({ kind: "audit.read", control_kid: ctx.kid, request_id: ctx.requestId }, now);
      return { response: page, save: false };
    });
    return { status: 200, body: res };
  }

  // Public key material for signature verification (any state; revocation is
  // enforced by the admission checks, not by hiding the key).
  signingJwk(kid: string): PublicJwk | null {
    const row = this.store.get<SigningKeyRow>("SELECT jwk FROM signing_keys WHERE kid=?", kid);
    return row ? (JSON.parse(row.jwk) as PublicJwk) : null;
  }

  callRowState(callId: string): string | null {
    const row = this.store.get<{ state: string }>("SELECT state FROM calls WHERE id=?", callId);
    return row?.state ?? null;
  }

  // ---------- public routes ----------

  handleKeys(): Reply {
    const tokenKeys = this.store.all<SigningKeyRow>("SELECT * FROM signing_keys WHERE state IN ('ACTIVE','VERIFY_ONLY')");
    const auditKeys = this.store.all<{ kid: string; jwk: string; activated_at: number | bigint; retired_seq: number | bigint | null }>("SELECT * FROM audit_keys");
    const views = [
      ...tokenKeys.map((k) => ({
        kid: k.kid, purpose: "token", jwk: JSON.parse(k.jwk) as PublicJwk,
        state: k.state, not_before: n(k.activated_at),
        verify_until: k.state === "VERIFY_ONLY" ? n(k.last_exp) + PROOF_LEEWAY : null,
      })),
      ...auditKeys.map((k) => ({
        kid: k.kid, purpose: "audit", jwk: JSON.parse(k.jwk) as PublicJwk,
        state: k.retired_seq === null ? "ACTIVE" : "VERIFY_ONLY",
        not_before: n(k.activated_at), verify_until: null,
      })),
    ].sort((a, b) => (a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0));
    return { status: 200, body: { v: 1, gateway_id: this.cfg.gateway_id, tenant_id: this.cfg.tenant_id, keys: views } };
  }

  health(): Reply {
    const ok = !this.maintenanceMode && !!this.store.meta("bootstrap_hash");
    return { status: ok ? 200 : 503, body: { v: 1, status: ok ? "ok" : "unavailable", protocol: "lexscope/1" } };
  }

  // ---------- maintenance, snapshot, restore (§14) ----------

  enterMaintenance(): void {
    this.maintenanceMode = true;
  }
  exitMaintenance(): void {
    this.maintenanceMode = false;
  }

  // Encrypted snapshot: every authority table plus the pinned audit head and
  // schema version, sealed under the tenant data key (§14).
  exportSnapshot(): string {
    const tables = [
      "meta", "policies", "tasks", "tokens", "revocations", "proofs",
      "nonces", "calls", "operations", "signing_keys", "audit_keys", "audit", "buckets",
    ];
    const dump: Record<string, unknown[]> = {};
    for (const t of tables) dump[t] = this.store.all(`SELECT * FROM ${t}`);
    return this.cipher.encrypt(
      `lexscope/1 ${this.cfg.tenant_id} snapshot 1`,
      Buffer.from(jcsString({ v: 1, schema_version: SCHEMA_VERSION, tables: dump }), "utf8"),
    );
  }

  // Restore requires maintenance; all previously live tasks are revoked at
  // cutover, tombstones retained, and a fresh never-used token key activated
  // (new key drain). Returns the number of task tombstones written.
  restoreSnapshot(sealed: string, newKey: { kid: string; jwk: PublicJwk; secret_ref: string }): number {
    if (!this.maintenanceMode) throw new LexError("STATE_UNAVAILABLE");
    const plain = this.cipher.decrypt(`lexscope/1 ${this.cfg.tenant_id} snapshot 1`, sealed);
    if (plain === null) throw new LexError("STATE_UNAVAILABLE");
    const snap = JSON.parse(Buffer.from(plain).toString("utf8")) as { v: number; schema_version: number; tables: Record<string, Record<string, unknown>[]> };
    if (snap.v !== 1 || snap.schema_version !== SCHEMA_VERSION) throw new LexError("STATE_UNAVAILABLE");
    return this.store.tx(() => {
      const now = this.now();
      const tables = Object.keys(snap.tables);
      for (const t of tables) this.store.run(`DELETE FROM ${t}`);
      for (const t of tables) {
        for (const row of snap.tables[t]!) {
          const cols = Object.keys(row).sort();
          this.store.run(
            `INSERT INTO ${t}(${cols.join(",")}) VALUES(${cols.map(() => "?").join(",")})`,
            ...cols.map((c) => row[c] as string | number | bigint | null),
          );
        }
      }
      // new key drain: current active -> VERIFY_ONLY (or COMPROMISED kept)
      const activeKid = this.store.meta("active_token_kid")!;
      const old = this.store.get<SigningKeyRow>("SELECT * FROM signing_keys WHERE kid=?", activeKid);
      if (old && old.state === "ACTIVE") this.store.run("UPDATE signing_keys SET state='VERIFY_ONLY' WHERE kid=?", activeKid);
      const kidUsed =
        !!this.store.get("SELECT 1 FROM signing_keys WHERE kid=?", newKey.kid) ||
        !!this.store.get("SELECT 1 FROM audit_keys WHERE kid=?", newKey.kid);
      if (kidUsed) throw new LexError("KEY_CONFLICT");
      this.store.run("INSERT INTO signing_keys(kid,jwk,secret_ref,state,last_exp,activated_at) VALUES(?,?,?,?,?,?)",
        newKey.kid, jcsString(newKey.jwk), newKey.secret_ref, "ACTIVE", 0, now);
      this.store.setMeta("active_token_kid", newKey.kid);
      const ev = this.appendEvent({ kind: "storage.migrated", revision: String(SCHEMA_VERSION) }, now);
      // cutover: revoke every task that was live in the snapshot
      let revoked = 0;
      const live = this.store.all<TaskRow>("SELECT * FROM tasks WHERE state='ACTIVE'");
      for (const t of live) {
        if (!this.revocation("task", t.id))
          this.store.run("INSERT INTO revocations(kind,target_id,effective_at,reason,audit_seq) VALUES('task',?,?,?,?)",
            t.id, now, "operator_request", BigInt(ev.body.seq));
        this.store.run("UPDATE tasks SET state='REVOKED' WHERE id=?", t.id);
        revoked++;
      }
      this.bumpNow(now);
      return revoked;
    });
  }

  // ---------- recovery + retention ----------

  recover(now: number): number {
    return this.store.tx(() => {
      const stale = this.store.all<CallRow>("SELECT * FROM calls WHERE state='DISPATCHING' AND admitted_at<=?", now - ADAPTER_DEADLINE);
      for (const row of stale) {
        const ev = this.appendEvent({
          kind: "call.unknown", sub: row.sub, task_id: row.task_id, token_id: row.token_id,
          call_id: row.id, call_hash: row.call_hash, scope_hash: row.scope_hash,
        }, now);
        this.store.run("UPDATE calls SET state='UNKNOWN', completed_at=?, error_code='OUTCOME_UNKNOWN', audit_seq=? WHERE id=?",
          now, BigInt(ev.body.seq), row.id);
      }
      this.bumpNow(now);
      return stale.length;
    });
  }

  runMaintenance(now: number): number {
    let actions = 0;
    this.store.tx(() => {
      for (const t of this.store.all<TaskRow>("SELECT * FROM tasks WHERE state='ACTIVE' AND expires_at<=? LIMIT ?", now, ALARM_BATCH)) {
        this.store.run("UPDATE tasks SET state='EXPIRED' WHERE id=?", t.id);
        this.appendEvent({ kind: "task.expired", sub: t.sub, task_id: t.id }, now);
        actions++;
      }
      for (const t of this.store.all<TokenRow>("SELECT * FROM tokens WHERE state='ACTIVE' AND expires_at<=? LIMIT ?", now, ALARM_BATCH)) {
        this.store.run("UPDATE tokens SET state='EXPIRED' WHERE id=?", t.id);
        this.appendEvent({ kind: "token.expired", sub: t.sub, task_id: t.task_id, token_id: t.id }, now);
        actions++;
      }
      for (const nn of this.store.all<NonceRow>("SELECT * FROM nonces WHERE state='OPEN' AND expires_at<=? LIMIT ?", now, ALARM_BATCH)) {
        this.store.run("UPDATE nonces SET state='EXPIRED' WHERE id=?", nn.id);
        this.appendEvent({ kind: "nonce.expired", nonce_id: nn.id, call_hash: nn.call_hash, token_id: nn.token_id }, now);
        actions++;
      }
      for (const k of this.store.all<SigningKeyRow>("SELECT * FROM signing_keys WHERE state='VERIFY_ONLY' AND last_exp+?<=? LIMIT ?", PROOF_LEEWAY, now, ALARM_BATCH)) {
        this.store.run("UPDATE signing_keys SET state='RETIRED', secret_ref=NULL WHERE kid=?", k.kid);
        this.appendEvent({ kind: "key.retired", key_id: k.kid }, now);
        actions++;
      }
      actions += Number(this.store.db.prepare("DELETE FROM proofs WHERE expires_at<=?").run(now).changes);
      actions += Number(this.store.db.prepare("DELETE FROM operations WHERE expires_at<=?").run(now).changes);
      for (const c of this.store.all<CallRow>("SELECT * FROM calls WHERE state='SUCCEEDED' AND result_cipher IS NOT NULL AND purge_at<=? LIMIT ?", now, ALARM_BATCH)) {
        this.store.run("UPDATE calls SET result_cipher=NULL WHERE id=?", c.id);
        actions++;
      }
      this.store.db.prepare(
        "DELETE FROM calls WHERE id IN (SELECT c.id FROM calls c JOIN tasks t ON c.task_id=t.id WHERE t.expires_at+?<=? LIMIT ?)",
      ).run(RESULT_RETENTION, now, ALARM_BATCH);
      this.store.db.prepare("DELETE FROM tokens WHERE expires_at+?<=?").run(PROOF_RETENTION, now);
      this.store.db.prepare("DELETE FROM nonces WHERE token_id NOT IN (SELECT id FROM tokens)").run();
      this.store.db.prepare("DELETE FROM buckets WHERE second<?").run(now - 4);
      this.bumpNow(now);
    });
    return actions;
  }
}

function jcsStringToBuf(v: unknown): Buffer {
  return jcs(v as never);
}

function deepFreeze<T>(o: T): T {
  if (o !== null && typeof o === "object") {
    for (const v of Object.values(o)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

async function withDeadline<T>(p: Promise<T>, secondsLeft: number): Promise<T> {
  if (secondsLeft <= 0) throw new Error("deadline");
  let t: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error("adapter timeout")), secondsLeft * 1000);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(t);
  }
}
