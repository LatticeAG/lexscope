// LexScope client SDK per §8.1. Tokens are opaque handles; every printed or
// serialized representation is the fixed string "[LexScope credential
// redacted]". The client never remints, broadens scopes, substitutes tools,
// suppresses hard denies, or retries a terminal/unknown effect.

import type { KeyObject } from "node:crypto";
import { jwsCompact, jkt, keyObjectToJwk, type PublicJwk } from "./core/jwt.ts";
import { domainHash, sha256 } from "./core/hash.ts";
import { b64uEncode } from "./core/b64.ts";
import { jcsString } from "./core/jcs.ts";
import { randomId, type IdGen } from "./core/ids.ts";
import {
  validateToolCall, validateMintRequest, validateRevokeRequest,
  validateTokenInspectRequest, validatePolicyApplyRequest, validateRotateRequest,
  SchemaIssue, TOOLS,
  type ToolCall, type MintRequest, type RevokeRequest, type PolicyApplyRequest,
  type RotateRequest,
} from "./core/schemas.ts";

export const REDACTED = "[LexScope credential redacted]";

export class LexScopeError extends Error {
  code: string;
  requestId: string | null;
  outcome: string;
  status: number;
  retryable: boolean;
  constructor(err: { code: string; request_id?: string | null; retryable?: boolean; outcome?: string }, strip?: string, status = 0) {
    // the public message is a stable code, never upstream bytes or credentials
    super(`${err.code}${err.request_id ? ` request_id=${err.request_id}` : ""}`);
    this.code = err.code;
    this.requestId = err.request_id ?? null;
    this.outcome = err.outcome ?? "NOT_DISPATCHED";
    this.retryable = err.retryable === true;
    this.status = status;
    if (strip && this.message.includes(strip)) this.message = this.message.split(strip).join(REDACTED);
  }
}

export class TransportError extends LexScopeError {
  constructor(detail: string) {
    super({ code: "TRANSPORT_UNAVAILABLE", request_id: null, retryable: true, outcome: "NOT_DISPATCHED" });
    this.message = "TRANSPORT_UNAVAILABLE"; // scrub transport detail from the error surface
    void detail;
  }
}

// Opaque credential handle. `secret` is reachable only inside this module.
export class TokenHandle {
  readonly tokenId: string;
  readonly expiresAt: number;
  readonly scopeHash: string;
  private readonly secret: string;
  private readonly openNonces = new Map<string, string>(); // call_hash -> OPEN nonce id
  constructor(secret: string, tokenId: string, expiresAt: number, scopeHash: string) {
    this.secret = secret;
    this.tokenId = tokenId;
    this.expiresAt = expiresAt;
    this.scopeHash = scopeHash;
  }
  toJSON(): string {
    return REDACTED;
  }
  toString(): string {
    return REDACTED;
  }
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED;
  }
}

export interface WireReq {
  method: string;
  url: string; // absolute URL path-suffixed
  headers: Record<string, string>;
  body: string | null; // canonical JSON or null
}
export interface WireRes {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}
export type Transport = (req: WireReq, timeoutMs: number) => Promise<WireRes>;

export interface ClientOpts {
  origin: string;
  tenantId: string;
  callerKey?: KeyObject;
  callerJwk?: PublicJwk; // explicit public JWK; else derived from callerKey
  controlKey?: KeyObject;
  controlKid?: string;
  transport: Transport;
  idgen?: IdGen;
  now?: () => number;
}

const CONTROL_TIMEOUT = 5000;
const CALL_TIMEOUT = 25000;
const MAX_RETRIES = 2;

export class LexScopeClient {
  private o: ClientOpts;
  private idg: IdGen;
  private callerJwk: PublicJwk | null;
  private callerJkt: string | null;
  constructor(opts: ClientOpts) {
    this.o = opts;
    this.idg = opts.idgen ?? randomId;
    this.callerJwk = opts.callerJwk ?? (opts.callerKey ? keyObjectToJwk(opts.callerKey) : null);
    this.callerJkt = this.callerJwk ? jkt(this.callerJwk) : null;
  }

  private get base(): string {
    return `${this.o.origin}/v1/tenants/${this.o.tenantId}`;
  }
  private now(): number {
    return this.o.now ? this.o.now() : Math.floor(Date.now() / 1000);
  }
  private proofId(): string {
    return this.idg("lpf", 32);
  }

  // ---------- control methods (control key signs; never a tool surface) ----------

  async mint(request: MintRequest): Promise<TokenHandle> {
    const req = this.checkControlSchema(() => validateMintRequest(request));
    const res = await this.controlSend("/mint", req, "POST");
    this.mustOk(res, 201);
    const b = this.bodyJson(res) as { access_token: string; token_id: string; expires_at: number; scope_hash: string };
    return new TokenHandle(b.access_token, b.token_id, b.expires_at, b.scope_hash);
  }

  async revoke(request: RevokeRequest): Promise<unknown> {
    const req = this.checkControlSchema(() => validateRevokeRequest(request));
    const res = await this.controlSend("/revoke", req, "POST");
    this.mustOk(res, 200);
    return this.bodyJson(res);
  }

  async inspect(request: { token_id: string }): Promise<unknown> {
    const req = this.checkControlSchema(() => validateTokenInspectRequest(request));
    const res = await this.controlSend("/inspect", req, "POST");
    this.mustOk(res, 200);
    return this.bodyJson(res);
  }

  async applyPolicy(request: PolicyApplyRequest): Promise<unknown> {
    const req = this.checkControlSchema(() => validatePolicyApplyRequest(request));
    const res = await this.controlSend("/policy", req, "POST");
    this.mustOk(res, 200);
    return this.bodyJson(res);
  }

  async rotate(request: RotateRequest): Promise<unknown> {
    const req = this.checkControlSchema(() => validateRotateRequest(request));
    const res = await this.controlSend("/rotate", req, "POST");
    this.mustOk(res, 200);
    return this.bodyJson(res);
  }

  async audit(after: string, limit: number): Promise<unknown> {
    const res = await this.controlSend(`/audit?after=${after}&limit=${limit}`, null, "GET");
    this.mustOk(res, 200);
    return this.bodyJson(res);
  }

  // ---------- agent methods ----------

  async nonce(token: TokenHandle, call: ToolCall): Promise<{ nonce: string; call_hash: string; expires_at: number }> {
    this.checkCallerSchema(call);
    const body = { v: 1, call };
    const res = await this.agentSend(token, "/nonces", body, null, CONTROL_TIMEOUT);
    if (res.status !== 200 && res.status !== 201) this.throwBody(res);
    const b = this.bodyJson(res) as { nonce: string; call_hash: string; expires_at: number };
    if (this.now() < b.expires_at) (token as unknown as { openNonces: Map<string, string> }).openNonces.set(b.call_hash, b.nonce);
    return b;
  }

  // call() allocates a destructive nonce unless the handle already owns an
  // OPEN nonce bound to the exact call hash. Terminal/unknown results are
  // never retried; uncertain transport loss falls back to /results on the
  // same call ID.
  async call(token: TokenHandle, call: ToolCall): Promise<unknown> {
    this.checkCallerSchema(call);
    const callHash = domainHash("LEXSCOPE-CALL/1", JSON.parse(jcsString(call)));
    const destructive = TOOLS[call.tool].destructive;
    let nonceId: string | null = null;
    if (destructive) {
      const held = (token as unknown as { openNonces: Map<string, string> }).openNonces.get(callHash);
      if (held !== undefined) nonceId = held;
      else {
        const n = await this.nonce(token, call);
        nonceId = n.nonce;
      }
    }
    const nonces = token as unknown as { openNonces: Map<string, string> };
    let attempt = 0;
    while (attempt <= MAX_RETRIES) {
      let res: WireRes;
      try {
        res = await this.agentSend(token, "/calls", call, nonceId, CALL_TIMEOUT);
      } catch (e) {
        if (e instanceof TransportError) {
          // uncertain completion: status lookup on the SAME call id; NOT_FOUND
          // permits resending that same ID, never a new one.
          try {
            return await this.result(token, { v: 1, task_id: call.task_id, call_id: call.call_id });
          } catch (e2) {
            if (e2 instanceof LexScopeError && e2.code === "NOT_FOUND") {
              const res2 = await this.agentSend(token, "/calls", call, nonceId, CALL_TIMEOUT);
              if (res2.status === 200 || res2.status === 202) {
                nonces.openNonces.delete(callHash);
                return this.bodyJson(res2);
              }
              this.throwBody(res2);
            }
            throw e2;
          }
        }
        throw e;
      }
      if (res.status === 200 || res.status === 202) {
        nonces.openNonces.delete(callHash);
        return this.bodyJson(res);
      }
      const code = this.errCode(res);
      // pre-admission retryable: 429/503 only, at most MAX_RETRIES times
      if ((res.status === 429 || res.status === 503) && attempt < MAX_RETRIES && code !== "OUTCOME_UNKNOWN") {
        const ra = Number(res.headers["retry-after"] ?? "1");
        await sleep(ra * 1000);
        attempt++;
        continue;
      }
      this.throwBody(res);
    }
    throw new LexScopeError({ code: "STATE_UNAVAILABLE", retryable: true });
  }

  async result(token: TokenHandle, request: { v: 1; task_id: string; call_id: string }): Promise<unknown> {
    const res = await this.agentSend(token, "/results", request, null, CONTROL_TIMEOUT);
    if (res.status === 404) {
      // NOT_FOUND permits resending the same call ID — surface a sentinel the
      // CLI/callers can act on; never auto-generate a new call ID.
      this.throwBody(res);
    }
    if (res.status !== 200 && res.status !== 202) this.throwBody(res);
    return this.bodyJson(res);
  }

  // ---------- internals ----------

  private checkCallerSchema(call: ToolCall): void {
    try {
      validateToolCall(call);
    } catch (e) {
      if (e instanceof SchemaIssue) throw new LexScopeError({ code: e.code, request_id: null });
      throw e;
    }
  }
  private checkControlSchema<T>(fn: () => T): T {
    try {
      return fn();
    } catch (e) {
      if (e instanceof SchemaIssue) throw new LexScopeError({ code: e.code, request_id: null });
      throw e;
    }
  }

  private async controlSend(suffix: string, body: unknown, method: "GET" | "POST"): Promise<WireRes> {
    if (!this.o.controlKey || !this.o.controlKid) throw new LexScopeError({ code: "CONTROL_KEY_MISSING", request_id: null });
    const url = this.base + suffix;
    const canon = body === null ? null : jcsString(body);
    const proof = {
      v: 1, tenant_id: this.o.tenantId, htm: method, htu: url,
      iat: this.now(), jti: this.proofId(),
      bht: domainHash("LEXSCOPE-BODY/1", body === null ? null : JSON.parse(canon!)),
      op_id: body !== null && typeof body === "object" ? (body as { op_id?: string }).op_id ?? null : null,
    };
    const jws = jwsCompact({ alg: "EdDSA", typ: "lexscope-control+jwt", kid: this.o.controlKid }, proof, this.o.controlKey);
    return this.sendRaw({
      method, url,
      headers: body === null ? { "lexscope-control": jws } : { "content-type": "application/json", "lexscope-control": jws },
      body: canon,
    }, CONTROL_TIMEOUT);
  }

  private async agentSend(token: TokenHandle, suffix: string, body: unknown, nonce: string | null, timeoutMs: number): Promise<WireRes> {
    if (!this.o.callerKey || !this.callerJwk || !this.callerJkt) throw new LexScopeError({ code: "CALLER_KEY_MISSING", request_id: null });
    const secret = (token as unknown as { secret: string }).secret;
    const url = this.base + suffix;
    const canon = jcsString(body);
    const call = suffix === "/calls" ? body : suffix === "/nonces" ? (body as { call: unknown }).call : null;
    const proof = {
      v: 1, htm: "POST", htu: url, iat: this.now(), jti: this.proofId(),
      ath: b64uEncode(sha256(Buffer.from(secret, "ascii"))),
      bht: domainHash("LEXSCOPE-BODY/1", JSON.parse(canon)),
      call_hash: call !== null ? domainHash("LEXSCOPE-CALL/1", call) : null,
      nonce,
    };
    const jws = jwsCompact({ alg: "EdDSA", typ: "dpop+jwt", jwk: this.callerJwk }, proof, this.o.callerKey);
    return this.sendRaw({
      method: "POST", url,
      headers: { "content-type": "application/json", authorization: "DPoP " + secret, dpop: jws },
      body: canon,
    }, timeoutMs);
  }

  private async sendRaw(req: WireReq, timeoutMs: number): Promise<WireRes> {
    let res: WireRes;
    try {
      res = await this.o.transport(req, timeoutMs);
    } catch (e) {
      throw new TransportError(e instanceof Error ? e.message : "transport failure");
    }
    // redirects are forbidden: a 3xx is a nonretryable transport failure
    if (res.status >= 300 && res.status < 400)
      throw new LexScopeError({ code: "TRANSPORT_REDIRECT", request_id: null, retryable: false });
    return res;
  }

  private bodyJson(res: WireRes): unknown {
    return JSON.parse(Buffer.from(res.body).toString("utf8"));
  }
  private errCode(res: WireRes): string | null {
    try {
      const b = this.bodyJson(res) as { error?: { code?: string } };
      return b.error?.code ?? null;
    } catch {
      return null;
    }
  }
  private mustOk(res: WireRes, want: number): void {
    if (res.status !== want) this.throwBody(res);
  }
  private throwBody(res: WireRes): never {
    let err: { code: string; request_id?: string | null; retryable?: boolean };
    let outcome: string | undefined;
    try {
      const b = this.bodyJson(res) as { error?: { code?: string; request_id?: string; retryable?: boolean }; outcome?: string };
      err = { code: b.error?.code ?? "STATE_UNAVAILABLE", request_id: b.error?.request_id ?? null, retryable: b.error?.retryable === true };
      outcome = b.outcome;
    } catch {
      err = { code: "STATE_UNAVAILABLE", request_id: null };
    }
    const e = new LexScopeError(err);
    if (outcome) e.outcome = outcome;
    e.status = res.status;
    throw e;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------- hosted/paid surfaces — explicit stubs, never fake ----------

export class HostedControlPlane {
  constructor() {
    throw new Error(
      "NotImplemented: the hosted LexScope control plane is a paid LatticeAG surface and is not part of the OSS core — see https://github.com/LatticeAG/lexscope/blob/main/README.md#hosted",
    );
  }
}
