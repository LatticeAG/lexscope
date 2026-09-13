// Gateway — the public-Worker equivalent: TLS-terminating ingress enforcing
// byte limits, strict JSON, the §5.3 step 1-3 pipeline, and routing into the
// single TenantAuthority. No edge-local revocation/authority state.

import { LexError, errorBody, retryAfter } from "../core/errors.ts";
import { parseStrict, JsonParseError } from "../core/strictjson.ts";
import { domainHash, sha256 } from "../core/hash.ts";
import { b64uEncode } from "../core/b64.ts";
import type { IdGen } from "../core/ids.ts";
import {
  SchemaIssue, checkNoChaining, validateTokenClaims, validateTokenHeader,
  validateProofHeader, validateCallerProof, validateControlHeader,
  validateControlProof, validateToolCall, validateNonceRequest,
  validateResultRequest, validateMintRequest, validateRevokeRequest,
  validateTokenInspectRequest, validatePolicyApplyRequest, validateRotateRequest,
  validateAuditQuery, TOOLS, isObj,
  type ToolCall, type CallerProof, type ControlProof, type TokenClaims,
  type PublicJwk,
} from "../core/schemas.ts";
import { parseJws, jkt as jwkThumbprint, ed25519Verify, type ParsedJws } from "../core/jwt.ts";
import { jcsString } from "../core/jcs.ts";
import { TenantAuthority, type AgentCtx, type ControlCtx, CrashFault } from "./authority.ts";

export interface WireRequest {
  method: string;
  target: string; // path + optional ?query
  headers: [string, string][];
  body: Uint8Array | null;
}

export interface WireResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  callState?: string;
}

const LIMITS = {
  token: 8192,
  proof: 4096,
  authCombined: 12293,
  headers: 16384,
  body: 65536,
};

const AGENT_ROUTES = new Set(["nonces", "calls", "results"]);
const CONTROL_POST = new Set(["mint", "revoke", "inspect", "policy", "rotate"]);
const KNOWN_RESOURCES = new Set([...AGENT_ROUTES, ...CONTROL_POST, "audit", "keys"]);

export class Gateway {
  authority: TenantAuthority;
  idgen: IdGen;

  constructor(authority: TenantAuthority, idgen: IdGen) {
    this.authority = authority;
    this.idgen = idgen;
  }

  get cfg() {
    return this.authority.cfg;
  }

  async handle(req: WireRequest): Promise<WireResponse> {
    const requestId = this.idgen("lrq");
    try {
      const r = await this.route(req, requestId);
      return respond(r.status, r.body, r.callState);
    } catch (e) {
      if (e instanceof CrashFault) throw e;
      const err = e instanceof LexError ? e : new LexError("STATE_UNAVAILABLE");
      return respond(err.status, errorBody(err, requestId));
    }
  }

  private async route(req: WireRequest, requestId: string): Promise<{ status: number; body: unknown; callState?: string }> {
    // ---- step 1: method/path/query/content-type/header/body limits ----
    const headerBytes = req.headers.reduce((a, [k, v]) => a + k.length + v.length, 0);
    if (headerBytes > LIMITS.headers) throw new LexError("HEADERS_TOO_LARGE");
    const q = req.target.indexOf("?");
    const path = q === -1 ? req.target : req.target.slice(0, q);
    const rawQuery = q === -1 ? null : req.target.slice(q + 1);
    if (req.method === "OPTIONS") throw new LexError("METHOD_NOT_ALLOWED");

    if (path === "/healthz") {
      if (req.method !== "GET") throw new LexError("METHOD_NOT_ALLOWED");
      return this.authority.health();
    }

    const m = /^\/v1\/tenants\/(ltn_[A-Za-z0-9_-]{21})\/([a-z]+)$/.exec(path);
    if (!m || !KNOWN_RESOURCES.has(m[2]!)) throw new LexError("NOT_FOUND");
    const tenantId = m[1]!;
    const resource = m[2]!;
    if (tenantId !== this.cfg.tenant_id) {
      // Unknown tenant: public existence check is 404; authenticated surfaces
      // fail closed because no foreign tenant context verifies here.
      if (resource === "keys") {
        if (req.method !== "GET") throw new LexError("METHOD_NOT_ALLOWED");
        throw new LexError("NOT_FOUND");
      }
      if (req.method !== "POST" && resource !== "audit") throw new LexError("METHOD_NOT_ALLOWED");
      if (resource === "audit" && req.method !== "GET") throw new LexError("METHOD_NOT_ALLOWED");
      throw new LexError("AUTH_INVALID");
    }

    if (resource === "keys") {
      if (req.method !== "GET") throw new LexError("METHOD_NOT_ALLOWED");
      return this.authority.handleKeys();
    }
    if (resource === "audit") {
      if (req.method !== "GET") throw new LexError("METHOD_NOT_ALLOWED");
      return this.controlRoute(req, "audit", requestId, rawQuery, path);
    }
    if (AGENT_ROUTES.has(resource)) {
      if (req.method !== "POST") throw new LexError("METHOD_NOT_ALLOWED");
      if (rawQuery !== null) throw new LexError("SCHEMA_INVALID");
      return this.agentRoute(req, resource, requestId, path);
    }
    // CONTROL_POST
    if (req.method !== "POST") throw new LexError("METHOD_NOT_ALLOWED");
    if (rawQuery !== null) throw new LexError("SCHEMA_INVALID");
    return this.controlRoute(req, resource, requestId, null, path);
  }

  // ---------- shared step-1 helpers ----------

  private headerValues(req: WireRequest, name: string): string[] {
    const lower = name.toLowerCase();
    return req.headers.filter(([k]) => k.toLowerCase() === lower).map(([, v]) => v);
  }

  private contentType(req: WireRequest): void {
    const ct = this.headerValues(req, "content-type");
    if (ct.length !== 1 || ct[0]!.trim() !== "application/json") throw new LexError("MEDIA_UNSUPPORTED");
    if (this.headerValues(req, "content-encoding").length > 0) throw new LexError("MEDIA_UNSUPPORTED");
  }

  private parseBody(req: WireRequest): unknown {
    if (req.body === null || req.body.length === 0) throw new LexError("JSON_INVALID");
    if (req.body.length > LIMITS.body) throw new LexError("BODY_TOO_LARGE");
    try {
      return parseStrict(req.body);
    } catch (e) {
      if (e instanceof JsonParseError) throw new LexError(e.kind);
      throw new LexError("JSON_INVALID");
    }
  }

  private schemaWrap(fn: () => void): void {
    try {
      fn();
    } catch (e) {
      if (e instanceof SchemaIssue) throw new LexError(e.code);
      throw e;
    }
  }

  // ---------- agent routes: DPoP token + caller proof ----------

  private async agentRoute(req: WireRequest, resource: string, requestId: string, path: string): Promise<{ status: number; body: unknown; callState?: string }> {
    if (this.authority.maintenanceMode && resource !== "results") throw new LexError("STATE_UNAVAILABLE");
    this.contentType(req);
    const auth = this.headerValues(req, "authorization");
    const dpop = this.headerValues(req, "dpop");
    if (this.headerValues(req, "lexscope-control").length > 0) throw new LexError("SCHEMA_INVALID");
    if (auth.length !== 1 || dpop.length !== 1) throw new LexError("SCHEMA_INVALID");
    const tokenVal = auth[0]!;
    const proofVal = dpop[0]!;
    if (Buffer.byteLength(tokenVal, "ascii") > 5 + LIMITS.token) throw new LexError("TOKEN_TOO_LARGE");
    if (Buffer.byteLength(proofVal, "ascii") > LIMITS.proof) throw new LexError("PROOF_TOO_LARGE");
    if (Buffer.byteLength(tokenVal, "ascii") + Buffer.byteLength(proofVal, "ascii") > LIMITS.authCombined)
      throw new LexError("AUTH_TOO_LARGE");
    if (!tokenVal.startsWith("DPoP ") || tokenVal.length <= 5) throw new LexError("AUTH_INVALID");
    const token = tokenVal.slice(5);
    if (/\s/.test(token)) throw new LexError("AUTH_INVALID");

    // ---- step 2: closed request/JWS schemas (specified sub-order) ----
    const body = this.parseBody(req);
    let call: ToolCall | null = null;
    let resultReq: { task_id: string; call_id: string } | null = null;
    this.schemaWrap(() => {
      if (resource === "calls") call = validateToolCall(body) as ToolCall;
      else if (resource === "nonces") call = validateNonceRequest(body).call;
      else resultReq = validateResultRequest(body);
    });
    // token: JSON-array -> CHAINING; malformed -> AUTH_INVALID
    const trimmed = token.trim();
    if (trimmed.startsWith("[")) {
      try {
        if (Array.isArray(JSON.parse(trimmed))) throw new LexError("CHAINING_FORBIDDEN");
      } catch (e) {
        if (e instanceof LexError) throw e;
      }
    }
    const tj = parseJws(token);
    if (!tj) throw new LexError("AUTH_INVALID");
    const tClaims = this.checkJws(tj, "token") as TokenClaims;
    const pj = parseJws(proofVal);
    if (!pj) throw new LexError("AUTH_INVALID");
    const proof = this.checkJws(pj, "caller") as CallerProof;

    // ---- step 3: signatures, canonical bytes, exact compares ----
    if (!tj.canonical || !pj.canonical) throw new LexError("AUTH_INVALID");
    const tokenKid = (tj.header as { kid: string }).kid;
    const signJwk = this.authority.signingJwk(tokenKid);
    if (!signJwk) throw new LexError("AUTH_INVALID");
    if (!ed25519Verify(tj.signingInput, tj.signature, signJwk)) throw new LexError("AUTH_INVALID");
    if (tClaims.iss !== `urn:lexscope:gateway:${this.cfg.gateway_id}`) throw new LexError("AUTH_INVALID");
    if (tClaims.aud !== `${this.cfg.origin}/v1/tenants/${this.cfg.tenant_id}`) throw new LexError("AUTH_INVALID");
    if (tClaims.iat !== tClaims.nbf) throw new LexError("AUTH_INVALID");
    const ttl = tClaims.exp - tClaims.iat;
    if (ttl < 30 || ttl > 300) throw new LexError("AUTH_INVALID");
    const proofJwk = (pj.header as { jwk: PublicJwk }).jwk;
    if (!ed25519Verify(pj.signingInput, pj.signature, proofJwk)) throw new LexError("AUTH_INVALID");
    if (jwkThumbprint(proofJwk) !== tClaims.cnf.jkt) throw new LexError("AUTH_INVALID");
    if (proof.ath !== b64uEncode(sha256(Buffer.from(token, "ascii")))) throw new LexError("AUTH_INVALID");
    if (proof.bht !== domainHash("LEXSCOPE-BODY/1", body)) throw new LexError("AUTH_INVALID");
    if (proof.htu !== this.cfg.origin + path) throw new LexError("AUTH_INVALID");
    const expectedCallHash =
      resource === "calls" || resource === "nonces"
        ? domainHash("LEXSCOPE-CALL/1", JSON.parse(jcsString(call)))
        : null;
    if (proof.call_hash !== expectedCallHash) throw new LexError("AUTH_INVALID");
    const destructive = resource === "calls" && TOOLS[call!.tool].destructive;
    if (proof.nonce !== null && !destructive) throw new LexError("NONCE_NOT_REQUIRED");

    const ctx: AgentCtx = {
      requestId, token, claims: tClaims, tokenKid,
      callerJwk: proofJwk, callerJkt: tClaims.cnf.jkt, proof,
    };
    if (resource === "calls") return this.authority.handleCall(ctx, call!);
    if (resource === "nonces") return this.authority.handleNonce(ctx, call!);
    return this.authority.handleResult(ctx, resultReq!);
  }

  // Shared JWS schema pipeline in the §5.3 sub-order: JOSE header (any fault ->
  // AUTH_INVALID) -> forbidden delegation members (CHAINING_FORBIDDEN) ->
  // claims schema (v first, then closure -> VERSION_UNSUPPORTED/SCHEMA_INVALID).
  private checkJws(j: ParsedJws, kind: "token" | "caller" | "control"): TokenClaims | CallerProof | ControlProof {
    const header = j.header as Record<string, unknown>;
    const payload = j.payload;
    try {
      if (kind === "token") validateTokenHeader(header);
      else if (kind === "caller") validateProofHeader(header);
      else validateControlHeader(header);
    } catch (e) {
      if (e instanceof SchemaIssue) throw new LexError("AUTH_INVALID");
      throw e;
    }
    if (isObj(payload)) {
      this.schemaWrap(() => {
        checkNoChaining(header, "");
        checkNoChaining(payload as Record<string, unknown>, "");
      });
    }
    try {
      if (kind === "token") return validateTokenClaims(payload);
      if (kind === "caller") return validateCallerProof(payload);
      return validateControlProof(payload);
    } catch (e) {
      if (e instanceof SchemaIssue) throw new LexError(e.code);
      throw e;
    }
  }

  // ---------- control routes: LexScope-Control proof only ----------

  private async controlRoute(
    req: WireRequest, resource: string, requestId: string,
    rawQuery: string | null, path: string,
  ): Promise<{ status: number; body: unknown; callState?: string }> {
    if (this.authority.maintenanceMode && (resource === "mint" || resource === "policy" || resource === "rotate"))
      throw new LexError("STATE_UNAVAILABLE");
    if (this.headerValues(req, "authorization").length > 0 || this.headerValues(req, "dpop").length > 0)
      throw new LexError("SCHEMA_INVALID");
    const ctrl = this.headerValues(req, "lexscope-control");
    if (ctrl.length !== 1) throw new LexError("SCHEMA_INVALID");
    const proofVal = ctrl[0]!;
    if (Buffer.byteLength(proofVal, "ascii") > LIMITS.proof) throw new LexError("PROOF_TOO_LARGE");
    if (resource !== "audit") this.contentType(req);

    const body = req.method === "GET" ? null : this.parseBody(req);
    let parsed: unknown = null;
    this.schemaWrap(() => {
      switch (resource) {
        case "mint": parsed = validateMintRequest(body); break;
        case "revoke": parsed = validateRevokeRequest(body); break;
        case "inspect": parsed = validateTokenInspectRequest(body); break;
        case "policy": parsed = validatePolicyApplyRequest(body); break;
        case "rotate": parsed = validateRotateRequest(body); break;
        case "audit": parsed = null; break;
      }
    });

    const cj = parseJws(proofVal);
    if (!cj) throw new LexError("AUTH_INVALID");
    const proof = this.checkJws(cj, "control") as ControlProof;
    if (!cj.canonical) throw new LexError("AUTH_INVALID");
    const kid = (cj.header as { kid: string }).kid;
    const enrollment = this.cfg.controls.find((c) => c.kid === kid);
    if (!enrollment) throw new LexError("AUTH_INVALID");
    if (!ed25519Verify(cj.signingInput, cj.signature, enrollment.jwk)) throw new LexError("AUTH_INVALID");
    if (proof.tenant_id !== this.cfg.tenant_id) throw new LexError("AUTH_INVALID");
    if (proof.htm !== req.method) throw new LexError("AUTH_INVALID");
    const expectedHtu = resource === "audit" ? `${this.cfg.origin}${path}?${rawQuery}` : this.cfg.origin + path;
    if (proof.htu !== expectedHtu) throw new LexError("AUTH_INVALID");
    if (proof.bht !== domainHash("LEXSCOPE-BODY/1", body)) throw new LexError("AUTH_INVALID");
    const bodyOpId = parsed !== null && typeof parsed === "object" && "op_id" in (parsed as object)
      ? (parsed as { op_id: string }).op_id
      : null;
    if (proof.op_id !== bodyOpId) throw new LexError("AUTH_INVALID");

    const ctx: ControlCtx = { requestId, kid, proof, body };
    switch (resource) {
      case "mint": return this.authority.handleMint(ctx, parsed as never);
      case "revoke": return this.authority.handleRevoke(ctx, parsed as never);
      case "inspect": return this.authority.handleInspect(ctx, parsed as never);
      case "policy": return this.authority.handlePolicy(ctx, parsed as never);
      case "rotate": return this.authority.handleRotate(ctx, parsed as never);
      case "audit": {
        const q = (() => {
          try {
            return validateAuditQuery(rawQuery);
          } catch (e) {
            if (e instanceof SchemaIssue) throw new LexError("SCHEMA_INVALID");
            throw e;
          }
        })();
        return this.authority.handleAudit(ctx, q.after, q.limit);
      }
    }
    throw new LexError("NOT_FOUND");
  }
}

function respond(status: number, body: unknown, callState?: string): WireResponse {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "cache-control": "no-store",
  };
  const ra = retryAfter(status);
  if (ra !== null) headers["retry-after"] = String(ra);
  const out: WireResponse = { status, headers, body: Buffer.from(jcsString(body), "utf8") };
  if (callState !== undefined) out.callState = callState;
  return out;
}
