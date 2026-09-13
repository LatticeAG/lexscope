// Conformance harness — builds fixture worlds, drives real gateway requests,
// and yields the §15.1 observation tuple (status, code, dispatch_delta,
// final_call_state). All state is reset per vector unless a sequence is given.

import {
  NOW, TEN, U, TOK, TASK, N, PJ, READ, DELETE, MINT, HB,
  GATEWAY_CONFIG, fixtureSecrets, DATA_KEY,
  agentRequest, controlRequest, ident, fresh, jwk, key,
} from "./fixtures.ts";
import { deploy, type Deployment } from "../src/engine/deploy.ts";
import type { WireRequest } from "../src/engine/gateway.ts";
import { FakeDocumentsAdapter, FakeRecordsAdapter, type ToolAdapter } from "../src/engine/adapters.ts";
import { FakeHeraldAdapter, type HeraldObservation } from "../src/engine/herald.ts";
import { jcsString } from "../src/core/jcs.ts";
import { domainHash } from "../src/core/hash.ts";
import type { IdGen } from "../src/core/ids.ts";

export interface Obs {
  status: number;
  code: string;
  dispatch: number;
  callState: string;
  body: unknown;
  headers: Record<string, string>;
}

const ALPHA = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-";

// Deterministic id generation for the fixture world:
//  - lrq always RID (the fixture request id)
//  - other prefixes advance through the fixture alphabet
//  - lev event ids are derived from seq inside the authority (fixtureIds flag)
export function fixtureIdGen(): IdGen {
  const counters = new Map<string, number>();
  return (prefix, size = 21) => {
    if (prefix === "lrq") return ident("lrq", "0");
    const n = counters.get(prefix) ?? 0;
    counters.set(prefix, n + 1);
    return ident(prefix, ALPHA[n % ALPHA.length]!, size);
  };
}

export interface FixtureRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

export function wire(req: FixtureRequest, rawBody?: Uint8Array): WireRequest {
  return {
    method: req.method,
    target: req.path,
    headers: Object.entries(req.headers),
    body: rawBody ?? (req.body === null || req.body === undefined ? null : Buffer.from(jcsString(req.body), "utf8")),
  };
}

export interface WorldOpts {
  policy?: unknown;
  heraldRequired?: boolean;
  tenantId?: string;
  records?: Record<string, Record<string, number>>;
  docs?: Record<string, Record<string, { text: string; version: number }>>;
  heraldQueue?: (HeraldObservation | "throw")[];
  fixtureIds?: boolean;
  idgen?: IdGen;
}

export class World {
  deployment: Deployment;
  clockT = NOW;
  mintedToken: string | null = null;
  docs: FakeDocumentsAdapter;
  recs: FakeRecordsAdapter;
  herald: FakeHeraldAdapter;
  config: typeof GATEWAY_CONFIG;
  private opts: WorldOpts;

  constructor(opts: WorldOpts = {}) {
    this.opts = opts;
    const config = JSON.parse(JSON.stringify(GATEWAY_CONFIG)) as typeof GATEWAY_CONFIG;
    if (opts.tenantId !== undefined) config.tenant_id = opts.tenantId;
    if (opts.policy !== undefined) config.policy = opts.policy as typeof config.policy;
    if (opts.heraldRequired) config.policy.principals[0]!.herald = "required";
    this.config = config;
    const clock = { nowSeconds: () => this.clockT };
    this.docs = new FakeDocumentsAdapter({
      gateway: config.gateway_id, binding: config.tools.documents_read_binding, now: () => this.clockT,
      docs: opts.docs ?? { demo: { "reports/a.txt": { text: "Quarterly report", version: 7 } } },
    });
    this.recs = new FakeRecordsAdapter({
      gateway: config.gateway_id, binding: config.tools.records_delete_binding, now: () => this.clockT,
      records: opts.records ?? { demo: { r1: 7 } },
    });
    this.herald = new FakeHeraldAdapter();
    if (opts.heraldQueue) this.herald.observations.push(...opts.heraldQueue);
    this.deployment = deploy({
      config,
      secrets: fixtureSecrets(),
      dataKey: DATA_KEY,
      clock,
      idgen: opts.idgen ?? fixtureIdGen(),
      adapters: new Map<string, ToolAdapter>([
        [config.tools.documents_read_binding, this.docs],
        [config.tools.records_delete_binding, this.recs],
      ]),
      heraldAdapters: new Map([["HERALD", this.herald]]),
      fixtureIds: opts.fixtureIds !== false,
    });
  }

  get authority() {
    return this.deployment.authority;
  }
  get gateway() {
    return this.deployment.gateway;
  }
  get store() {
    return this.deployment.store;
  }
  get dispatchCount(): number {
    return this.docs.calls + this.recs.calls;
  }

  setTime(t: number): void {
    this.clockT = t;
  }

  // ---------- request plumbing ----------

  async send(req: WireRequest): Promise<Obs> {
    const before = this.dispatchCount;
    const res = await this.gateway.handle(req);
    const body = JSON.parse(Buffer.from(res.body).toString("utf8")) as Record<string, unknown>;
    const err = body.error as { code?: string } | undefined;
    const code = err?.code ?? "OK";
    const callState = res.callState ?? this.lookupCall(req);
    return { status: res.status, code, dispatch: this.dispatchCount - before, callState, body, headers: res.headers };
  }

  private lookupCall(req: WireRequest): string {
    let callId: string | null = null;
    try {
      const body = req.body ? (JSON.parse(Buffer.from(req.body).toString("utf8")) as Record<string, unknown>) : null;
      if (body) {
        if (typeof body.call_id === "string") callId = body.call_id;
        else if (body.call && typeof (body.call as { call_id?: string }).call_id === "string")
          callId = (body.call as { call_id: string }).call_id;
      }
    } catch {
      /* unparseable body */
    }
    if (!callId) return "ABSENT";
    return this.authority.callRowState(callId) ?? "ABSENT";
  }

  async agent(suffix: string, body: unknown, opts: Parameters<typeof agentRequest>[2] = {}): Promise<Obs> {
    const o = { ...opts };
    if (o.token === undefined && this.mintedToken !== null) o.token = this.mintedToken;
    if (o.tenant === undefined && this.opts.tenantId !== undefined) o.tenant = this.opts.tenantId;
    return this.send(wire(agentRequest(suffix, body, o)));
  }

  async control(suffix: string, body: unknown, opts: Parameters<typeof controlRequest>[2] = {}): Promise<Obs> {
    const o = { ...opts };
    if (o.tenant === undefined && this.opts.tenantId !== undefined) o.tenant = this.opts.tenantId;
    return this.send(wire(controlRequest(suffix, body, o)));
  }

  // ---------- canonical fixture states ----------

  async base(): Promise<this> {
    return this;
  }

  async issued(): Promise<this> {
    const mint = this.opts.heraldRequired ? { ...MINT, herald: HB } : MINT;
    const r = await this.control("/mint", mint, { proof_id: ident("lpf", "M", 32) });
    if (r.status !== 201) throw new Error(`ISSUED setup failed: ${r.status} ${JSON.stringify(r.body)}`);
    this.mintedToken = (r.body as { access_token: string }).access_token;
    return this;
  }

  async open(): Promise<this> {
    await this.issued();
    const r = await this.agent("/nonces", { v: 1, call: DELETE }, { proof_id: ident("lpf", "N", 32) });
    if (r.status !== 201 && r.status !== 200) throw new Error(`OPEN setup failed: ${r.status} ${JSON.stringify(r.body)}`);
    return this;
  }

  async done(): Promise<this> {
    await this.issued();
    const r = await this.agent("/calls", READ);
    if (r.status !== 200) throw new Error(`DONE setup failed: ${r.status} ${JSON.stringify(r.body)}`);
    return this;
  }

  // ---------- seeding helpers ----------

  seedBucket(kind: string, subject: string, second: number, count: number): void {
    this.store.run(
      "INSERT INTO buckets(kind,subject,second,count) VALUES(?,?,?,?) ON CONFLICT(kind,subject,second) DO UPDATE SET count=excluded.count",
      kind, subject, second, count);
  }

  setLastNow(t: number): void {
    this.store.setMeta("last_now", String(t));
  }

  // Direct policy commit for race-injection vectors (TV-26): bypasses the API.
  applyPolicyDirect(policy: { revision: string }): void {
    const hash = domainHash("LEXSCOPE-POLICY/1", policy);
    this.store.run("INSERT INTO policies(revision,hash,body) VALUES(?,?,?)",
      BigInt(policy.revision), hash, jcsString(policy));
    this.store.setMeta("active_policy_revision", policy.revision);
  }

  deleteTokenRow(id: string): void {
    this.store.run("DELETE FROM tokens WHERE id=?", id);
  }

  seedDispatching(count: number): void {
    this.store.tx(() => {
      for (let i = 0; i < count; i++) {
        this.store.run(
          "INSERT INTO calls(id,task_id,sub,jkt,token_id,scope_hash,call_hash,state,admitted_at,completed_at,result_cipher,error_code,audit_seq,purge_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
          ident("lcl", "Z") + "-" + i, TASK, U, "x".repeat(43), TOK, "0".repeat(64), "0".repeat(64),
          "DISPATCHING", NOW, null, null, null, 1, NOW + 3600 + 86400,
        );
      }
    });
  }

  auditEntries(): { seq: number; kind: string; code: string }[] {
    return this.store.all<{ body: string }>("SELECT body FROM audit ORDER BY seq").map((r) => {
      const b = JSON.parse(r.body) as { seq: string; kind: string; code: string };
      return { seq: Number(b.seq), kind: b.kind, code: b.code };
    });
  }

  auditCount(): number {
    return this.store.all("SELECT 1 FROM audit").length;
  }

  nonceState(id: string): string | null {
    const r = this.store.get<{ state: string }>("SELECT state FROM nonces WHERE id=?", id);
    return r?.state ?? null;
  }
}

// The canonical observation assertion.
export function expectObs(obs: Obs, status: number, code: string, dispatch: number, callState: string): void {
  const got = `(${obs.status},${obs.code},${obs.dispatch},${obs.callState})`;
  const want = `(${status},${code},${dispatch},${callState})`;
  if (got !== want) throw new Error(`expected ${want}, got ${got}\nbody: ${JSON.stringify(obs.body)}`);
}

export { agentRequest, controlRequest, ident, fresh, jwk, key, NOW, TEN, U, TOK, TASK, N, PJ, READ, DELETE, MINT, HB };
