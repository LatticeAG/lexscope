// Internal adapter contracts per §12 — in-process/service-binding contracts,
// never public HTTP routes. Adapters accept only the declared gateway service
// identity; provider credentials live only in adapter secret bindings.

import { LexError } from "../core/errors.ts";
import { domainHash } from "../core/hash.ts";
import { jcs } from "../core/jcs.ts";
import type { ToolCall, ToolName, ReadResultT, DeleteResultT } from "../core/schemas.ts";

export interface AdapterInfo {
  v: 1;
  tool: ToolName;
  destructive: boolean;
}

export interface Invocation {
  v: 1;
  tenant_id: string;
  call: ToolCall;
  call_hash: string;
  admission_seq: string;
  idempotency_key: string;
  deadline: number;
}

export type AdapterReply =
  | { v: 1; status: "ok"; result: ReadResultT | DeleteResultT }
  | { v: 1; status: "rejected"; code: "VERSION_CONFLICT" | "RESOURCE_MISSING" | "PROVIDER_DENIED" }
  | { v: 1; status: "unknown" };

export interface ToolAdapter {
  info(): AdapterInfo | Promise<AdapterInfo>;
  invoke(input: Invocation, binding: ServiceIdentity): Promise<AdapterReply>;
}

// A Workers-service-binding analog: a fixed identity the adapter verifies
// before touching the invocation body.
export interface ServiceIdentity {
  binding: string;
  gateway: string; // gateway_id expected by the adapter
}

export class AdapterAuthError extends Error {}

// Shared pre-checks for adapters: binding identity first, then call hash and
// deadline recomputation before any provider contact.
export async function adapterPrecheck(
  input: Invocation,
  binding: ServiceIdentity,
  expectedGateway: string,
  expectedBinding: string,
  now: () => number,
): Promise<void> {
  if (binding.gateway !== expectedGateway || binding.binding !== expectedBinding)
    throw new AdapterAuthError("service identity rejected");
  if (input.v !== 1 || domainHash("LEXSCOPE-CALL/1", input.call) !== input.call_hash)
    throw new AdapterAuthError("call hash mismatch");
  if (input.idempotency_key !== `${input.tenant_id}:${input.call.call_id}`)
    throw new AdapterAuthError("idempotency key mismatch");
  if (now() >= input.deadline) throw new AdapterAuthError("deadline passed");
}

// ---------- sandbox fakes used by conformance tests and local runs ----------
// They are fixed stores: document objects keyed by workspace/path, records keyed
// by workspace/record_id with a version counter.

export class FakeDocumentsAdapter implements ToolAdapter {
  store: Map<string, Map<string, { text: string; version: number }>>;
  expectedGateway: string;
  expectedBinding: string;
  clock: () => number;
  calls = 0;
  gate: (() => Promise<void>) | null = null;
  providerSecrets: string[] = [];
  constructor(opts: { gateway: string; binding: string; now: () => number; docs?: Record<string, Record<string, { text: string; version: number }>> }) {
    this.expectedGateway = opts.gateway;
    this.expectedBinding = opts.binding;
    this.clock = opts.now;
    this.store = new Map(Object.entries(opts.docs ?? {}).map(([w, m]) => [w, new Map(Object.entries(m))]));
  }
  info(): AdapterInfo {
    return { v: 1, tool: "documents.read", destructive: false };
  }
  async invoke(input: Invocation, binding: ServiceIdentity): Promise<AdapterReply> {
    this.calls++;
    if (this.gate) await this.gate();
    await adapterPrecheck(input, binding, this.expectedGateway, this.expectedBinding, this.clock);
    const call = input.call;
    if (call.tool !== "documents.read") throw new AdapterAuthError("wrong tool");
    const args = call.args as { workspace: string; path: string };
    const doc = this.store.get(args.workspace)?.get(args.path);
    if (doc === undefined) return { v: 1, status: "rejected", code: "RESOURCE_MISSING" };
    return { v: 1, status: "ok", result: { text: doc.text, version: doc.version } };
  }
}

export class FakeRecordsAdapter implements ToolAdapter {
  store: Map<string, Map<string, number>>; // workspace -> record_id -> version
  expectedGateway: string;
  expectedBinding: string;
  clock: () => number;
  calls = 0;
  gate: (() => Promise<void>) | null = null;
  providerSecrets: string[] = [];
  constructor(opts: { gateway: string; binding: string; now: () => number; records?: Record<string, Record<string, number>> }) {
    this.expectedGateway = opts.gateway;
    this.expectedBinding = opts.binding;
    this.clock = opts.now;
    this.store = new Map(Object.entries(opts.records ?? {}).map(([w, m]) => [w, new Map(Object.entries(m))]));
  }
  info(): AdapterInfo {
    return { v: 1, tool: "records.delete", destructive: true };
  }
  async invoke(input: Invocation, binding: ServiceIdentity): Promise<AdapterReply> {
    this.calls++;
    if (this.gate) await this.gate();
    await adapterPrecheck(input, binding, this.expectedGateway, this.expectedBinding, this.clock);
    const call = input.call;
    if (call.tool !== "records.delete") throw new AdapterAuthError("wrong tool");
    const args = call.args as { workspace: string; record_id: string; expected_version: number };
    const ws = this.store.get(args.workspace);
    const cur = ws?.get(args.record_id);
    if (cur === undefined) return { v: 1, status: "rejected", code: "RESOURCE_MISSING" };
    // atomic provider-side expected_version compare
    if (cur !== args.expected_version) return { v: 1, status: "rejected", code: "VERSION_CONFLICT" };
    ws!.delete(args.record_id);
    return { v: 1, status: "ok", result: { deleted: true, version: cur + 1 } };
  }
}

// A scripted adapter for failure/hold injection in tests.
export class ScriptedAdapter implements ToolAdapter {
  toolName: ToolName;
  destructiveFlag: boolean;
  replies: (AdapterReply | "hold" | "throw")[] = [];
  held: AdapterReply | null = null;
  heldResolvers: (() => void)[] = [];
  invocations: Invocation[] = [];
  calls = 0;
  gate: (() => Promise<void>) | null = null;
  constructor(tool: ToolName, destructive: boolean) {
    this.toolName = tool;
    this.destructiveFlag = destructive;
  }
  info(): AdapterInfo {
    return { v: 1, tool: this.toolName, destructive: this.destructiveFlag };
  }
  hold(reply: AdapterReply): void {
    this.held = reply;
  }
  release(): void {
    for (const r of this.heldResolvers) r();
    this.heldResolvers = [];
  }
  async invoke(input: Invocation): Promise<AdapterReply> {
    this.calls++;
    this.invocations.push(input);
    if (this.gate) await this.gate();
    if (this.held !== null) {
      const r = this.held;
      await new Promise<void>((resolve) => this.heldResolvers.push(resolve));
      return r;
    }
    const next = this.replies.shift();
    if (next === undefined) throw new Error("scripted adapter exhausted");
    if (next === "throw") throw new Error("adapter fault");
    if (next === "hold") return new Promise<AdapterReply>(() => {});
    return next;
  }
}
