// MCP stdio shim: local JSON-RPC 2.0 server exposing only documents_read and
// records_delete. Newline-delimited UTF-8 JSON on stdio; batches rejected;
// 65536-byte message cap; JSON-RPC only on stdout; scrubbed diagnostics on
// stderr. No credentials ever appear in tool schemas, results, or logs.

import { createInterface } from "node:readline";
import { parseStrict } from "./core/strictjson.ts";
import { randomId } from "./core/ids.ts";
import type { LexScopeClient, TokenHandle } from "./sdk.ts";
import { LexScopeError } from "./sdk.ts";
import type { ToolCall, ToolName } from "./core/schemas.ts";

const PROTOCOL_VERSION = "2025-06-18";
const MAX_MSG = 65536;

const TOOL_MAP: Record<string, ToolName> = {
  documents_read: "documents.read",
  records_delete: "records.delete",
};

const TOOL_DEFS = [
  {
    name: "documents_read",
    description: "Read one document in the configured workspace.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["workspace", "path"],
      properties: {
        workspace: { type: "string" },
        path: { type: "string" },
      },
    },
  },
  {
    name: "records_delete",
    description: "Delete one version-matched record in the configured workspace.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["workspace", "record_id", "expected_version"],
      properties: {
        workspace: { type: "string" },
        record_id: { type: "string" },
        expected_version: { type: "integer", minimum: 0 },
      },
    },
  },
];

type JsonId = string | number | null;

function validId(id: unknown): id is JsonId {
  if (id === null) return true;
  if (typeof id === "string") return id.length >= 1 && id.length <= 64 && /^[\x20-\x7e]+$/.test(id);
  if (typeof id === "number") return Number.isSafeInteger(id) && id >= 0;
  return false;
}

export class McpServer {
  private client: LexScopeClient;
  private handle: TokenHandle;
  private taskId: string;
  private tools: ToolName[];
  private idgen: (p: string, l: number) => string;
  private initialized = false;
  private out: (line: string) => void;
  private diag: (line: string) => void;
  private seq = 0;

  constructor(opts: {
    client: LexScopeClient;
    handle: TokenHandle;
    taskId: string;
    tools?: ToolName[];
    idgen?: (p: string, l: number) => string;
    out?: (line: string) => void;
    diag?: (line: string) => void;
  }) {
    this.client = opts.client;
    this.handle = opts.handle;
    this.taskId = opts.taskId;
    this.tools = opts.tools ?? ["documents.read", "records.delete"];
    this.idgen = opts.idgen ?? ((p, l) => randomId(p, l));
    this.out = opts.out ?? ((l) => process.stdout.write(l + "\n"));
    this.diag = opts.diag ?? ((l) => process.stderr.write(l + "\n"));
  }

  private send(msg: unknown): void {
    this.out(JSON.stringify(msg));
  }
  private reply(id: JsonId, result: unknown): void {
    this.send({ jsonrpc: "2.0", id, result });
  }
  private err(id: JsonId, code: number, message: string): void {
    this.send({ jsonrpc: "2.0", id, error: { code, message } });
  }

  // one NDJSON line -> optional response lines. Never throws.
  async handleLine(line: string): Promise<void> {
    if (Buffer.byteLength(line, "utf8") > MAX_MSG) {
      this.err(null, -32600, "message too large");
      return;
    }
    let msg: unknown;
    try {
      msg = parseStrict(new TextEncoder().encode(line));
    } catch {
      this.err(null, -32700, "parse error");
      return;
    }
    if (Array.isArray(msg)) {
      this.err(null, -32600, "batches are not accepted");
      return;
    }
    if (typeof msg !== "object" || msg === null) {
      this.err(null, -32600, "invalid request");
      return;
    }
    const o = msg as Record<string, unknown>;
    if (o.jsonrpc !== "2.0" || typeof o.method !== "string" || !validId(o.id ?? null)) {
      this.err(null, -32600, "invalid request");
      return;
    }
    const id = (o.id ?? null) as JsonId;
    const method = o.method as string;
    const params = o.params;
    const isNotif = !("id" in o);

    switch (method) {
      case "initialize": {
        if (id === null) break;
        const req = typeof params === "object" && params !== null ? (params as Record<string, unknown>).protocolVersion : undefined;
        const requested = typeof req === "string" ? req : null;
        this.initialized = true;
        this.reply(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "lexscope", version: "1.0.0" },
          ...(requested !== null && requested !== PROTOCOL_VERSION ? { requestedProtocolVersion: requested } : {}),
        });
        return;
      }
      case "notifications/initialized":
        return; // notification: no response
      case "ping":
        if (id !== null) this.reply(id, {});
        return;
      case "tools/list": {
        if (!this.initialized) { this.err(id, -32002, "not initialized"); return; }
        // inventory is derived from the token's permitted tool names
        this.reply(id, { tools: TOOL_DEFS.filter((d) => this.tools.includes(TOOL_MAP[d.name]!)) });
        return;
      }
      case "tools/call": {
        if (!this.initialized) { this.err(id, -32002, "not initialized"); return; }
        if (typeof params !== "object" || params === null) { this.err(id, -32602, "invalid params"); return; }
        const p = params as Record<string, unknown>;
        const name = p.name;
        const args = p.arguments;
        if (typeof name !== "string" || TOOL_MAP[name] === undefined) { this.err(id, -32602, "unknown tool"); return; }
        if (typeof args !== "object" || args === null || Array.isArray(args)) { this.err(id, -32602, "invalid arguments"); return; }
        const tool = TOOL_MAP[name];
        const allowed = tool === "documents.read" ? ["workspace", "path"] : ["workspace", "record_id", "expected_version"];
        for (const k of Object.keys(args)) {
          if (!allowed.includes(k)) { this.err(id, -32602, `unexpected argument ${k}`); return; }
        }
        const call = { v: 1, call_id: this.idgen("lcl", 21), task_id: this.taskId, tool, args } as ToolCall;
        this.seq++;
        try {
          const res = (await this.client.call(this.handle, call)) as { state?: string; outcome?: string; result?: unknown };
          const state = typeof res.state === "string" ? res.state : typeof res.outcome === "string" ? res.outcome : "UNKNOWN";
          const text = state === "SUCCEEDED" ? JSON.stringify(res.result ?? null) : JSON.stringify({ outcome: state });
          this.reply(id, { content: [{ type: "text", text }], isError: state !== "SUCCEEDED" });
        } catch (e) {
          if (e instanceof LexScopeError) {
            this.reply(id, { content: [{ type: "text", text: JSON.stringify({ outcome: e.outcome, code: e.code }) }], isError: true });
          } else {
            this.diag("tool call failed");
            this.reply(id, { content: [{ type: "text", text: JSON.stringify({ outcome: "UNKNOWN" }) }], isError: true });
          }
        }
        return;
      }
      default:
        if (!isNotif) this.err(id, -32601, "method not found");
    }
  }

  // stdio entry: NDJSON in, NDJSON out. Diagnostics go to stderr, scrubbed.
  runStdio(): void {
    const rl = createInterface({ input: process.stdin, terminal: false });
    rl.on("line", (line) => {
      this.handleLine(line).catch(() => this.diag("internal error"));
    });
  }
}
