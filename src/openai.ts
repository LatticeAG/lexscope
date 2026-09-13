// OpenAI function-calling shim: a host-side adapter, never an inference
// endpoint or API-key proxy. Function argument blobs are strict-parsed with
// duplicate-key detection, closed against the tool schema, then signed as
// ToolCall objects by the SDK. `tool_call_id` is correlation metadata only —
// never a LexScope call ID and never an authorization claim.

import { parseStrict } from "./core/strictjson.ts";
import { randomId } from "./core/ids.ts";
import { TOOLS, type ToolCall, type ToolName } from "./core/schemas.ts";
import { LexScopeClient, LexScopeError, TokenHandle } from "./sdk.ts";

export interface FunctionTool {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
    strict: true;
  };
}

export interface ModelToolCall {
  id: string; // tool_call_id — correlation only
  type: "function";
  function: { name: string; arguments: string };
}

const TOOL_MAP: Record<string, ToolName> = {
  documents_read: "documents.read",
  records_delete: "records.delete",
};

// Strict closed JSON schemas mirroring the §4 call args. No credentials or
// token fields appear anywhere in these schemas.
export function toolDefinitions(taskId: string, callPrefix: string): FunctionTool[] {
  void taskId; // task binding is injected host-side, never from the model
  return [
    {
      type: "function",
      function: {
        name: "documents_read",
        description: "Read a document from the current LexScope workspace.",
        strict: true,
        parameters: {
          type: "object",
          additionalProperties: false,
          required: ["workspace", "path"],
          properties: {
            workspace: { type: "string", minLength: 1, maxLength: 128 },
            path: { type: "string", minLength: 1, maxLength: 1024 },
          },
        },
      },
    },
    {
      type: "function",
      function: {
        name: "records_delete",
        description: "Delete a record. Destructive: requires a server-issued nonce.",
        strict: true,
        parameters: {
          type: "object",
          additionalProperties: false,
          required: ["workspace", "record_id", "expected_version"],
          properties: {
            workspace: { type: "string", minLength: 1, maxLength: 128 },
            record_id: { type: "string", minLength: 1, maxLength: 64 },
            expected_version: { type: "integer", minimum: 0 },
          },
        },
      },
    },
  ];
}

export interface CallOutcome {
  tool_call_id: string;
  call_id: string | null;
  ok: boolean;
  content: string; // model-visible result text — credential-free by construction
}

export class OpenAIShim {
  private client: LexScopeClient;
  private handle: TokenHandle;
  private taskId: string;
  // host-side mapping: tool_call_id -> LexScope call_id (never exposed)
  private corr = new Map<string, string>();
  private idgen: (pfx: string, len: number) => string;

  constructor(client: LexScopeClient, handle: TokenHandle, taskId: string, idgen?: (p: string, l: number) => string) {
    this.client = client;
    this.handle = handle;
    this.taskId = taskId;
    this.idgen = idgen ?? ((p, l) => randomId(p, l));
  }

  tools(): FunctionTool[] {
    return toolDefinitions(this.taskId, "lcl");
  }

  async runToolCall(tc: ModelToolCall): Promise<CallOutcome> {
    const fail = (msg: string): CallOutcome => ({ tool_call_id: tc.id, call_id: this.corr.get(tc.id) ?? null, ok: false, content: msg });
    if (tc.type !== "function") return fail("unsupported tool call type");
    const tool = TOOL_MAP[tc.function.name];
    if (tool === undefined) return fail(`unknown function ${tc.function.name}`);
    let args: unknown;
    try {
      args = parseStrict(new TextEncoder().encode(tc.function.arguments));
    } catch {
      return fail("malformed function arguments");
    }
    if (typeof args !== "object" || args === null || Array.isArray(args)) return fail("arguments must be a JSON object");
    const call: ToolCall = {
      v: 1,
      call_id: this.idgen("lcl", 21),
      task_id: this.taskId,
      tool,
      args: args as ToolCall["args"],
      // risk is NEVER taken from the model — the server derives it
    } as ToolCall;
    // enforce arg closure against the tool schema before signing
    const argKeys = Object.keys(args as Record<string, unknown>);
    const allowed = tool === "documents.read" ? ["workspace", "path"] : ["workspace", "record_id", "expected_version"];
    for (const k of argKeys) if (!allowed.includes(k)) return fail(`unexpected argument ${k}`);
    try {
      const res = (await this.client.call(this.handle, call)) as { call_id?: string; state?: string; outcome?: string; result?: unknown };
      const callId = typeof res.call_id === "string" ? res.call_id : call.call_id;
      this.corr.set(tc.id, callId);
      const state = typeof res.state === "string" ? res.state : typeof res.outcome === "string" ? res.outcome : "UNKNOWN";
      return {
        tool_call_id: tc.id,
        call_id: callId,
        ok: state === "SUCCEEDED",
        content: state === "SUCCEEDED" ? JSON.stringify(res.result ?? null) : JSON.stringify({ outcome: state }),
      };
    } catch (e) {
      if (e instanceof LexScopeError) {
        // the public message is already scrubbed to a stable code
        return fail(JSON.stringify({ outcome: e.outcome, code: e.code }));
      }
      return fail("tool error");
    }
  }
}
