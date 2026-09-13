"""OpenAI function-calling shim: a host-side adapter, never an inference
endpoint or API-key proxy. Function argument blobs are strict-parsed with
duplicate-key detection, closed against the tool schema, then signed as
ToolCall objects by the SDK. `tool_call_id` is correlation metadata only —
never a LexScope call ID and never an authorization claim.
"""
from __future__ import annotations

import json

from .canon import parse_strict
from .ids import random_id
from .sdk import LexScopeError

TOOL_MAP = {
    "documents_read": "documents.read",
    "records_delete": "records.delete",
}

_PARAMETERS = {
    "documents_read": {
        "type": "object",
        "additionalProperties": False,
        "required": ["workspace", "path"],
        "properties": {"workspace": {"type": "string"}, "path": {"type": "string"}},
    },
    "records_delete": {
        "type": "object",
        "additionalProperties": False,
        "required": ["workspace", "record_id", "expected_version"],
        "properties": {
            "workspace": {"type": "string"},
            "record_id": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
    },
}

_DESCRIPTIONS = {
    "documents_read": "Read one document in the configured workspace.",
    "records_delete": "Delete one version-matched record in the configured workspace.",
}


def tool_definitions(tools=None):
    """Strict closed JSON schemas mirroring the §4 call args. No credentials
    or token fields appear anywhere in these schemas."""
    tools = tools or list(TOOL_MAP.values())
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": _DESCRIPTIONS[name],
                "strict": True,
                "parameters": _PARAMETERS[name],
            },
        }
        for name, mapped in TOOL_MAP.items()
        if mapped in tools
    ]


class OpenAIShim:
    def __init__(self, client, handle, task_id, tools=None, idgen=None):
        self.client = client
        self.handle = handle
        self.task_id = task_id
        self.tools = tools if tools is not None else ["documents.read", "records.delete"]
        self.idgen = idgen or random_id
        # host-side mapping: tool_call_id -> LexScope call_id (never exposed)
        self._corr = {}

    def tools_definitions(self):
        return tool_definitions(self.tools)

    def run_tool_call(self, tc):
        def fail(msg):
            return {"tool_call_id": tc.get("id"), "call_id": self._corr.get(tc.get("id")),
                    "ok": False, "content": msg}

        if tc.get("type") != "function":
            return fail("unsupported tool call type")
        fn = tc.get("function") or {}
        tool = TOOL_MAP.get(fn.get("name"))
        if tool is None:
            return fail(f"unknown function {fn.get('name')}")
        if tool not in self.tools:
            return fail(f"function {fn.get('name')} not in token inventory")
        try:
            args = parse_strict(fn.get("arguments", ""))
        except Exception:
            return fail("malformed function arguments")
        if not isinstance(args, dict):
            return fail("arguments must be a JSON object")
        call = {
            "v": 1,
            "call_id": self.idgen("lcl", 21),
            "task_id": self.task_id,
            "tool": tool,
            "args": args,
            # risk is NEVER taken from the model — the server derives it
        }
        allowed = ["workspace", "path"] if tool == "documents.read" else ["workspace", "record_id", "expected_version"]
        for k in args:
            if k not in allowed:
                return fail(f"unexpected argument {k}")
        try:
            res = self.client.call(self.handle, call)
            call_id = res.get("call_id") if isinstance(res.get("call_id"), str) else call["call_id"]
            self._corr[tc["id"]] = call_id
            state = res.get("state") or res.get("outcome") or "UNKNOWN"
            return {
                "tool_call_id": tc["id"],
                "call_id": call_id,
                "ok": state == "SUCCEEDED",
                "content": json.dumps(res.get("result") if state == "SUCCEEDED" else {"outcome": state}),
            }
        except LexScopeError as e:
            # the public message is already scrubbed to a stable code
            return fail(json.dumps({"outcome": e.outcome, "code": e.code}))
        except Exception:
            return fail("tool error")
