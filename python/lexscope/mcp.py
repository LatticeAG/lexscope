"""MCP stdio shim: local JSON-RPC 2.0 server exposing only documents_read and
records_delete. Newline-delimited UTF-8 JSON on stdio; batches rejected;
65536-byte message cap; JSON-RPC only on stdout; scrubbed diagnostics on
stderr. No credentials ever appear in tool schemas, results, or logs.
"""
from __future__ import annotations

import json
import sys

from .canon import parse_strict
from .ids import random_id
from .schemas import TOOL_NAME_RE
from .sdk import LexScopeError

PROTOCOL_VERSION = "2025-06-18"
MAX_MSG = 65536

TOOL_MAP = {
    "documents_read": "documents.read",
    "records_delete": "records.delete",
}

TOOL_DEFS = [
    {
        "name": "documents_read",
        "description": "Read one document in the configured workspace.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["workspace", "path"],
            "properties": {"workspace": {"type": "string"}, "path": {"type": "string"}},
        },
    },
    {
        "name": "records_delete",
        "description": "Delete one version-matched record in the configured workspace.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["workspace", "record_id", "expected_version"],
            "properties": {
                "workspace": {"type": "string"},
                "record_id": {"type": "string"},
                "expected_version": {"type": "integer", "minimum": 0},
            },
        },
    },
]


def _valid_id(i):
    if i is None:
        return True
    if isinstance(i, str):
        return 1 <= len(i) <= 64 and all(0x20 <= ord(c) <= 0x7E for c in i)
    if isinstance(i, int) and not isinstance(i, bool):
        return 0 <= i <= 9007199254740991
    return False


class McpServer:
    def __init__(self, client, handle, task_id, tools=None, idgen=None, out=None, diag=None):
        self.client = client
        self.handle = handle
        self.task_id = task_id
        self.tools = tools if tools is not None else ["documents.read", "records.delete"]
        self.idgen = idgen or random_id
        self.out = out or (lambda line: sys.stdout.write(line + "\n"))
        self.diag = diag or (lambda line: sys.stderr.write(line + "\n"))
        self.initialized = False

    def _send(self, msg):
        self.out(json.dumps(msg, separators=(",", ":")))

    def _reply(self, i, result):
        self._send({"jsonrpc": "2.0", "id": i, "result": result})

    def _err(self, i, code, message):
        self._send({"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": message}})

    # one NDJSON line -> optional response lines. Never raises.
    def handle_line(self, line: str):
        if len(line.encode("utf-8")) > MAX_MSG:
            self._err(None, -32600, "message too large")
            return
        try:
            msg = parse_strict(line)
        except Exception:
            self._err(None, -32700, "parse error")
            return
        if isinstance(msg, list):
            self._err(None, -32600, "batches are not accepted")
            return
        if not isinstance(msg, dict):
            self._err(None, -32600, "invalid request")
            return
        if msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str) or not _valid_id(msg.get("id")):
            self._err(None, -32600, "invalid request")
            return
        i = msg.get("id")
        method = msg["method"]
        params = msg.get("params")
        is_notif = "id" not in msg

        if method == "initialize":
            if i is None:
                return
            req = params.get("protocolVersion") if isinstance(params, dict) else None
            requested = req if isinstance(req, str) else None
            self.initialized = True
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "lexscope", "version": "1.0.0"},
            }
            if requested is not None and requested != PROTOCOL_VERSION:
                result["requestedProtocolVersion"] = requested
            self._reply(i, result)
            return
        if method == "notifications/initialized":
            return  # notification: no response
        if method == "ping":
            if i is not None:
                self._reply(i, {})
            return
        if method == "tools/list":
            if not self.initialized:
                self._err(i, -32002, "not initialized")
                return
            # inventory is derived from the token's permitted tool names
            self._reply(i, {"tools": [d for d in TOOL_DEFS if TOOL_MAP[d["name"]] in self.tools]})
            return
        if method == "tools/call":
            if not self.initialized:
                self._err(i, -32002, "not initialized")
                return
            if not isinstance(params, dict):
                self._err(i, -32602, "invalid params")
                return
            name = params.get("name")
            args = params.get("arguments")
            if not isinstance(name, str) or name not in TOOL_MAP:
                self._err(i, -32602, "unknown tool")
                return
            if not isinstance(args, dict):
                self._err(i, -32602, "invalid arguments")
                return
            tool = TOOL_MAP[name]
            allowed = ["workspace", "path"] if tool == "documents.read" else ["workspace", "record_id", "expected_version"]
            for k in args:
                if k not in allowed:
                    self._err(i, -32602, f"unexpected argument {k}")
                    return
            call = {"v": 1, "call_id": self.idgen("lcl", 21), "task_id": self.task_id, "tool": tool, "args": args}
            try:
                res = self.client.call(self.handle, call)
                state = res.get("state") or res.get("outcome") or "UNKNOWN"
                text = json.dumps(res.get("result") if state == "SUCCEEDED" else {"outcome": state})
                self._reply(i, {"content": [{"type": "text", "text": text}], "isError": state != "SUCCEEDED"})
            except LexScopeError as e:
                self._reply(i, {"content": [{"type": "text", "text": json.dumps({"outcome": e.outcome, "code": e.code})}], "isError": True})
            except Exception:
                self.diag("tool call failed")
                self._reply(i, {"content": [{"type": "text", "text": json.dumps({"outcome": "UNKNOWN"})}], "isError": True})
            return
        if not is_notif:
            self._err(i, -32601, "method not found")

    # stdio entry: NDJSON in, NDJSON out. Diagnostics go to stderr, scrubbed.
    def run_stdio(self):
        for line in sys.stdin:
            line = line.rstrip("\n")
            try:
                self.handle_line(line)
            except Exception:
                self.diag("internal error")
