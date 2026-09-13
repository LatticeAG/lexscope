"""Closed-schema validators for the SDK-visible request surface — identical
member sets, ordering rules, and error codes to src/core/schemas.ts.
"""
from __future__ import annotations

import re

from .canon import jcs, MAX_SAFE
from .crypto import b64u_decode
from .ids import is_id, is_counter, is_hash

IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
PATH_SEG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PTR_SEG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
TOOL_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$")
HERALD_SOURCE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
SECRET_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

TOOLS = {"documents.read": {"destructive": False}, "records.delete": {"destructive": True}}


class SchemaIssue(Exception):
    def __init__(self, ptr: str, msg: str, code: str = "SCHEMA_INVALID"):
        super().__init__(f"{code} {ptr}: {msg}")
        self.ptr = ptr
        self.code = code


def issue(ptr: str, msg: str, code: str = "SCHEMA_INVALID"):
    raise SchemaIssue(ptr, msg, code)


def closed(v, ptr: str, required, optional=()):
    if not isinstance(v, dict):
        issue(ptr or "/", "expected object")
    keys = set(v.keys())
    for r in required:
        if r not in v:
            issue(f"{ptr}/{r}", "missing")
    allowed = set(required) | set(optional)
    for k in keys - allowed:
        issue(f"{ptr}/{k}", "unknown member")
    return v


def check_version(v, ptr=""):
    if isinstance(v, dict) and "v" in v and v["v"] != 1:
        raise SchemaIssue(f"{ptr}/v", "version", "VERSION_UNSUPPORTED")


def typ(v, t: str, ptr: str):
    ok = {
        "string": isinstance(v, str),
        "number": isinstance(v, (int, float)) and not isinstance(v, bool),
        "integer": isinstance(v, int) and not isinstance(v, bool),
        "boolean": isinstance(v, bool),
        "array": isinstance(v, list),
        "object": isinstance(v, dict),
        "scalar": v is None or isinstance(v, (str, int, float, bool)),
    }[t]
    if not ok:
        issue(ptr, f"expected {t}")


def id_field(v, prefix: str, ptr: str):
    if not is_id(v, prefix):
        issue(ptr, f"expected {prefix}_ id")
    return v


def hash_field(v, ptr: str):
    if not is_hash(v):
        issue(ptr, "expected sha256 hex")
    return v


def counter_field(v, ptr: str):
    if not is_counter(v):
        issue(ptr, "expected decimal counter")
    return v


def b64u32(v, ptr: str):
    if not isinstance(v, str):
        issue(ptr, "expected b64u")
    b = b64u_decode(v)
    if b is None or len(b) != 32:
        issue(ptr, "expected 32-byte b64u")
    return v


# ---------- scalar grammars ----------


def is_workspace(v) -> bool:
    return isinstance(v, str) and bool(IDENT_RE.match(v))


def is_path(v) -> bool:
    if not isinstance(v, str) or not v or len(v.encode("utf-8")) > 512:
        return False
    if re.search(r"[%\\]", v):
        return False
    if not re.fullmatch(r"[\x20-\x7e]+", v):
        return False
    if v.startswith("/") or v.endswith("/"):
        return False
    segs = v.split("/")
    if not (1 <= len(segs) <= 16):
        return False
    return all(s not in (".", "..") and PATH_SEG_RE.match(s) for s in segs)


def is_pointer(v) -> bool:
    if not isinstance(v, str) or not v.startswith("/"):
        return False
    segs = v[1:].split("/")
    return 1 <= len(segs) <= 8 and all(PTR_SEG_RE.match(s) for s in segs)


def is_tool_name(v) -> bool:
    return v in TOOLS


def _nonneg_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE


PREDICATE_DOMAIN = {
    "documents.read": {
        "/workspace": {"ops": ["eq", "in"], "operand": is_workspace},
        "/path": {"ops": ["eq", "in", "path_prefix"], "operand": is_path},
    },
    "records.delete": {
        "/workspace": {"ops": ["eq", "in"], "operand": is_workspace},
        "/record_id": {"ops": ["eq", "in"], "operand": lambda v: isinstance(v, str) and bool(IDENT_RE.match(v))},
        "/expected_version": {"ops": ["eq", "in", "int_range"], "operand": _nonneg_int},
    },
}

_SCALAR_TYPES = (str, int, bool)


def _is_scalar(v) -> bool:
    return v is None or isinstance(v, (str, bool)) or (isinstance(v, int) and not isinstance(v, bool))


def _scalar_type(v):
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, str):
        return "string"
    if isinstance(v, int):
        return "number"
    return type(v).__name__


def valid_predicate_shape(v, ptr: str):
    o = closed(v, ptr, ["ptr", "op"], ["value", "values", "min", "max"])
    if not is_pointer(o["ptr"]):
        issue(f"{ptr}/ptr", "bad pointer")
    op = o["op"]
    if op == "eq":
        closed(v, ptr, ["ptr", "op", "value"])
        if not _is_scalar(o["value"]) or o["value"] is None or isinstance(o["value"], float):
            issue(f"{ptr}/value", "expected scalar")
    elif op == "in":
        closed(v, ptr, ["ptr", "op", "values"])
        vals = o["values"]
        if not isinstance(vals, list):
            issue(f"{ptr}/values", "expected array")
        if not (1 <= len(vals) <= 16):
            issue(f"{ptr}/values", "1..16 members")
        t = None
        for i, x in enumerate(vals):
            if not _is_scalar(x) or x is None or isinstance(x, float):
                issue(f"{ptr}/values/{i}", "expected scalar")
            xt = _scalar_type(x)
            if t is None:
                t = xt
            elif xt != t:
                issue(f"{ptr}/values/{i}", "mixed types")
        enc = [jcs(x) for x in vals]
        for i in range(1, len(enc)):
            if enc[i - 1] == enc[i]:
                issue(f"{ptr}/values/{i}", "duplicate")
            if enc[i - 1] > enc[i]:
                issue(f"{ptr}/values", "not sorted")
    elif op == "int_range":
        closed(v, ptr, ["ptr", "op", "min", "max"])
        if not _is_int_pred(o["min"]):
            issue(f"{ptr}/min", "expected number")
        if not _is_int_pred(o["max"]):
            issue(f"{ptr}/max", "expected number")
        if o["min"] > o["max"]:
            issue(f"{ptr}/max", "min>max")
    elif op == "path_prefix":
        closed(v, ptr, ["ptr", "op", "value"])
        if not isinstance(o["value"], str):
            issue(f"{ptr}/value", "expected string")
    else:
        issue(f"{ptr}/op", "unknown operator")
    return o


def _is_int_pred(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_predicate(v, tool: str, ptr: str):
    p = valid_predicate_shape(v, ptr)
    dom = PREDICATE_DOMAIN[tool].get(p["ptr"])
    if dom is None:
        issue(f"{ptr}/ptr", "pointer outside domain")
    if p["op"] not in dom["ops"]:
        issue(f"{ptr}/op", "operator not allowed at pointer")
    if p["op"] in ("eq", "path_prefix"):
        if not dom["operand"](p["value"]):
            issue(f"{ptr}/value", "operand grammar")
    elif p["op"] == "in":
        for i, x in enumerate(p["values"]):
            if not dom["operand"](x):
                issue(f"{ptr}/values/{i}", "operand grammar")
    else:
        if not dom["operand"](p["min"]):
            issue(f"{ptr}/min", "operand grammar")
        if not dom["operand"](p["max"]):
            issue(f"{ptr}/max", "operand grammar")
    return p


def validate_scope(v, ptr: str):
    o = closed(v, ptr, ["tool", "where"])
    if not is_tool_name(o["tool"]):
        issue(f"{ptr}/tool", "unregistered tool")
    where = o["where"]
    if not isinstance(where, list):
        issue(f"{ptr}/where", "expected array")
    if len(where) > 8:
        issue(f"{ptr}/where", "too many predicates")
    seen_ptr = set()
    prev_key = ""
    preds = []
    for i, raw in enumerate(where):
        p = validate_predicate(raw, o["tool"], f"{ptr}/where/{i}")
        if p["ptr"] in seen_ptr:
            issue(f"{ptr}/where/{i}", "duplicate pointer")
        seen_ptr.add(p["ptr"])
        key = p["ptr"] + " " + jcs(raw).decode("utf-8")
        if i > 0 and prev_key >= key:
            issue(f"{ptr}/where/{i}", "where not sorted")
        prev_key = key
        preds.append(p)
    return {"tool": o["tool"], "where": preds}


def validate_scope_set(v, ptr: str):
    if not isinstance(v, list):
        issue(ptr, "expected array")
    if not (1 <= len(v) <= 8):
        issue(ptr, "1..8 scopes")
    scopes = [validate_scope(s, f"{ptr}/{i}") for i, s in enumerate(v)]
    enc = [jcs(s) for s in v]
    for i in range(1, len(enc)):
        if enc[i - 1] == enc[i]:
            issue(f"{ptr}/{i}", "duplicate scope")
        if enc[i - 1] > enc[i]:
            issue(ptr, "scopes not sorted")
    total = sum(len(e) for e in enc) + 2 + max(0, len(enc) - 1)
    if total > 4096:
        raise SchemaIssue(ptr, "scope set too large", "SCOPE_TOO_LARGE")
    return scopes


def validate_public_jwk(v, ptr: str):
    o = closed(v, ptr, ["kty", "crv", "x"])
    if o["kty"] != "OKP":
        issue(f"{ptr}/kty", "kty")
    if o["crv"] != "Ed25519":
        issue(f"{ptr}/crv", "crv")
    b64u32(o["x"], f"{ptr}/x")
    return o


def validate_herald_binding(v, ptr: str):
    o = closed(v, ptr, ["source", "card_id", "card_hash"])
    if not isinstance(o["source"], str) or not HERALD_SOURCE_RE.match(o["source"]):
        issue(f"{ptr}/source", "bad source")
    cid = o["card_id"]
    if not isinstance(cid, str) or not cid or len(cid.encode("utf-8")) > 128 or re.search(r"[\x00-\x1f\x7f-\x9f]", cid):
        issue(f"{ptr}/card_id", "bad card_id")
    hash_field(o["card_hash"], f"{ptr}/card_hash")
    return o


def validate_mint_request(v):
    check_version(v)
    o = closed(v, "", ["v", "op_id", "sub", "task_id", "caller_jwk", "scopes", "ttl_s", "herald"])
    id_field(o["op_id"], "lop", "/op_id")
    id_field(o["sub"], "lsu", "/sub")
    id_field(o["task_id"], "lts", "/task_id")
    validate_public_jwk(o["caller_jwk"], "/caller_jwk")
    scopes = validate_scope_set(o["scopes"], "/scopes")
    typ(o["ttl_s"], "number", "/ttl_s")
    if o["herald"] is not None:
        validate_herald_binding(o["herald"], "/herald")
    out = dict(o)
    out["scopes"] = scopes
    return out


def validate_args(v, tool: str, ptr: str):
    if tool == "documents.read":
        o = closed(v, ptr, ["workspace", "path"])
        if not is_workspace(o["workspace"]):
            issue(f"{ptr}/workspace", "workspace grammar")
        if not is_path(o["path"]):
            issue(f"{ptr}/path", "path grammar")
        return o
    o = closed(v, ptr, ["workspace", "record_id", "expected_version"])
    if not is_workspace(o["workspace"]):
        issue(f"{ptr}/workspace", "workspace grammar")
    if not isinstance(o["record_id"], str) or not IDENT_RE.match(o["record_id"]):
        issue(f"{ptr}/record_id", "record id grammar")
    typ(o["expected_version"], "number", f"{ptr}/expected_version")
    if o["expected_version"] < 0:
        issue(f"{ptr}/expected_version", "negative")
    return o


def validate_tool_call(v, ptr=""):
    check_version(v, ptr)
    o = closed(v, ptr, ["v", "call_id", "task_id", "tool", "args"])
    id_field(o["call_id"], "lcl", f"{ptr}/call_id")
    id_field(o["task_id"], "lts", f"{ptr}/task_id")
    if not is_tool_name(o["tool"]):
        issue(f"{ptr}/tool", "unregistered tool")
    validate_args(o["args"], o["tool"], f"{ptr}/args")
    return o


def validate_nonce_request(v):
    check_version(v)
    o = closed(v, "", ["v", "call"])
    return {"v": 1, "call": validate_tool_call(o["call"], "/call")}


def validate_result_request(v):
    check_version(v)
    o = closed(v, "", ["v", "task_id", "call_id"])
    id_field(o["task_id"], "lts", "/task_id")
    id_field(o["call_id"], "lcl", "/call_id")
    return o


TARGET_PREFIX = {"token": "ltk", "task": "lts", "subject": "lsu", "signing_key": "lky"}
REVOKE_REASONS = {"task_finished", "compromised", "operator_request"}


def validate_revoke_request(v):
    check_version(v)
    o = closed(v, "", ["v", "op_id", "target", "reason"])
    id_field(o["op_id"], "lop", "/op_id")
    t = o["target"]
    closed(t, "/target", ["kind", "id"])
    if t["kind"] not in TARGET_PREFIX:
        issue("/target/kind", "bad kind")
    id_field(t["id"], TARGET_PREFIX[t["kind"]], "/target/id")
    if o["reason"] not in REVOKE_REASONS:
        issue("/reason", "bad reason")
    return o


def validate_token_inspect_request(v):
    check_version(v)
    o = closed(v, "", ["v", "token_id"])
    id_field(o["token_id"], "ltk", "/token_id")
    return o


def validate_policy(v, ptr=""):
    check_version(v, ptr)
    o = closed(v, ptr, ["v", "revision", "hard_deny", "principals"])
    counter_field(o["revision"], f"{ptr}/revision")
    hd = o["hard_deny"]
    if not isinstance(hd, list):
        issue(f"{ptr}/hard_deny", "expected array")
    if len(hd) > 2:
        issue(f"{ptr}/hard_deny", "at most two")
    for i, t in enumerate(hd):
        if not is_tool_name(t):
            issue(f"{ptr}/hard_deny/{i}", "unregistered tool")
        if i > 0 and hd[i - 1] >= t:
            issue(f"{ptr}/hard_deny/{i}", "not sorted/duplicate")
    prins = o["principals"]
    if not isinstance(prins, list):
        issue(f"{ptr}/principals", "expected array")
    if len(prins) > 128:
        issue(f"{ptr}/principals", "at most 128")
    prev_sub = ""
    out = []
    for i, raw in enumerate(prins):
        p = closed(raw, f"{ptr}/principals/{i}", ["sub", "scopes", "max_ttl_s", "herald"])
        id_field(p["sub"], "lsu", f"{ptr}/principals/{i}/sub")
        if i > 0 and prev_sub >= p["sub"]:
            issue(f"{ptr}/principals/{i}/sub", "not sorted/duplicate")
        prev_sub = p["sub"]
        scopes = validate_scope_set(p["scopes"], f"{ptr}/principals/{i}/scopes")
        typ(p["max_ttl_s"], "number", f"{ptr}/principals/{i}/max_ttl_s")
        if p["herald"] not in ("disabled", "required"):
            issue(f"{ptr}/principals/{i}/herald", "bad herald mode")
        out.append({"sub": p["sub"], "scopes": scopes, "max_ttl_s": p["max_ttl_s"], "herald": p["herald"]})
    return {"v": 1, "revision": o["revision"], "hard_deny": hd, "principals": out}


def validate_policy_apply_request(v):
    check_version(v)
    o = closed(v, "", ["v", "op_id", "expected_revision", "policy"])
    id_field(o["op_id"], "lop", "/op_id")
    counter_field(o["expected_revision"], "/expected_revision")
    return {"v": 1, "op_id": o["op_id"], "expected_revision": o["expected_revision"],
            "policy": validate_policy(o["policy"], "/policy")}


def validate_rotate_request(v):
    check_version(v)
    o = closed(v, "", ["v", "op_id", "expected_kid", "new_kid", "new_jwk", "secret_ref"])
    id_field(o["op_id"], "lop", "/op_id")
    id_field(o["expected_kid"], "lky", "/expected_kid")
    id_field(o["new_kid"], "lky", "/new_kid")
    validate_public_jwk(o["new_jwk"], "/new_jwk")
    if not isinstance(o["secret_ref"], str) or not SECRET_REF_RE.match(o["secret_ref"]):
        issue("/secret_ref", "bad secret ref")
    return o


def validate_origin(v, ptr: str):
    if not isinstance(v, str):
        issue(ptr, "expected string")
    from urllib.parse import urlsplit
    try:
        u = urlsplit(v)
    except Exception:
        issue(ptr, "bad origin")
    if u.scheme not in ("https", "http") or not u.hostname:
        issue(ptr, "bad origin")
    if u.scheme != "https" and v != "http://127.0.0.1:8787":
        issue(ptr, "origin must be https")
    if u.username or u.password or u.query or u.fragment:
        issue(ptr, "origin decoration")
    if u.path not in ("", "/") or v.endswith("/"):
        issue(ptr, "origin path/slash")
    if u.hostname != u.hostname.lower():
        issue(ptr, "origin case")
    if (u.scheme == "https" and u.port == 443) or (u.scheme == "http" and u.port == 80):
        issue(ptr, "default port")
    return v


def validate_client_config(v):
    check_version(v)
    o = closed(v, "", ["v", "origin", "gateway_id", "tenant_id", "audit_trust"])
    validate_origin(o["origin"], "/origin")
    id_field(o["gateway_id"], "lsg", "/gateway_id")
    id_field(o["tenant_id"], "ltn", "/tenant_id")
    at = o["audit_trust"]
    if not isinstance(at, list):
        issue("/audit_trust", "expected array")
    prev = ""
    for i, k in enumerate(at):
        closed(k, f"/audit_trust/{i}", ["kid", "jwk"])
        id_field(k["kid"], "lky", f"/audit_trust/{i}/kid")
        validate_public_jwk(k["jwk"], f"/audit_trust/{i}/jwk")
        if i > 0 and prev >= k["kid"]:
            issue(f"/audit_trust/{i}/kid", "not sorted/duplicate")
        prev = k["kid"]
    return o
