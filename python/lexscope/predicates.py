"""Predicate evaluation and the fixed §4.2 implication table — identical
semantics to src/core/predicates.ts. No regex, glob, eval, or theorem proving.
"""
from __future__ import annotations


def _typed_eq(a, b) -> bool:
    # JS `typeof a === typeof b && a === b`: bool is its own type here.
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    if type(a) is not type(b):
        return False
    return a == b


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def path_matches(prefix: str, s: str) -> bool:
    """matches prefix itself or anything strictly below it"""
    return s == prefix or s.startswith(prefix + "/")


def eval_predicate(p: dict, args) -> bool:
    if not isinstance(args, dict):
        return False
    field = p["ptr"][1:]
    if field not in args:
        return False
    v = args[field]
    if v is None or isinstance(v, (dict, list)):
        return False
    op = p["op"]
    if op == "eq":
        return _typed_eq(v, p["value"])
    if op == "in":
        return any(_typed_eq(v, x) for x in p["values"])
    if op == "int_range":
        return _is_int(v) and p["min"] <= v <= p["max"]
    if op == "path_prefix":
        return isinstance(v, str) and path_matches(p["value"], v)
    return False


def scope_holds(scope: dict, args) -> bool:
    return all(eval_predicate(p, args) for p in scope["where"])


def args_permitted(scopes, tool: str, args) -> bool:
    return any(s["tool"] == tool and scope_holds(s, args) for s in scopes)


def _is_singleton_in(p: dict) -> bool:
    return p["op"] == "in" and len(p["values"]) == 1


def implies(q: dict, p: dict) -> bool:
    """Does request predicate q imply grant predicate p (same pointer)?"""
    if q["ptr"] != p["ptr"]:
        return False
    po = p["op"]
    if po == "eq":
        if q["op"] == "eq":
            return _typed_eq(q["value"], p["value"])
        if _is_singleton_in(q):
            return _typed_eq(q["values"][0], p["value"])
        return False
    if po == "in":
        if q["op"] == "eq":
            return any(_typed_eq(x, q["value"]) for x in p["values"])
        if q["op"] == "in":
            return all(any(_typed_eq(a, b) for a in p["values"]) for b in q["values"])
        return False
    if po == "int_range":
        if q["op"] == "eq":
            return _is_int(q["value"]) and p["min"] <= q["value"] <= p["max"]
        if q["op"] == "in":
            return all(_is_int(b) and p["min"] <= b <= p["max"] for b in q["values"])
        if q["op"] == "int_range":
            return q["min"] >= p["min"] and q["max"] <= p["max"]
        return False
    if po == "path_prefix":
        if q["op"] == "eq":
            return isinstance(q["value"], str) and path_matches(p["value"], q["value"])
        if q["op"] == "in":
            return all(isinstance(b, str) and path_matches(p["value"], b) for b in q["values"])
        if q["op"] == "path_prefix":
            return path_matches(p["value"], q["value"])
        return False
    return False


def scope_implies(request: dict, grant: dict) -> bool:
    """Request scope ⊆ grant scope: every grant predicate must be implied by
    some same-pointer request predicate."""
    if request["tool"] != grant["tool"]:
        return False
    return all(any(implies(q, p) for q in request["where"]) for p in grant["where"])


def check_mint_scopes(request, grants, hard_deny) -> tuple[bool, bool]:
    """Returns (ok, hard_denied)."""
    for s in request:
        if s["tool"] in hard_deny:
            return False, True
        if not any(scope_implies(s, g) for g in grants):
            return False, False
    return True, False
