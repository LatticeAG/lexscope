"""Two-language parity suite: runs the shared conformance corpus and the
predicate/implication semantics against the Python package. Every vector here
also passes under the TypeScript implementation (tests/parity.test.ts).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import lexscope as lx  # noqa: E402
from lexscope import canon, crypto, predicates, schemas  # noqa: E402

VECTORS = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "conformance", "vectors.json")))
FX = VECTORS["fixtures"]


def seed_key(hexbyte: str):
    return crypto.private_from_seed(bytes.fromhex(hexbyte * 32))


# ---------- canonicalization corpus: 10,000 objects ----------

def test_canon_corpus_bytes_and_hashes():
    for i, row in enumerate(VECTORS["canon_objects"]):
        obj = canon.parse_strict(row["input"])
        out = canon.jcs(obj)
        assert out.decode("utf-8") == row["canonical"], f"canon mismatch at {i}"
        assert hashlib.sha256(out).hexdigest() == row["sha256"], f"hash mismatch at {i}"


def test_canon_rejects_profile_violations():
    for bad in ['{"a":1,"a":2}', "-0", "1.5", "1e3", "9007199254740993",
                '"\\ud800"', '"\\udfff"', "[1,2,,3]", "{]", '"\\ud800\\ud800"']:
        with pytest.raises(canon.StrictJsonError):
            canon.parse_strict(bad)


def test_canon_accepts_valid_surrogate_pair():
    assert canon.parse_strict('"\\ud83d\\ude00"') == "\U0001f600"
    assert canon.jcs(canon.parse_strict('"\\ud83d\\ude00"')) == '"\U0001f600"'.encode("utf-8")


def test_utf16_key_order():
    # UTF-16 code-unit order: "z" (U+007A) < non-BMP keys whose lead surrogate
    # is U+D83D; between astral keys the pair order applies (D83D DE00 < D83D DE01)
    obj = {"\U0001f601": 1, "\U0001f600": 2, "z": 3}
    assert canon.jcs_str(obj) == '{"z":3,"\U0001f600":2,"\U0001f601":1}'


# ---------- crypto parity ----------

def test_seed_keys_reproduce_jwks():
    for name, seed in FX["key_seeds"].items():
        pub = crypto.public_jwk(seed_key(seed))
        assert pub == FX["keys"][f"{name}_jwk"], name


def test_jkt_matches():
    assert crypto.jkt(FX["keys"]["caller_jwk"]) == FX["keys"]["caller_jkt"]


def test_token_signature_byte_identical():
    tok = crypto.jws(FX["token_header"], FX["claims"], seed_key(FX["key_seeds"]["token"]))
    assert tok == FX["token"]


def test_token_verifies_and_mutation_fails():
    claims = crypto.verify_jws(FX["token"], FX["keys"]["token_jwk"], "lexscope+jwt")
    assert claims is not None and claims["jti"] == FX["ids"]["token"]
    # one-bit signature mutation must reject
    bad = list(crypto.b64u_decode(FX["token"].split(".")[2]))
    bad[0] ^= 1
    parts = FX["token"].split(".")
    assert crypto.verify_jws(".".join(parts[:2] + [crypto.b64u(bytes(bad))]),
                             FX["keys"]["token_jwk"], "lexscope+jwt") is None
    # wrong key rejects
    assert crypto.verify_jws(FX["token"], FX["keys"]["audit_jwk"], "lexscope+jwt") is None


def test_audit_entries_verify():
    for e in FX["audit"]["entries"]:
        assert lx.audit.verify_entry(e, FX["keys"]["audit_jwk"])


# ---------- ids / errors ----------

def test_id_validation():
    for name, i in FX["ids"].items():
        prefix = i.split("_")[0]
        assert lx.is_id(i, prefix), i
    assert not lx.is_id("ltk_short", "ltk")
    assert not lx.is_id("lts_000000000000000000000", "ltk")
    assert lx.is_counter("0") and lx.is_counter("9223372036854775807")
    assert not lx.is_counter("9223372036854775808") and not lx.is_counter("01")


def test_error_taxonomy():
    assert lx.status("SCOPE_DENIED") == 403
    assert lx.status("RATE_LIMITED") == 429
    assert lx.status("OUTCOME_UNKNOWN") == 504
    assert lx.is_retryable("RATE_LIMITED") and lx.is_retryable("CLOCK_UNSAFE")
    assert not lx.is_retryable("SCOPE_DENIED") and not lx.is_retryable("OUTCOME_UNKNOWN")


# ---------- predicate semantics ----------

READ_CALL = FX["read_call"]
DELETE_CALL = FX["delete_call"]
SCOPES = FX["scopes"]


def test_scope_holds():
    assert predicates.scope_holds(SCOPES[0], READ_CALL["args"])
    assert not predicates.scope_holds(SCOPES[0], {"workspace": "other", "path": "reports/a.txt"})
    assert not predicates.scope_holds(SCOPES[0], {"workspace": "demo", "path": "secret/x"})
    assert predicates.scope_holds(SCOPES[1], DELETE_CALL["args"])
    assert predicates.args_permitted(SCOPES, "documents.read", READ_CALL["args"])
    # the records.delete grant binds only /workspace — a different workspace fails
    assert not predicates.args_permitted(
        SCOPES, "records.delete", {"workspace": "other", "record_id": "r1", "expected_version": 7})
    assert predicates.args_permitted(
        SCOPES, "records.delete", DELETE_CALL["args"])
    # a tool not granted at all permits nothing
    assert not predicates.args_permitted(
        [SCOPES[0]], "records.delete", DELETE_CALL["args"])


def test_typed_eq():
    assert predicates._typed_eq(1, True) is False  # JS: 1 !== true
    assert predicates._typed_eq(True, True) is True
    assert predicates._typed_eq("a", "a") is True
    assert predicates._typed_eq(None, None) is True  # JS: null === null
    assert predicates._typed_eq(None, 0) is False


def test_eval_predicate():
    assert predicates.eval_predicate({"ptr": "/path", "op": "path_prefix", "value": "reports"}, READ_CALL["args"])
    assert not predicates.eval_predicate({"ptr": "/path", "op": "path_prefix", "value": "report"}, READ_CALL["args"])
    assert predicates.eval_predicate({"ptr": "/expected_version", "op": "int_range", "min": 0, "max": 9}, DELETE_CALL["args"])
    assert not predicates.eval_predicate({"ptr": "/expected_version", "op": "int_range", "min": 8, "max": 9}, DELETE_CALL["args"])
    assert predicates.eval_predicate({"ptr": "/workspace", "op": "in", "values": ["demo", "x"]}, READ_CALL["args"])
    # missing/null/object argument never satisfies
    assert not predicates.eval_predicate({"ptr": "/nope", "op": "eq", "value": "x"}, READ_CALL["args"])


def test_implication_table():
    eq_demo = {"ptr": "/workspace", "op": "eq", "value": "demo"}
    in_dx = {"ptr": "/workspace", "op": "in", "values": ["demo", "x"]}
    in_d = {"ptr": "/workspace", "op": "in", "values": ["demo"]}
    rng = {"ptr": "/expected_version", "op": "int_range", "min": 0, "max": 9}
    rng_sub = {"ptr": "/expected_version", "op": "int_range", "min": 3, "max": 6}
    eq7 = {"ptr": "/expected_version", "op": "eq", "value": 7}
    assert predicates.implies(eq_demo, eq_demo)
    assert predicates.implies(eq_demo, in_dx) and not predicates.implies(eq_demo, in_d) is False
    assert predicates.implies(in_d, in_dx) and not predicates.implies(in_dx, in_d)
    assert predicates.implies(rng_sub, rng) and not predicates.implies(rng, rng_sub)
    assert predicates.implies(eq7, rng) and not predicates.implies(rng, eq7)
    # pointer mismatch never implies
    assert not predicates.implies(eq_demo, {"ptr": "/path", "op": "eq", "value": "demo"})


def test_scope_implies_and_mint():
    narrow = {"tool": "documents.read", "where": [
        {"ptr": "/path", "op": "path_prefix", "value": "reports/q1"},
        {"ptr": "/workspace", "op": "eq", "value": "demo"}]}
    assert predicates.scope_implies(narrow, SCOPES[0])
    broad = {"tool": "documents.read", "where": [{"ptr": "/workspace", "op": "eq", "value": "demo"}]}
    assert not predicates.scope_implies(broad, SCOPES[0])  # missing /path predicate
    ok, denied = predicates.check_mint_scopes(
        [narrow], FX["policy"]["principals"][0]["scopes"], [])
    assert ok and not denied
    ok, denied = predicates.check_mint_scopes(
        [{"tool": "records.delete", "where": []}], FX["policy"]["principals"][0]["scopes"],
        ["records.delete"])
    assert not ok and denied


# ---------- schemas ----------

def test_request_validation():
    assert schemas.validate_mint_request(FX["mint"])["task_id"] == FX["ids"]["task"]
    with pytest.raises(schemas.SchemaIssue) as ei:
        schemas.validate_mint_request({**FX["mint"], "v": 2})
    assert ei.value.code == "VERSION_UNSUPPORTED"
    with pytest.raises(schemas.SchemaIssue):
        schemas.validate_mint_request({**FX["mint"], "extra": 1})
    assert schemas.validate_tool_call(READ_CALL)["tool"] == "documents.read"
    with pytest.raises(schemas.SchemaIssue):
        schemas.validate_tool_call({**READ_CALL, "args": {"workspace": "demo", "path": "../x"}})


# ---------- token handle redaction ----------

def test_token_handle_redacted():
    h = lx.TokenHandle("secret-token-bytes", "ltk_0", 1, "h")
    assert str(h) == lx.REDACTED and repr(h) == lx.REDACTED
    assert json.dumps({"t": h.to_json()}) == '{"t": "[LexScope credential redacted]"}'
