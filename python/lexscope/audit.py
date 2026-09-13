"""Offline audit verification — identical semantics to src/core/audit.ts.

Verifies a complete AuditPage against an AuditTrust: hash chain, entry
signatures, sequence continuity, signed head, key-rotation admission, and
pinned-head completeness.
"""
from __future__ import annotations

from .canon import jcs
from .crypto import b64u, b64u_decode, domain_hash, sign, verify
from .ids import is_counter, is_hash, is_id

GENESIS_PREV = "0" * 64

AUDIT_FAIL = (
    "AUDIT_HASH_MISMATCH", "AUDIT_INCOMPLETE", "AUDIT_SIGNATURE_INVALID",
    "AUDIT_SEQUENCE_INVALID", "AUDIT_TRUST_INVALID",
)


def entry_hash(body: dict) -> str:
    return domain_hash("LEXSCOPE-AUDIT/1", body)


def _entry_sign_msg(digest_hex: str) -> bytes:
    return b"LEXSCOPE-AUDIT-SIGN/1" + b"\x00" + bytes.fromhex(digest_hex)


def sign_entry(body: dict, priv) -> dict:
    digest = entry_hash(body)
    return {"body": body, "hash": digest, "signature": b64u(sign(priv, _entry_sign_msg(digest)))}


def verify_entry(entry: dict, jwk: dict) -> bool:
    sig = b64u_decode(entry["signature"])
    if sig is None or len(sig) != 64:
        return False
    digest = entry_hash(entry["body"])
    if digest != entry["hash"]:
        return False
    return verify(jwk, _entry_sign_msg(digest), sig)


def sign_head(tenant_id: str, seq: str, h: str, signer_kid: str, priv) -> dict:
    msg = b"LEXSCOPE-HEAD/1" + b"\x00" + jcs(
        {"tenant_id": tenant_id, "seq": seq, "hash": h, "signer_kid": signer_kid}
    )
    return {"seq": seq, "hash": h, "signer_kid": signer_kid, "signature": b64u(sign(priv, msg))}


def verify_head(head: dict, tenant_id: str, jwk: dict) -> bool:
    sig = b64u_decode(head["signature"])
    if sig is None or len(sig) != 64:
        return False
    msg = b"LEXSCOPE-HEAD/1" + b"\x00" + jcs(
        {"tenant_id": tenant_id, "seq": head["seq"], "hash": head["hash"], "signer_kid": head["signer_kid"]}
    )
    return verify(jwk, msg, sig)


def verify_audit(page: dict, trust: dict) -> dict:
    """Returns {"valid": True, "entries": n, "head": hash} or
    {"valid": False, "code": AUDIT_*, "seq": str}."""
    def fail(code, seq):
        return {"valid": False, "code": code, "seq": seq}

    entries = page["entries"]
    key_of = {k["kid"]: k["jwk"] for k in trust["keys"]}

    prev = GENESIS_PREV
    expect_seq = 1
    # offline verification begins with AuditTrust.initial_kid and may advance
    # only at key.rotated events whose new key is in trust.keys
    current_kid = trust["initial_kid"]
    if trust.get("checkpoint") is not None:
        cp = trust["checkpoint"]
        prev = cp["hash"]
        expect_seq = int(cp["body"]["seq"]) + 1
        current_kid = cp["body"]["signer_kid"]

    last = None
    for e in entries:
        body = e["body"]
        if int(body["seq"]) != expect_seq:
            return fail("AUDIT_SEQUENCE_INVALID", body["seq"])
        if body["prev"] != prev:
            return fail("AUDIT_HASH_MISMATCH", body["seq"])
        if body["signer_kid"] != current_kid:
            return fail("AUDIT_TRUST_INVALID", body["seq"])
        if entry_hash(body) != e["hash"]:
            return fail("AUDIT_HASH_MISMATCH", body["seq"])
        jwk = key_of.get(current_kid)
        if jwk is None:
            return fail("AUDIT_TRUST_INVALID", body["seq"])
        if not verify_entry(e, jwk):
            return fail("AUDIT_SIGNATURE_INVALID", body["seq"])
        # signer rotation admission
        if body["kind"] == "key.rotated" and body.get("key_id") in key_of:
            current_kid = body["key_id"]
        prev = e["hash"]
        expect_seq += 1
        last = e

    head = page["head"]
    head_jwk = key_of.get(head["signer_kid"])
    if head_jwk is None:
        return fail("AUDIT_TRUST_INVALID", head["seq"])
    if not verify_head(head, trust["tenant_id"], head_jwk):
        return fail("AUDIT_SIGNATURE_INVALID", head["seq"])
    if last is None:
        cp = trust.get("checkpoint")
        if cp is None or cp["hash"] != head["hash"] or cp["body"]["seq"] != head["seq"]:
            return fail("AUDIT_INCOMPLETE", head["seq"])
    else:
        if head["seq"] != last["body"]["seq"] or head["hash"] != last["hash"]:
            return fail("AUDIT_INCOMPLETE", str(int(last["body"]["seq"]) + 1))
    pinned = trust.get("pinned_head")
    if pinned is not None:
        if (pinned["seq"] != head["seq"] or pinned["hash"] != head["hash"]
                or pinned["signer_kid"] != head["signer_kid"]):
            return fail("AUDIT_INCOMPLETE", head["seq"])
    return {"valid": True, "entries": len(entries), "head": head["hash"]}


def valid_audit_page(page) -> bool:
    if not isinstance(page, dict):
        return False
    if page.get("v") != 1 or not isinstance(page.get("entries"), list):
        return False
    if not is_counter(page.get("next_after")) or not isinstance(page.get("has_more"), bool):
        return False
    h = page.get("head")
    if not (isinstance(h, dict) and is_counter(h.get("seq")) and is_hash(h.get("hash"))
            and is_id(h.get("signer_kid"), "lky") and isinstance(h.get("signature"), str)):
        return False
    for e in page["entries"]:
        if not (isinstance(e, dict) and isinstance(e.get("body"), dict)
                and is_hash(e.get("hash")) and isinstance(e.get("signature"), str)):
            return False
    return True


def valid_audit_trust(t) -> bool:
    if not isinstance(t, dict):
        return False
    if t.get("v") != 1 or not is_id(t.get("tenant_id"), "ltn") or not is_id(t.get("initial_kid"), "lky"):
        return False
    keys = t.get("keys")
    if not isinstance(keys, list):
        return False
    prev = ""
    for k in keys:
        if not (isinstance(k, dict) and is_id(k.get("kid"), "lky")):
            return False
        j = k.get("jwk")
        if not (isinstance(j, dict) and j.get("kty") == "OKP" and j.get("crv") == "Ed25519"
                and isinstance(j.get("x"), str) and len(b64u_decode(j["x"]) or b"") == 32):
            return False
        if prev and prev >= k["kid"]:
            return False
        prev = k["kid"]
    # pinned_head / checkpoint must be present (null or a valid member);
    # absent members are rejected like the TS parser's `!== null` check
    if "pinned_head" not in t:
        return False
    h = t["pinned_head"]
    if h is not None and not (
        isinstance(h, dict) and is_counter(h.get("seq")) and is_hash(h.get("hash"))
        and is_id(h.get("signer_kid"), "lky") and isinstance(h.get("signature"), str)
    ):
        return False
    if "checkpoint" not in t:
        return False
    cp = t["checkpoint"]
    if cp is not None and not (
        isinstance(cp, dict) and isinstance(cp.get("body"), dict)
        and is_hash(cp.get("hash")) and isinstance(cp.get("signature"), str)
    ):
        return False
    return True
