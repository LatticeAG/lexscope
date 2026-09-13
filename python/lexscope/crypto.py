"""Cryptographic primitives: base64url, domain-separated SHA-256, Ed25519
sign/verify, compact JWS, and JWK thumbprints — interoperable with the TS core.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_der_private_key,
)

from .canon import jcs


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


_B64U_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64U_SET = frozenset(_B64U_ALPHABET)


# Returns None on any deviation from the unpadded-base64url profile:
# padding, nonalphabet characters, %4==1 length, or nonzero unused bits.
def b64u_decode(s: str) -> bytes | None:
    if not isinstance(s, str):
        return None
    n = len(s)
    if n == 0:
        return b""
    if n % 4 == 1:
        return None
    if any(c not in _B64U_SET for c in s):
        return None
    rem = n % 4
    last = _B64U_ALPHABET.index(s[-1])
    if rem == 2 and (last & 0x0F) != 0:
        return None
    if rem == 3 and (last & 0x03) != 0:
        return None
    return base64.urlsafe_b64decode(s + "=" * (-n % 4))


def b64u_json(s: str):
    d = b64u_decode(s)
    if d is None:
        return None
    try:
        return json.loads(d.decode("utf-8"))
    except Exception:
        return None


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def domain_hash(tag: str, value) -> str:
    """D(tag, v) = sha256(tag || 0x00 || J(v)) — hex."""
    h = hashlib.sha256()
    h.update(tag.encode("ascii"))
    h.update(b"\x00")
    h.update(jcs(value))
    return h.hexdigest()


# ---------- Ed25519 ----------


def gen_private() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_from_seed(seed: bytes) -> Ed25519PrivateKey:
    assert len(seed) == 32
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_jwk(priv: Ed25519PrivateKey) -> dict:
    x = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": b64u(x)}


def jwk_public(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an Ed25519 JWK")
    x = b64u_decode(jwk["x"])
    if x is None or len(x) != 32:
        raise ValueError("bad JWK x")
    return Ed25519PublicKey.from_public_bytes(x)


def jkt(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint: sha256 of the canonical member subset."""
    return b64u(sha256(jcs({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]})))


def sign(priv: Ed25519PrivateKey, msg: bytes) -> bytes:
    return priv.sign(msg)


def verify(jwk: dict, msg: bytes, sig: bytes) -> bool:
    try:
        jwk_public(jwk).verify(sig, msg)
        return True
    except Exception:
        return False


def jws(header: dict, payload: dict, priv: Ed25519PrivateKey) -> str:
    h = b64u(jcs(header))
    p = b64u(jcs(payload))
    sig = sign(priv, f"{h}.{p}".encode("ascii"))
    return f"{h}.{p}.{b64u(sig)}"


def parse_jws(tok: str):
    """Returns (header, payload, signing_input, signature) or None."""
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    h, p, s = parts
    header = b64u_json(h)
    payload = b64u_json(p)
    sig = b64u_decode(s)
    if header is None or payload is None or sig is None or len(sig) != 64:
        return None
    return header, payload, f"{h}.{p}".encode("ascii"), sig


def verify_jws(tok: str, jwk: dict, expect_typ: str | None = None):
    """Cryptographic verification only — no authorization semantics."""
    parsed = parse_jws(tok)
    if parsed is None:
        return None
    header, payload, msg, sig = parsed
    if header.get("alg") != "EdDSA":
        return None
    if expect_typ is not None and header.get("typ") != expect_typ:
        return None
    if not verify(jwk, msg, sig):
        return None
    return payload


# ---------- key file IO ----------


def load_pkcs8(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        data = f.read()
    if b"PRIVATE KEY" in data:
        k = load_pem_private_key(data, password=None)
    else:
        k = load_der_private_key(data, password=None)
    if not isinstance(k, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 key")
    return k


def pkcs8_pem(priv: Ed25519PrivateKey) -> bytes:
    return priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def load_public_jwk(path: str) -> dict:
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))
