"""Identifier and scalar validators shared with the TS core."""
from __future__ import annotations

import re

ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")
IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
COUNTER_RE = re.compile(r"^(0|[1-9][0-9]*)$")

# prefix -> fixed suffix length
ID_SIZES = {
    "ltn": 21, "lsg": 21, "lsu": 21, "lts": 21, "ltk": 21, "lcl": 21,
    "lop": 21, "lrq": 21, "lky": 21, "lev": 21, "lnn": 32, "lpf": 32,
}


def is_id(v, prefix: str) -> bool:
    if not isinstance(v, str):
        return False
    want = f"{prefix}_"
    if not v.startswith(want):
        return False
    rest = v[len(want):]
    size = ID_SIZES.get(prefix)
    if size is not None and len(rest) != size:
        return False
    return bool(rest) and bool(ID_RE.match(rest))


def is_counter(v) -> bool:
    return isinstance(v, str) and bool(COUNTER_RE.match(v)) and int(v) <= 9223372036854775807


def is_hash(v) -> bool:
    return isinstance(v, str) and bool(re.fullmatch(r"[0-9a-f]{64}", v))


def is_seconds(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 4102444800


def random_id(prefix: str, size: int = 21) -> str:
    import secrets
    return f"{prefix}_{secrets.token_urlsafe(size)[:size]}"
