"""lexscope/1 canonical JSON: strict parse + RFC 8785 JCS with the integer-only
number profile. Byte-identical output to the TypeScript implementation.

Strict profile: duplicate object keys rejected, only safe integers
(|n| <= 2**53-1), no negative zero, no fractions/exponents, no unpaired
surrogates, max depth 64, max document 64 KiB enforced by callers.
"""
from __future__ import annotations

import json

MAX_SAFE = 9007199254740991
MAX_DEPTH = 64


class StrictJsonError(ValueError):
    code = "JSON_INVALID"


class DupKey(StrictJsonError):
    code = "JSON_DUP_KEY"


class UnsafeNumber(StrictJsonError):
    code = "JSON_UNSAFE_NUMBER"


class DepthError(StrictJsonError):
    code = "JSON_DEPTH"


def _check(v, depth: int):
    if depth > MAX_DEPTH:
        raise DepthError("max depth exceeded")
    if isinstance(v, dict):
        for x in v.values():
            _check(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _check(x, depth + 1)
    elif isinstance(v, float):
        raise UnsafeNumber("non-integer number")
    elif isinstance(v, int) and not isinstance(v, bool):
        if abs(v) > MAX_SAFE:
            raise UnsafeNumber("unsafe integer")
    # unpaired-surrogate rejection happens in _combine_surrogates, which runs
    # after this check so valid escaped pairs survive to be combined.


def _pairs_hook(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise DupKey(f"duplicate key {k!r}")
        obj[k] = v
    return obj


def _int_hook(s: str) -> int:
    n = int(s)
    if abs(n) > MAX_SAFE:
        raise UnsafeNumber("unsafe integer")
    return n


def _const_hook(s: str):
    raise StrictJsonError(f"invalid literal {s}")  # NaN/Infinity


def parse_strict(raw: bytes | str):
    """Strict JSON parse: duplicate keys, unsafe ints, fractions, -0 rejected."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise StrictJsonError("invalid utf-8") from e
    else:
        text = raw
    # scan the token stream for forms Python's json would otherwise accept
    _scan_number_forms(text)
    try:
        v = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_int=_int_hook,
            parse_float=lambda s: (_ for _ in ()).throw(UnsafeNumber("fraction/exponent")),
            parse_constant=_const_hook,
        )
    except StrictJsonError:
        raise
    except (json.JSONDecodeError, RecursionError) as e:
        raise StrictJsonError("malformed JSON") from e
    _check(v, 0)
    return _combine_surrogates(v)


def _combine_surrogates(v):
    """Python's json leaves escaped surrogate pairs as two lone code units;
    combine valid pairs into the astral character (as JS does) and reject any
    remaining unpaired surrogate."""
    if isinstance(v, str):
        try:
            return v.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
        except UnicodeDecodeError:
            raise StrictJsonError("unpaired surrogate")
    if isinstance(v, list):
        return [_combine_surrogates(x) for x in v]
    if isinstance(v, dict):
        return {_combine_surrogates(k): _combine_surrogates(x) for k, x in v.items()}
    return v


def _scan_number_forms(text: str) -> None:
    """Reject -0 and float-looking numbers at the token level (Python's
    json.loads alone would produce -0.0 / floats we must distinguish)."""
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            i += 1
            continue
        if c == "-" or c.isdigit():
            j = i
            if text[j] == "-":
                j += 1
            while j < n and text[j].isdigit():
                j += 1
            if j < n and text[j] in ".eE":
                raise UnsafeNumber("fraction/exponent")
            if text[i : j] == "-0":
                raise UnsafeNumber("negative zero")
            i = j
            continue
        i += 1


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def _escape(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    # RFC 8785 sorts object keys by UTF-16 code units; utf-16-be bytes give the
    # same ordering including surrogate pairs.
    return k.encode("utf-16-be")


def jcs(v) -> bytes:
    if v is None:
        return b"null"
    if v is True:
        return b"true"
    if v is False:
        return b"false"
    if isinstance(v, str):
        return _escape(v).encode("utf-8")
    if isinstance(v, int) and not isinstance(v, bool):
        if abs(v) > MAX_SAFE:
            raise UnsafeNumber("outside lexscope integer JSON profile")
        return str(v).encode("ascii")
    if isinstance(v, list):
        return b"[" + b",".join(jcs(x) for x in v) + b"]"
    if isinstance(v, dict):
        parts = []
        for k in sorted(v.keys(), key=_utf16_key):
            parts.append(_escape(k).encode("utf-8") + b":" + jcs(v[k]))
        return b"{" + b",".join(parts) + b"}"
    raise UnsafeNumber("outside lexscope integer JSON profile")


def jcs_str(v) -> str:
    return jcs(v).decode("utf-8")
