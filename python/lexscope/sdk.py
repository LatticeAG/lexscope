"""LexScope client SDK — identical semantics to src/sdk.ts.

Tokens are opaque handles; every printed or serialized representation is the
fixed string "[LexScope credential redacted]". The client never remints,
broadens scopes, substitutes tools, suppresses hard denies, or retries a
terminal/unknown effect.
"""
from __future__ import annotations

import json
import time
import urllib.request
import urllib.error

from .canon import jcs, jcs_str
from .crypto import b64u, domain_hash, jkt, jws, public_jwk, sha256
from .errors import LexScopeError as _CoreError
from .ids import random_id
from .schemas import (
    SchemaIssue, TOOLS, validate_mint_request, validate_policy_apply_request,
    validate_result_request, validate_revoke_request, validate_rotate_request,
    validate_token_inspect_request, validate_tool_call,
)

REDACTED = "[LexScope credential redacted]"


class LexScopeError(Exception):
    def __init__(self, err, strip=None, status=0):
        code = err["code"]
        rid = err.get("request_id")
        super().__init__(f"{code} request_id={rid}" if rid else code)
        self.code = code
        self.request_id = rid
        self.outcome = err.get("outcome", "NOT_DISPATCHED")
        self.retryable = err.get("retryable") is True
        self.status = status
        if strip and strip in str(self):
            self.args = (str(self).replace(strip, REDACTED),)


class TransportError(LexScopeError):
    def __init__(self, detail: str = ""):
        super().__init__({"code": "TRANSPORT_UNAVAILABLE", "request_id": None,
                          "retryable": True, "outcome": "NOT_DISPATCHED"})
        self.args = ("TRANSPORT_UNAVAILABLE",)  # scrub transport detail


class TokenHandle:
    """Opaque credential. The secret is reachable only inside this module."""

    def __init__(self, secret: str, token_id: str, expires_at: int, scope_hash: str):
        self._secret = secret
        self.token_id = token_id
        self.expires_at = expires_at
        self.scope_hash = scope_hash
        self._open_nonces = {}  # call_hash -> OPEN nonce id

    def __repr__(self):
        return REDACTED

    def __str__(self):
        return REDACTED

    def __json__(self):
        return REDACTED

    def to_json(self):
        return REDACTED


CONTROL_TIMEOUT = 5000
CALL_TIMEOUT = 25000
MAX_RETRIES = 2


class LexScopeClient:
    def __init__(self, origin, tenant_id, caller_key=None, caller_jwk=None,
                 control_key=None, control_kid=None, transport=None, idgen=None, now=None):
        self._origin = origin
        self._tenant_id = tenant_id
        self._caller_key = caller_key
        self._caller_jwk = caller_jwk if caller_jwk is not None else (public_jwk(caller_key) if caller_key else None)
        self._caller_jkt = jkt(self._caller_jwk) if self._caller_jwk else None
        self._control_key = control_key
        self._control_kid = control_kid
        self._transport = transport or _http_transport
        self._idg = idgen or random_id
        self._now = now or (lambda: int(time.time()))

    # ---------- control methods (control key signs; never a tool surface) ----------

    def mint(self, request):
        req = self._check_control_schema(lambda: validate_mint_request(request))
        res = self._control_send("/mint", req, "POST")
        self._must_ok(res, 201)
        b = self._body_json(res)
        return TokenHandle(b["access_token"], b["token_id"], b["expires_at"], b["scope_hash"])

    def revoke(self, request):
        req = self._check_control_schema(lambda: validate_revoke_request(request))
        res = self._control_send("/revoke", req, "POST")
        self._must_ok(res, 200)
        return self._body_json(res)

    def inspect(self, request):
        req = self._check_control_schema(lambda: validate_token_inspect_request(request))
        res = self._control_send("/inspect", req, "POST")
        self._must_ok(res, 200)
        return self._body_json(res)

    def apply_policy(self, request):
        req = self._check_control_schema(lambda: validate_policy_apply_request(request))
        res = self._control_send("/policy", req, "POST")
        self._must_ok(res, 200)
        return self._body_json(res)

    def rotate(self, request):
        req = self._check_control_schema(lambda: validate_rotate_request(request))
        res = self._control_send("/rotate", req, "POST")
        self._must_ok(res, 200)
        return self._body_json(res)

    def audit(self, after: str, limit: int):
        res = self._control_send(f"/audit?after={after}&limit={limit}", None, "GET")
        self._must_ok(res, 200)
        return self._body_json(res)

    # ---------- agent methods ----------

    def nonce(self, token: TokenHandle, call):
        self._check_caller_schema(call)
        body = {"v": 1, "call": call}
        res = self._agent_send(token, "/nonces", body, None, CONTROL_TIMEOUT)
        if res["status"] not in (200, 201):
            self._throw_body(res)
        b = self._body_json(res)
        if self._now() < b["expires_at"]:
            token._open_nonces[b["call_hash"]] = b["nonce"]
        return b

    # call() allocates a destructive nonce unless the handle already owns an
    # OPEN nonce bound to the exact call hash. Terminal/unknown results are
    # never retried; uncertain transport loss falls back to /results on the
    # same call ID.
    def call(self, token: TokenHandle, call):
        self._check_caller_schema(call)
        call_hash = domain_hash("LEXSCOPE-CALL/1", call)
        destructive = TOOLS[call["tool"]]["destructive"]
        nonce_id = None
        if destructive:
            nonce_id = token._open_nonces.get(call_hash)
            if nonce_id is None:
                nonce_id = self.nonce(token, call)["nonce"]
        attempt = 0
        while attempt <= MAX_RETRIES:
            try:
                res = self._agent_send(token, "/calls", call, nonce_id, CALL_TIMEOUT)
            except TransportError:
                # uncertain completion: status lookup on the SAME call id;
                # NOT_FOUND permits resending that same ID, never a new one.
                try:
                    return self.result(token, {"v": 1, "task_id": call["task_id"], "call_id": call["call_id"]})
                except LexScopeError as e2:
                    if e2.code == "NOT_FOUND":
                        res2 = self._agent_send(token, "/calls", call, nonce_id, CALL_TIMEOUT)
                        if res2["status"] in (200, 202):
                            token._open_nonces.pop(call_hash, None)
                            return self._body_json(res2)
                        self._throw_body(res2)
                    raise
            if res["status"] in (200, 202):
                token._open_nonces.pop(call_hash, None)
                return self._body_json(res)
            code = self._err_code(res)
            # pre-admission retryable: 429/503 only, at most MAX_RETRIES times
            if res["status"] in (429, 503) and attempt < MAX_RETRIES and code != "OUTCOME_UNKNOWN":
                ra = int(res["headers"].get("retry-after", "1"))
                time.sleep(ra)
                attempt += 1
                continue
            self._throw_body(res)
        raise LexScopeError({"code": "STATE_UNAVAILABLE", "retryable": True})

    def result(self, token: TokenHandle, request):
        validate_result_request(request)
        res = self._agent_send(token, "/results", request, None, CONTROL_TIMEOUT)
        if res["status"] not in (200, 202):
            self._throw_body(res)
        return self._body_json(res)

    # ---------- internals ----------

    @property
    def _base(self):
        return f"{self._origin}/v1/tenants/{self._tenant_id}"

    def _proof_id(self):
        return self._idg("lpf", 32)

    def _check_caller_schema(self, call):
        try:
            validate_tool_call(call)
        except SchemaIssue as e:
            raise LexScopeError({"code": e.code, "request_id": None})

    def _check_control_schema(self, fn):
        try:
            return fn()
        except SchemaIssue as e:
            raise LexScopeError({"code": e.code, "request_id": None})

    def _control_send(self, suffix, body, method):
        if not self._control_key or not self._control_kid:
            raise LexScopeError({"code": "CONTROL_KEY_MISSING", "request_id": None})
        url = self._base + suffix
        canon = None if body is None else jcs_str(body)
        proof = {
            "v": 1, "tenant_id": self._tenant_id, "htm": method, "htu": url,
            "iat": self._now(), "jti": self._proof_id(),
            "bht": domain_hash("LEXSCOPE-BODY/1", None if body is None else body),
            "op_id": body.get("op_id") if isinstance(body, dict) else None,
        }
        t = jws({"alg": "EdDSA", "typ": "lexscope-control+jwt", "kid": self._control_kid}, proof, self._control_key)
        headers = {"lexscope-control": t}
        if body is not None:
            headers["content-type"] = "application/json"
        return self._send_raw({"method": method, "url": url, "headers": headers, "body": canon}, CONTROL_TIMEOUT)

    def _agent_send(self, token: TokenHandle, suffix, body, nonce, timeout_ms):
        if not self._caller_key or not self._caller_jwk or not self._caller_jkt:
            raise LexScopeError({"code": "CALLER_KEY_MISSING", "request_id": None})
        secret = token._secret
        url = self._base + suffix
        canon = jcs_str(body)
        call = body if suffix == "/calls" else (body["call"] if suffix == "/nonces" else None)
        proof = {
            "v": 1, "htm": "POST", "htu": url, "iat": self._now(), "jti": self._proof_id(),
            "ath": b64u(sha256(secret.encode("ascii"))),
            "bht": domain_hash("LEXSCOPE-BODY/1", body),
            "call_hash": domain_hash("LEXSCOPE-CALL/1", call) if call is not None else None,
            "nonce": nonce,
        }
        t = jws({"alg": "EdDSA", "typ": "dpop+jwt", "jwk": self._caller_jwk}, proof, self._caller_key)
        return self._send_raw({
            "method": "POST", "url": url,
            "headers": {"content-type": "application/json", "authorization": "DPoP " + secret, "dpop": t},
            "body": canon,
        }, timeout_ms)

    def _send_raw(self, req, timeout_ms):
        try:
            res = self._transport(req, timeout_ms)
        except LexScopeError:
            raise
        except Exception as e:
            raise TransportError(str(e))
        # redirects are forbidden: a 3xx is a nonretryable transport failure
        if 300 <= res["status"] < 400:
            raise LexScopeError({"code": "TRANSPORT_REDIRECT", "request_id": None, "retryable": False})
        return res

    @staticmethod
    def _body_json(res):
        return json.loads(bytes(res["body"]).decode("utf-8"))

    def _err_code(self, res):
        try:
            return self._body_json(res).get("error", {}).get("code")
        except Exception:
            return None

    def _must_ok(self, res, want):
        if res["status"] != want:
            self._throw_body(res)

    def _throw_body(self, res):
        outcome = None
        try:
            b = self._body_json(res)
            e = b.get("error") or {}
            err = {"code": e.get("code", "STATE_UNAVAILABLE"), "request_id": e.get("request_id"),
                   "retryable": e.get("retryable") is True}
            outcome = b.get("outcome")
        except Exception:
            err = {"code": "STATE_UNAVAILABLE", "request_id": None}
        ex = LexScopeError(err)
        if outcome:
            ex.outcome = outcome
        ex.status = res["status"]
        raise ex


def _http_transport(req, timeout_ms):
    """Default transport over urllib — returns {"status","headers","body"}."""
    r = urllib.request.Request(req["url"], method=req["method"])
    for k, v in req["headers"].items():
        r.add_header(k, v)
    data = req["body"].encode("utf-8") if req["body"] is not None else None
    try:
        with urllib.request.urlopen(r, data=data, timeout=timeout_ms / 1000) as resp:
            return {"status": resp.status, "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "body": resp.read()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": {k.lower(): v for k, v in e.headers.items()}, "body": e.read()}


class HostedControlPlane:
    def __init__(self):
        raise NotImplementedError(
            "the hosted LexScope control plane is a paid LatticeAG surface and is not part of the OSS "
            "core — see https://github.com/LatticeAG/lexscope/blob/main/README.md#hosted")
