"""Closed lexscope/1 error taxonomy — identical to src/core/errors.ts."""
from __future__ import annotations

STATUS = {
    "TOKEN_TOO_LARGE": 413, "PROOF_TOO_LARGE": 413, "AUTH_TOO_LARGE": 413,
    "HEADERS_TOO_LARGE": 431, "BODY_TOO_LARGE": 413, "JSON_LIMIT": 400,
    "JSON_INVALID": 400, "SCHEMA_INVALID": 400, "CHAINING_FORBIDDEN": 400,
    "VERSION_UNSUPPORTED": 400, "METHOD_NOT_ALLOWED": 405,
    "MEDIA_UNSUPPORTED": 415, "SCOPE_TOO_LARGE": 400, "TTL_INVALID": 400,
    "AUTH_INVALID": 401, "CLOCK_WINDOW": 401, "CLOCK_UNSAFE": 503,
    "TOKEN_EXPIRED": 401, "TOKEN_REVOKED": 403, "KEY_REVOKED": 403,
    "SUBJECT_REVOKED": 403, "TASK_REVOKED": 403, "TASK_EXPIRED": 403,
    "TASK_BINDING_CONFLICT": 409, "CONTROL_FORBIDDEN": 403,
    "POLICY_STALE": 403, "SCOPE_DENIED": 403, "HARD_DENY": 403,
    "PROOF_REPLAY": 401, "NONCE_REQUIRED": 400, "NONCE_NOT_REQUIRED": 400,
    "NONCE_EXPIRED": 409, "NONCE_INVALID": 409, "NONCE_USED": 409,
    "CALL_CONFLICT": 409, "CALL_EXISTS": 409, "OP_CONFLICT": 409,
    "MINT_RESULT_EXPIRED": 409, "REVISION_CONFLICT": 409, "KEY_CONFLICT": 409,
    "KEY_UNAVAILABLE": 503, "RATE_LIMITED": 429, "CAPACITY": 429,
    "STATE_UNAVAILABLE": 503, "HERALD_UNAVAILABLE": 503, "HERALD_REVOKED": 403,
    "NOT_FOUND": 404, "RESULT_GONE": 410, "UPSTREAM_REJECTED": 502,
    "OUTPUT_REDACTED": 502, "OUTPUT_INVALID": 502, "OUTPUT_TOO_LARGE": 502,
    "OUTCOME_UNKNOWN": 504, "COUNTER_EXHAUSTED": 503,
}

RETRYABLE = frozenset(
    ["CLOCK_UNSAFE", "KEY_UNAVAILABLE", "STATE_UNAVAILABLE", "HERALD_UNAVAILABLE",
     "RATE_LIMITED", "CAPACITY"]
)

OUTCOMES = frozenset(["NOT_DISPATCHED", "UNKNOWN", "FAILED"])


def status(code: str) -> int:
    return STATUS.get(code, 500)


def is_retryable(code: str) -> bool:
    return code in RETRYABLE


class LexScopeError(Exception):
    """Public protocol error: stable code, never upstream bytes or secrets."""

    def __init__(self, code: str, request_id: str | None = None,
                 outcome: str = "NOT_DISPATCHED", http_status: int = 0):
        super().__init__(f"{code}" + (f" request_id={request_id}" if request_id else ""))
        self.code = code
        self.request_id = request_id
        self.outcome = outcome
        self.status = http_status
        self.retryable = is_retryable(code)
