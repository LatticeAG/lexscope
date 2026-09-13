// Error taxonomy per §7.2. Public errors never echo secrets, argument values,
// policy fragments, downstream messages, private URLs, or stack traces.

export type ErrorCode =
  | "TOKEN_TOO_LARGE" | "PROOF_TOO_LARGE" | "AUTH_TOO_LARGE" | "HEADERS_TOO_LARGE"
  | "BODY_TOO_LARGE" | "JSON_LIMIT" | "JSON_INVALID" | "SCHEMA_INVALID"
  | "CHAINING_FORBIDDEN" | "VERSION_UNSUPPORTED" | "METHOD_NOT_ALLOWED"
  | "MEDIA_UNSUPPORTED" | "SCOPE_TOO_LARGE" | "TTL_INVALID" | "AUTH_INVALID"
  | "CLOCK_WINDOW" | "CLOCK_UNSAFE" | "TOKEN_EXPIRED" | "TOKEN_REVOKED"
  | "KEY_REVOKED" | "SUBJECT_REVOKED" | "TASK_REVOKED" | "TASK_EXPIRED"
  | "TASK_BINDING_CONFLICT" | "CONTROL_FORBIDDEN" | "POLICY_STALE" | "SCOPE_DENIED"
  | "HARD_DENY" | "PROOF_REPLAY" | "NONCE_REQUIRED" | "NONCE_NOT_REQUIRED"
  | "NONCE_EXPIRED" | "NONCE_INVALID" | "NONCE_USED" | "CALL_CONFLICT"
  | "CALL_EXISTS" | "OP_CONFLICT" | "MINT_RESULT_EXPIRED" | "REVISION_CONFLICT"
  | "KEY_CONFLICT" | "KEY_UNAVAILABLE" | "RATE_LIMITED" | "CAPACITY"
  | "STATE_UNAVAILABLE" | "HERALD_UNAVAILABLE" | "HERALD_REVOKED"
  | "NOT_FOUND" | "RESULT_GONE" | "UPSTREAM_REJECTED" | "OUTPUT_REDACTED"
  | "OUTPUT_INVALID" | "OUTPUT_TOO_LARGE" | "OUTCOME_UNKNOWN" | "COUNTER_EXHAUSTED";

const STATUS: Record<ErrorCode, number> = {
  TOKEN_TOO_LARGE: 413, PROOF_TOO_LARGE: 413, AUTH_TOO_LARGE: 413, HEADERS_TOO_LARGE: 431,
  BODY_TOO_LARGE: 413, JSON_LIMIT: 400, JSON_INVALID: 400, SCHEMA_INVALID: 400,
  CHAINING_FORBIDDEN: 400, VERSION_UNSUPPORTED: 400, METHOD_NOT_ALLOWED: 405,
  MEDIA_UNSUPPORTED: 415, SCOPE_TOO_LARGE: 400, TTL_INVALID: 400, AUTH_INVALID: 401,
  CLOCK_WINDOW: 401, CLOCK_UNSAFE: 503, TOKEN_EXPIRED: 401, TOKEN_REVOKED: 403,
  KEY_REVOKED: 403, SUBJECT_REVOKED: 403, TASK_REVOKED: 403, TASK_EXPIRED: 403,
  TASK_BINDING_CONFLICT: 409, CONTROL_FORBIDDEN: 403, POLICY_STALE: 403, SCOPE_DENIED: 403,
  HARD_DENY: 403, PROOF_REPLAY: 401, NONCE_REQUIRED: 400, NONCE_NOT_REQUIRED: 400,
  NONCE_EXPIRED: 409, NONCE_INVALID: 409, NONCE_USED: 409, CALL_CONFLICT: 409,
  CALL_EXISTS: 409, OP_CONFLICT: 409, MINT_RESULT_EXPIRED: 409, REVISION_CONFLICT: 409,
  KEY_CONFLICT: 409, KEY_UNAVAILABLE: 503, RATE_LIMITED: 429, CAPACITY: 429,
  STATE_UNAVAILABLE: 503, HERALD_UNAVAILABLE: 503, HERALD_REVOKED: 403,
  NOT_FOUND: 404, RESULT_GONE: 410, UPSTREAM_REJECTED: 502, OUTPUT_REDACTED: 502,
  OUTPUT_INVALID: 502, OUTPUT_TOO_LARGE: 502, OUTCOME_UNKNOWN: 504, COUNTER_EXHAUSTED: 503,
};

const RETRYABLE = new Set<ErrorCode>([
  "CLOCK_UNSAFE", "KEY_UNAVAILABLE", "STATE_UNAVAILABLE", "HERALD_UNAVAILABLE",
  "RATE_LIMITED", "CAPACITY",
]);

export type Outcome = "NOT_DISPATCHED" | "UNKNOWN" | "FAILED";

export class LexError extends Error {
  code: ErrorCode;
  status: number;
  retryable: boolean;
  outcome: Outcome;
  callId: string | null;
  constructor(code: ErrorCode, opts: { outcome?: Outcome; callId?: string | null } = {}) {
    super(code);
    this.code = code;
    this.status = STATUS[code];
    this.retryable = RETRYABLE.has(code);
    this.outcome = opts.outcome ?? "NOT_DISPATCHED";
    this.callId = opts.callId ?? null;
  }
}

export function errorStatus(code: ErrorCode): number {
  return STATUS[code];
}

export function isRetryable(code: ErrorCode): boolean {
  return RETRYABLE.has(code);
}

// ErrorResponse body per §4. Retry-After handled by the HTTP layer:
// 202 -> 1, 429 -> 1, 503 -> 2.
export function errorBody(e: LexError, requestId: string): Record<string, unknown> {
  return {
    v: 1,
    error: { code: e.code, request_id: requestId, retryable: e.retryable },
    call_id: e.callId,
    outcome: e.outcome,
  };
}

export function retryAfter(status: number): number | null {
  if (status === 202 || status === 429) return 1;
  if (status === 503) return 2;
  return null;
}
