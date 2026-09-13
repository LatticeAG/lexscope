"""`python -m lexscope` CLI — identical grammar, exit codes, and secret-FD
rules to the `lexscope` binary (§8.4). Secret handling: private keys come from
file paths only; token bytes travel over inherited FDs (--token-fd reads,
--out-fd writes); secrets are never command-line values, env values, or
written to FD 1/2.
"""
from __future__ import annotations

import json
import os
import stat
import sys

from .audit import valid_audit_page, valid_audit_trust, verify_audit
from .canon import jcs_str, parse_strict
from .crypto import b64u_json, gen_private, pkcs8_pem, public_jwk, load_pkcs8
from .mcp import McpServer
from .schemas import SchemaIssue, validate_client_config
from .sdk import LexScopeClient, LexScopeError, TokenHandle

VERSION = "1.0.0"

# ---------- exit-code mapping (§8.4) ----------

EXIT_BY_CODE = {
    # 3 — authentication / cryptographic failure
    "AUTH_INVALID": 3, "AUTH_MALFORMED": 3, "AUTH_HEADER_DUP": 3, "AUTH_SCHEME": 3,
    "TOKEN_TYPE": 3, "TOKEN_MALFORMED": 3, "TOKEN_SIZE": 3, "TOKEN_EXPIRED": 3,
    "SIGNATURE_INVALID": 3, "ALG_FORBIDDEN": 3, "CHAINING_FORBIDDEN": 3, "CNF_MISMATCH": 3,
    "PROOF_INVALID": 3, "PROOF_MALFORMED": 3, "PROOF_REPLAY": 3, "PROOF_SIZE": 3,
    "CLOCK_WINDOW": 3, "METHOD_MISMATCH": 3, "PATH_MISMATCH": 3, "BODY_MISMATCH": 3,
    "CALL_HASH_MISMATCH": 3, "ATH_MISMATCH": 3, "JKT_MISMATCH": 3, "SUBJECT_UNKNOWN": 3,
    "BINDING_MISMATCH": 3,
    # 4 — authorization denial
    "TOKEN_REVOKED": 4, "KEY_REVOKED": 4, "SUBJECT_REVOKED": 4, "TASK_REVOKED": 4,
    "TASK_EXPIRED": 4, "CONTROL_FORBIDDEN": 4, "POLICY_STALE": 4, "SCOPE_DENIED": 4,
    "HARD_DENY": 4, "HERALD_REVOKED": 4,
    # 5 — conflict / missing / gone
    "TASK_BINDING_CONFLICT": 5, "NONCE_REQUIRED": 5, "NONCE_INVALID": 5,
    "NONCE_CONSUMED": 5, "NONCE_EXPIRED": 5, "NONCE_MISMATCH": 5, "NONCE_SCOPE": 5,
    "NONCE_OVERFLOW": 5, "CALL_ID_CONFLICT": 5, "OP_CONFLICT": 5,
    "MINT_RESULT_EXPIRED": 5, "REVISION_CONFLICT": 5, "KEY_CONFLICT": 5,
    "NOT_FOUND": 5, "RESULT_GONE": 5, "RESULT_UNKNOWN": 5,
    # 6 — retryable infrastructure
    "CLOCK_UNSAFE": 6, "KEY_UNAVAILABLE": 6, "STATE_UNAVAILABLE": 6,
    "HERALD_UNAVAILABLE": 6, "HERALD_STALE": 6, "RATE_LIMITED": 6, "CAPACITY": 6,
    "COUNTER_EXHAUSTED": 6, "TRANSPORT_UNAVAILABLE": 6,
    # 7 — unknown outcome / blocked output
    "OUTCOME_UNKNOWN": 7, "OUTPUT_REDACTED": 7, "OUTPUT_INVALID": 7,
    "OUTPUT_TOO_LARGE": 7, "TRANSPORT_REDIRECT": 7,
    # 9 — definite upstream rejection
    "UPSTREAM_REJECTED": 9,
}

SCHEMA_CODES = {
    "SCHEMA_INVALID", "VERSION_UNSUPPORTED", "JSON_INVALID", "JSON_DUP_KEY",
    "JSON_UNSAFE_NUMBER", "JSON_DEPTH", "HEADER_TOO_LARGE", "BODY_TOO_LARGE",
    "MEDIA_TYPE", "METHOD_INVALID", "PATH_INVALID", "TENANT_INVALID",
    "QUERY_INVALID", "KEY_INSECURE", "HERALD_INVALID", "CONTROL_KEY_MISSING",
    "CALLER_KEY_MISSING", "ADAPTER_BYPASS", "DESTRUCTIVE_CLASS",
}


class CliUsage(Exception):
    pass


def exit_code(e) -> int:
    if isinstance(e, CliUsage):
        return 2
    if isinstance(e, LexScopeError):
        if e.status == 202:
            return 10
        m = EXIT_BY_CODE.get(e.code)
        if m is not None:
            return m
        if e.code in SCHEMA_CODES:
            return 2
        return 6 if e.retryable else 5
    return 2


# ---------- arg parsing ----------

GLOBAL_FLAGS = {"--config", "--json", "--timeout-ms", "--help", "--version"}


class ParsedArgs:
    def __init__(self, cmd, flags):
        self.cmd = cmd
        self.flags = flags
        self.json = flags.get("--json") is True


def parse_args(argv):
    flags = {}
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if not a.startswith("--"):
            cmd.append(a)
            i += 1
            continue
        eq = a.find("=")
        name = a if eq == -1 else a[:eq]
        if name in flags:
            raise CliUsage(f"duplicate flag {name}")
        if eq != -1:
            flags[name] = a[eq + 1:]
            i += 1
            continue
        if name in ("--json", "--help", "--version"):
            flags[name] = True
            i += 1
            continue
        if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
            raise CliUsage(f"flag {name} requires a value")
        flags[name] = argv[i + 1]
        i += 2
    return ParsedArgs(cmd, flags)


def need(p: ParsedArgs, name: str) -> str:
    v = p.flags.get(name)
    if v is None or v is True:
        raise CliUsage(f"missing required flag {name}")
    return v


def no_leftover(p: ParsedArgs, allowed):
    for k in p.flags:
        if k not in GLOBAL_FLAGS and k not in allowed:
            raise CliUsage(f"unknown flag {k}")


# ---------- config / keys / secret FDs ----------

def load_client_config(path):
    try:
        raw = open(path, "rb").read()
    except OSError:
        raise CliUsage(f"cannot read config {path}")
    try:
        return validate_client_config(parse_strict(raw))
    except Exception as e:
        raise CliUsage(f"invalid client config: {e}")


def load_private_key(path):
    try:
        pem = open(path, "rb").read()
    except OSError:
        raise CliUsage(f"cannot read key {path}")
    try:
        return load_pkcs8(path)
    except Exception:
        raise CliUsage(f"key {path} is not a valid PKCS8 PEM")


# Secret FDs must be inherited pipes or owned mode-0600 regular files, never
# terminal devices; token output to FD 1 or 2 is refused outright.
def secret_fd(fd_str: str, mode: str) -> int:
    try:
        n = int(fd_str)
    except ValueError:
        raise CliUsage(f"invalid fd {fd_str}")
    if n < 0:
        raise CliUsage(f"invalid fd {fd_str}")
    if mode == "write" and n in (1, 2):
        raise CliUsage("token output to FD 1 or 2 is forbidden")
    try:
        st = os.fstat(n)
    except OSError:
        raise CliUsage(f"fd {n} is not open")
    m = st.st_mode
    if stat.S_ISCHR(m) or stat.S_ISDIR(m) or stat.S_ISSOCK(m):
        raise CliUsage(f"fd {n} is not a safe secret channel")
    if stat.S_ISREG(m) and (m & 0o777) != 0o600:
        raise CliUsage(f"fd {n} file must be mode 0600")
    return n


def read_token_fd(fd_str: str) -> str:
    n = secret_fd(fd_str, "read")
    tok = os.read(n, 65536).decode("utf-8").strip()
    if not tok:
        raise CliUsage("empty token fd")
    return tok


def write_token_fd(fd_str: str, token: str):
    n = secret_fd(fd_str, "write")
    os.write(n, (token + "\n").encode("utf-8"))


def load_request(path: str):
    if path == "-":
        raw = sys.stdin.buffer.read()
    else:
        try:
            raw = open(path, "rb").read()
        except OSError:
            raise CliUsage(f"cannot read request {path}")
    try:
        return parse_strict(raw)
    except Exception as e:
        raise CliUsage(f"request is not strict JSON: {e}")


def emit(p: ParsedArgs, value):
    sys.stdout.write((jcs_str(value) if p.json else json.dumps(value, indent=2)) + "\n")


def usage() -> str:
    return f"""lexscope {VERSION}
usage: lexscope [--config PATH] [--json] [--timeout-ms N] <command> [flags]

commands:
  config check --file PATH
  keygen --out PATH [--public-out PATH]
  mint --request PATH --control-key PATH --control-kid ID --caller-key PATH --out-fd N
  call --request PATH --token-fd N --caller-key PATH
  result --request PATH --token-fd N --caller-key PATH
  revoke --request PATH --control-key PATH --control-kid ID
  inspect --request PATH --control-key PATH --control-kid ID
  policy apply --request PATH --control-key PATH --control-kid ID
  keys rotate --request PATH --control-key PATH --control-kid ID
  audit export --control-key PATH --control-kid ID --out PATH [--after N] [--limit N]
  audit verify --in PATH --trust PATH
  mcp serve --token-fd N --caller-key PATH --task-id ID
"""


# Token claims are decoded locally for metadata only — the server is the sole
# verifier; a client-side parse never authenticates anything.
def token_claims(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise CliUsage("malformed token on fd")
    claims = b64u_json(parts[1])
    if not isinstance(claims, dict):
        raise CliUsage("malformed token on fd")
    return claims


def handle_from_token(token: str) -> TokenHandle:
    c = token_claims(token)
    return TokenHandle(token, str(c.get("jti", "")), int(c.get("exp", 0)), str(c.get("scope_hash", "")))


def _exclusive_write(path: str, data: bytes, mode: int):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def main(argv) -> int:
    try:
        p = parse_args(argv)
    except CliUsage as e:
        sys.stderr.write(f"{e}\n")
        return 2
    if p.flags.get("--help") is True and not p.cmd:
        sys.stdout.write(usage())
        return 0
    if p.flags.get("--version") is True and not p.cmd:
        sys.stdout.write(VERSION + "\n")
        return 0
    if not p.cmd:
        sys.stderr.write(usage())
        return 2

    tflag = p.flags.get("--timeout-ms")
    if tflag is not None and tflag is not True:
        try:
            timeout_ms = int(tflag)
        except ValueError:
            timeout_ms = -1
        if timeout_ms < 100 or timeout_ms > 30000:
            sys.stderr.write("--timeout-ms must be an integer in [100, 30000]\n")
            return 2
    elif tflag is True:
        sys.stderr.write("--timeout-ms requires a value\n")
        return 2

    try:
        cfg_path = p.flags.get("--config") if isinstance(p.flags.get("--config"), str) else "./lexscope.json"
        cmd = " ".join(p.cmd)

        if cmd == "config check":
            no_leftover(p, ["--file"])
            cfg = load_client_config(need(p, "--file"))
            emit(p, {"protocol": "lexscope/1", "tenant_id": cfg["tenant_id"], "valid": True})
            return 0

        if cmd == "keygen":
            no_leftover(p, ["--out", "--public-out"])
            out = need(p, "--out")
            pub = p.flags.get("--public-out")
            priv = gen_private()
            _exclusive_write(out, pkcs8_pem(priv), 0o600)
            jwk_json = jcs_str(public_jwk(priv)) + "\n"
            if isinstance(pub, str):
                _exclusive_write(pub, jwk_json.encode("utf-8"), 0o644)
                emit(p, {"created": out, "public_out": pub})
            else:
                sys.stdout.write(jwk_json)
            return 0

        if cmd == "mint":
            no_leftover(p, ["--request", "--control-key", "--control-kid", "--caller-key", "--out-fd"])
            cfg = load_client_config(cfg_path)
            req = load_request(need(p, "--request"))
            control_key = load_private_key(need(p, "--control-key"))
            control_kid = need(p, "--control-kid")
            caller_key = load_private_key(need(p, "--caller-key"))
            out_fd = need(p, "--out-fd")
            # The caller public key derived from --caller-key must equal the
            # mint request's caller_jwk — mismatch fails before any HTTP request.
            want = public_jwk(caller_key)
            got = req.get("caller_jwk") if isinstance(req, dict) else None
            if not isinstance(got, dict) or got.get("x") != want["x"]:
                raise CliUsage("--caller-key does not match request caller_jwk")
            client = LexScopeClient(origin=cfg["origin"], tenant_id=cfg["tenant_id"],
                                    control_key=control_key, control_kid=control_kid, caller_key=caller_key)
            handle = client.mint(req)
            write_token_fd(out_fd, handle._secret)
            emit(p, {"expires_at": handle.expires_at, "scope_hash": handle.scope_hash, "token_id": handle.token_id})
            return 0

        if cmd in ("call", "result"):
            no_leftover(p, ["--request", "--token-fd", "--caller-key"])
            cfg = load_client_config(cfg_path)
            req = load_request(need(p, "--request"))
            token = read_token_fd(need(p, "--token-fd"))
            caller_key = load_private_key(need(p, "--caller-key"))
            client = LexScopeClient(origin=cfg["origin"], tenant_id=cfg["tenant_id"], caller_key=caller_key)
            handle = handle_from_token(token)
            res = client.call(handle, req) if cmd == "call" else client.result(handle, req)
            emit(p, res)
            return 0

        if cmd in ("revoke", "inspect", "policy apply", "keys rotate"):
            no_leftover(p, ["--request", "--control-key", "--control-kid"])
            cfg = load_client_config(cfg_path)
            req = load_request(need(p, "--request"))
            control_key = load_private_key(need(p, "--control-key"))
            control_kid = need(p, "--control-kid")
            client = LexScopeClient(origin=cfg["origin"], tenant_id=cfg["tenant_id"],
                                    control_key=control_key, control_kid=control_kid)
            res = (client.revoke(req) if cmd == "revoke" else
                   client.inspect(req) if cmd == "inspect" else
                   client.apply_policy(req) if cmd == "policy apply" else
                   client.rotate(req))
            emit(p, res)
            return 0

        if cmd == "audit export":
            no_leftover(p, ["--control-key", "--control-kid", "--out", "--after", "--limit"])
            cfg = load_client_config(cfg_path)
            control_key = load_private_key(need(p, "--control-key"))
            control_kid = need(p, "--control-kid")
            after = p.flags.get("--after") if isinstance(p.flags.get("--after"), str) else "0"
            limit = p.flags.get("--limit") if isinstance(p.flags.get("--limit"), str) else "100"
            out = need(p, "--out")
            client = LexScopeClient(origin=cfg["origin"], tenant_id=cfg["tenant_id"],
                                    control_key=control_key, control_kid=control_kid)
            page = client.audit(after, int(limit))
            _exclusive_write(out, (jcs_str(page) + "\n").encode("utf-8"), 0o644)  # never overwrites evidence
            emit(p, {"written": out})
            return 0

        if cmd == "audit verify":
            no_leftover(p, ["--in", "--trust"])
            page = load_request(need(p, "--in"))
            trust = load_request(need(p, "--trust"))
            if not valid_audit_page(page) or not valid_audit_trust(trust):
                raise CliUsage("malformed audit page or trust document")
            v = verify_audit(page, trust)
            if not v["valid"]:
                if p.json:
                    emit(p, {"code": v["code"], "valid": False})
                else:
                    sys.stderr.write(f"audit verification failed: {v['code']}\n")
                return 8
            emit(p, {"entries": v["entries"], "head": v["head"], "valid": True})
            return 0

        if cmd == "mcp serve":
            no_leftover(p, ["--token-fd", "--caller-key", "--task-id"])
            cfg = load_client_config(cfg_path)
            token = read_token_fd(need(p, "--token-fd"))
            caller_key = load_private_key(need(p, "--caller-key"))
            task_id = need(p, "--task-id")
            claims = token_claims(token)
            if claims.get("task_id") != task_id:
                raise CliUsage("--task-id does not match token task_id claim")
            tools = [s["tool"] for s in claims.get("scopes", []) if isinstance(s, dict) and isinstance(s.get("tool"), str)]
            client = LexScopeClient(origin=cfg["origin"], tenant_id=cfg["tenant_id"], caller_key=caller_key)
            McpServer(client, handle_from_token(token), task_id, tools=tools).run_stdio()
            return 0

        sys.stderr.write(f"unknown command: {cmd}\n{usage()}")
        return 2
    except (LexScopeError, CliUsage) as e:
        sys.stderr.write(f"{e}\n")
        return exit_code(e)
    except SchemaIssue as e:
        sys.stderr.write(f"{e}\n")
        return 2
    except Exception:
        sys.stderr.write("error\n")
        return 2
