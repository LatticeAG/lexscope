"""LexScope — scoped, one-shot, revocable agent credentials (Python package).

The public surface mirrors the TypeScript package: canonical JSON, Ed25519
cryptography, the error taxonomy, predicates, schemas, the offline audit
verifier, the client SDK, and the MCP/OpenAI shims.
"""
from . import audit, canon, crypto, errors, ids, predicates, schemas, sdk

from .canon import (
    DepthError, DupKey, StrictJsonError, UnsafeNumber, jcs, jcs_str, parse_strict,
)
from .crypto import (
    b64u, b64u_decode, b64u_json, domain_hash, gen_private, jkt, jws,
    jwk_public, load_pkcs8, load_public_jwk, parse_jws, pkcs8_pem,
    private_from_seed, public_jwk, sha256, sha256_hex, sign, verify, verify_jws,
)
from .errors import LexScopeError as CoreError, is_retryable, status
from .ids import is_counter, is_hash, is_id, is_seconds, random_id
from .predicates import (
    args_permitted, check_mint_scopes, eval_predicate, implies, path_matches,
    scope_holds, scope_implies,
)
from .audit import verify_audit, valid_audit_page, valid_audit_trust
from .sdk import (
    HostedControlPlane, LexScopeClient, LexScopeError, REDACTED, TokenHandle,
    TransportError,
)
from .mcp import McpServer
from .openai import OpenAIShim, tool_definitions

__version__ = "1.0.0"
