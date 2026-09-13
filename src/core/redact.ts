// Output scrubbing per §11.2. The buffered adapter result is scanned whole —
// before any chunking or model delivery — for exact secret bytes, one-pass
// percent encoding, base64, base64url, and recognizable compact LexScope JWTs.
// A detection blocks the entire result; the matched secret is never reported.

import { b64uDecode } from "./b64.ts";

const JWT_RE = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const LEX_TYP = new Set(["lexscope+jwt", "dpop+jwt", "lexscope-control+jwt"]);

export function percentEncode(s: string): string {
  return encodeURIComponent(s);
}

export function collectStrings(v: unknown, into: string[]): void {
  if (typeof v === "string") {
    into.push(v);
    return;
  }
  if (Array.isArray(v)) {
    for (const x of v) collectStrings(x, into);
    return;
  }
  if (v !== null && typeof v === "object") {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      into.push(k);
      collectStrings(x, into);
    }
  }
}

function isLexScopeJwt(candidate: string): boolean {
  const parts = candidate.split(".");
  const h = b64uDecode(parts[0]!);
  if (h === null) return false;
  try {
    const header = JSON.parse(Buffer.from(h).toString("utf8"));
    if (header && typeof header === "object" && LEX_TYP.has((header as Record<string, unknown>).typ as string)) return true;
  } catch {
    /* not json */
  }
  const p = b64uDecode(parts[1]!);
  if (p === null) return false;
  try {
    const payload = JSON.parse(Buffer.from(p).toString("utf8"));
    if (payload && typeof payload === "object") {
      const s = JSON.stringify(payload);
      if (s.includes("urn:lexscope:") || s.includes("lexscope")) return true;
    }
  } catch {
    /* not json */
  }
  return false;
}

// secrets: exact byte strings that must never appear (access token, proofs,
// provider credentials held by the adapter for this invocation).
export function scanForCredentials(result: unknown, serialized: string, secrets: string[]): boolean {
  const texts: string[] = [serialized];
  collectStrings(result, texts);
  for (const text of texts) {
    for (const secret of secrets) {
      if (secret.length === 0) continue;
      if (text.includes(secret)) return true;
      if (text.includes(percentEncode(secret))) return true;
      if (text.includes(Buffer.from(secret, "utf8").toString("base64"))) return true;
      if (text.includes(Buffer.from(secret, "utf8").toString("base64url"))) return true;
    }
    JWT_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = JWT_RE.exec(text)) !== null) {
      if (isLexScopeJwt(m[0])) return true;
    }
  }
  return false;
}
