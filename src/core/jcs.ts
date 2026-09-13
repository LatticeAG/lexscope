// J(x): RFC 8785 canonical JSON restricted to the lexscope/1 integer profile.
// Numbers are safe integers only; object keys sort by UTF-16 code units.

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const MAX_SAFE = 9007199254740991;

function escapeString(s: string): string {
  // RFC 8785 / ECMA-404 minimal escaping; non-ASCII preserved raw (UTF-8 output).
  let out = '"';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

export function jcs(value: Json | unknown): Buffer {
  if (value === null) return Buffer.from("null", "utf8");
  const t = typeof value;
  if (t === "boolean") return Buffer.from(value ? "true" : "false", "ascii");
  if (t === "string") return Buffer.from(escapeString(value as string), "utf8");
  if (t === "number") {
    const n = value as number;
    if (!Number.isSafeInteger(n) || Math.abs(n) > MAX_SAFE || Object.is(n, -0))
      throw new Error("outside lexscope integer JSON profile");
    return Buffer.from(String(n), "ascii");
  }
  if (Array.isArray(value)) {
    const parts = (value as unknown[]).map((x) => jcs(x));
    return Buffer.concat([Buffer.from("["), ...intersperse(parts), Buffer.from("]")]);
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort(utf16Compare);
    const parts: Buffer[] = [];
    for (const k of keys) {
      parts.push(Buffer.from(escapeString(k), "utf8"));
      parts.push(Buffer.from(":"));
      parts.push(jcs(obj[k]));
    }
    return Buffer.concat([Buffer.from("{"), ...intersperse(parts, true), Buffer.from("}")]);
  }
  throw new Error("outside lexscope integer JSON profile");
}

function intersperse(parts: Buffer[], triplets = false): Buffer[] {
  // For arrays: join elements with ",". For objects: parts arrive as [k,":",v,k,":",v]
  // and must be joined as k:v,k:v.
  if (!triplets) {
    const out: Buffer[] = [];
    parts.forEach((p, i) => {
      if (i > 0) out.push(Buffer.from(","));
      out.push(p);
    });
    return out;
  }
  const out: Buffer[] = [];
  for (let i = 0; i < parts.length; i += 3) {
    if (i > 0) out.push(Buffer.from(","));
    out.push(parts[i]!, parts[i + 1]!, parts[i + 2]!);
  }
  return out;
}

// UTF-16 code-unit ordering (JS string comparison is already UTF-16 based).
export function utf16Compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function jcsString(value: unknown): string {
  return jcs(value).toString("utf8");
}
