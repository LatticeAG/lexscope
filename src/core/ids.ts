import { randomBytes } from "node:crypto";

// Cryptographic nanoid-style identifiers per §3.
// 21-char suffix => 126 random bits; lnn_/lpf_ use 32 chars => 192 bits.
const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

export type IdGen = (prefix: string, size?: number) => string;

export const randomId: IdGen = (prefix, size = 21) => {
  const bytes = randomBytes(size);
  let s = "";
  for (let i = 0; i < size; i++) s += ALPHA[bytes[i]! & 63];
  return `${prefix}_${s}`;
};

const ID_RE = /^[A-Za-z0-9_-]+$/;

export function isId(v: unknown, prefix: string, size = 21): v is string {
  return (
    typeof v === "string" &&
    v.length === prefix.length + 1 + size &&
    v.startsWith(prefix + "_") &&
    ID_RE.test(v.slice(prefix.length + 1))
  );
}

export const idValidators: Record<string, (v: unknown) => boolean> = {
  lsg: (v) => isId(v, "lsg"),
  ltn: (v) => isId(v, "ltn"),
  lsu: (v) => isId(v, "lsu"),
  lts: (v) => isId(v, "lts"),
  ltk: (v) => isId(v, "ltk"),
  lcl: (v) => isId(v, "lcl"),
  lop: (v) => isId(v, "lop"),
  lky: (v) => isId(v, "lky"),
  lev: (v) => isId(v, "lev"),
  lrq: (v) => isId(v, "lrq"),
  lnn: (v) => isId(v, "lnn", 32),
  lpf: (v) => isId(v, "lpf", 32),
};

export function isCounter(v: unknown): v is string {
  return typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) <= 9223372036854775807n;
}
