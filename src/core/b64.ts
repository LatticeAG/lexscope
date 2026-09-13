// Strict unpadded base64url per lexscope/1 §3.
// Encodings with padding, nonalphabet characters, or nonzero unused bits are rejected.

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const DECODE = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) DECODE[ALPHABET.charCodeAt(i)] = i;

export function b64uEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

// Returns null on any deviation from the unpadded-base64url profile.
export function b64uDecode(s: string): Uint8Array | null {
  if (s.length === 0) return new Uint8Array(0);
  if (s.length % 4 === 1) return null;
  const n = s.length;
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (c > 127 || DECODE[c]! < 0) return null;
  }
  // nonzero unused bits: last char of a %4==2 group keeps low 4 bits zero; %4==3 keeps low 2 bits zero.
  const rem = n % 4;
  const last = DECODE[s.charCodeAt(n - 1)]!;
  if (rem === 2 && (last & 0x0f) !== 0) return null;
  if (rem === 3 && (last & 0x03) !== 0) return null;
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function b64uJson(s: string): unknown | undefined {
  const bytes = b64uDecode(s);
  if (bytes === null) return undefined;
  try {
    return JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    return undefined;
  }
}
