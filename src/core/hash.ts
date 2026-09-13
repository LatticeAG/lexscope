import { createHash } from "node:crypto";
import { jcs } from "./jcs.ts";

// S(x): lowercase hexadecimal SHA-256 of byte string x.
export function sha256(data: Uint8Array | string): Uint8Array {
  return createHash("sha256").update(typeof data === "string" ? Buffer.from(data, "utf8") : data).digest();
}

export function sha256Hex(data: Uint8Array | string): string {
  return Buffer.from(sha256(data)).toString("hex");
}

// D(tag,x) = S(UTF8(tag) || 0x00 || J(x))
export function domainHash(tag: string, value: unknown): string {
  const h = createHash("sha256");
  h.update(tag, "ascii");
  h.update(Buffer.from([0]));
  h.update(jcs(value));
  return h.digest("hex");
}

// U(h): exactly 64 lowercase hex chars -> 32 bytes; null otherwise.
export function unhex(h: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/.test(h)) return null;
  return new Uint8Array(Buffer.from(h, "hex"));
}
