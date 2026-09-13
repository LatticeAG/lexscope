import { createPublicKey, createPrivateKey, sign as rawSign, verify as rawVerify, KeyObject } from "node:crypto";
import { b64uEncode, b64uDecode } from "./b64.ts";
import { jcs } from "./jcs.ts";
import { sha256 } from "./hash.ts";

// Ed25519 JWS compact serialization per §5.1. Closed header profiles are
// enforced by the schema layer; here we handle raw crypto + strict segments.

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export function jwkToKeyObject(jwk: PublicJwk): KeyObject {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
}

export function keyObjectToJwk(key: KeyObject): PublicJwk {
  const j = key.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
  return { kty: "OKP", crv: "Ed25519", x: j.x };
}

export function publicJwkFromRaw(raw: Uint8Array): PublicJwk {
  return { kty: "OKP", crv: "Ed25519", x: b64uEncode(raw) };
}

// RFC 7638 thumbprint over the fixed public-JWK member set.
export function jkt(jwk: PublicJwk): string {
  return b64uEncode(sha256(jcs(jwk)));
}

export function ed25519Sign(message: Uint8Array, privateKey: KeyObject): Uint8Array {
  return new Uint8Array(rawSign(null, Buffer.from(message), privateKey));
}

export function ed25519Verify(message: Uint8Array, signature: Uint8Array, jwk: PublicJwk): boolean {
  try {
    return rawVerify(null, Buffer.from(message), jwkToKeyObject(jwk), Buffer.from(signature));
  } catch {
    return false;
  }
}

export function privateKeyFromSeed(seed: Uint8Array): KeyObject {
  // PKCS8-wrapped Ed25519 from a 32-byte seed (deterministic; test/local use).
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8 = Buffer.concat([prefix, Buffer.from(seed)]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

export function privateKeyToPkcs8Pem(key: KeyObject): string {
  return key.export({ format: "pem", type: "pkcs8" }) as string;
}

export function privateKeyFromPkcs8Pem(pem: string): KeyObject {
  return createPrivateKey({ key: pem, format: "pem", type: "pkcs8" });
}

export function jwsCompact(header: unknown, payload: unknown, key: KeyObject): string {
  const h = b64uEncode(jcs(header));
  const p = b64uEncode(jcs(payload));
  const input = `${h}.${p}`;
  const sig = ed25519Sign(Buffer.from(input, "ascii"), key);
  return `${input}.${b64uEncode(sig)}`;
}

export interface ParsedJws {
  header: unknown;
  payload: unknown;
  headerBytes: Uint8Array;
  payloadBytes: Uint8Array;
  signature: Uint8Array;
  signingInput: Uint8Array;
  canonical: boolean; // each decoded segment equals its own canonical JCS encoding
}

// Structural decode only — no trust decision here. Returns null when the value
// is not a well-formed compact JWS (segment shape, strict b64u, JSON objects,
// 64-byte signature).
export function parseJws(token: string): ParsedJws | null {
  if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) return null;
  const parts = token.split(".");
  const h = b64uDecode(parts[0]!);
  const p = b64uDecode(parts[1]!);
  const s = b64uDecode(parts[2]!);
  if (h === null || p === null || s === null || s.length !== 64) return null;
  let header: unknown, payload: unknown;
  try {
    header = JSON.parse(Buffer.from(h).toString("utf8"));
    payload = JSON.parse(Buffer.from(p).toString("utf8"));
  } catch {
    return null;
  }
  if (header === null || payload === null || typeof header !== "object" || typeof payload !== "object" || Array.isArray(header) || Array.isArray(payload))
    return null;
  let canonical = true;
  try {
    if (!jcs(header).equals(h) || !jcs(payload).equals(p)) canonical = false;
  } catch {
    canonical = false;
  }
  return {
    header,
    payload,
    headerBytes: h,
    payloadBytes: p,
    signature: s,
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"),
    canonical,
  };
}

// Detects a compact-JWS-shaped string (three strict b64u segments).
export function looksLikeJwt(v: unknown): boolean {
  return typeof v === "string" && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
}
