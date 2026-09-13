// Local smoke transport redirect (examples/smoke.mjs only).
//
// The spec's test-mode origin is a fixed string; the smoke broker listens on
// an ephemeral loopback port. This shim rewrites fetch targets from the
// configured origin to the local socket — equivalent to a hosts-file entry or
// a TLS-terminating edge. Signed htu/aud claims still carry the configured
// origin, so every wire-level binding is exercised for real.
const real = globalThis.fetch;
const target = process.env.LX_SMOKE_TARGET; // e.g. http://127.0.0.1:PORT
const from = process.env.LX_SMOKE_ORIGIN ?? "https://gateway.example.test";
globalThis.fetch = (url, init) => {
  const u = String(url);
  return real(target && u.startsWith(from) ? target + u.slice(from.length) : u, init);
};
