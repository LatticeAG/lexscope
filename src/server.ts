// lexscope-broker: local single-process HTTP server for the LexScope gateway.
// Maps node:http requests onto the Gateway wire surface. Local development and
// conformance hosting only; production deployment targets are documented in
// the spec but are not implemented here.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, openSync, statSync } from "node:fs";
import { createPrivateKey, type KeyObject } from "node:crypto";
import { parseStrict } from "./core/strictjson.ts";
import { deploy, type Deployment } from "./engine/deploy.ts";
import { FakeDocumentsAdapter, FakeRecordsAdapter } from "./engine/adapters.ts";
import { FakeHeraldAdapter } from "./engine/herald.ts";
import type { WireRequest } from "./engine/gateway.ts";
import type { ToolAdapter } from "./engine/adapters.ts";

export interface BrokerOptions {
  configPath: string;
  secretsPath: string; // strict JSON: { "<SECRET_REF>": "<pkcs8 pem>" }
  dataKeyPath: string; // 64 lowercase hex chars (32 bytes), mode 0600
  dbPath?: string;
  listen?: { host: string; port: number };
  docsPath?: string;    // strict JSON seed data for the fake documents adapter
  recordsPath?: string; // strict JSON seed data for the fake records adapter
}

const MAX_BODY = 128 * 1024;

function loadSecrets(path: string): Map<string, KeyObject> {
  const doc = parseStrict(new Uint8Array(readFileSync(path)));
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error(`secrets file must be a JSON object: ${path}`);
  }
  const out = new Map<string, KeyObject>();
  for (const [ref, pem] of Object.entries(doc)) {
    if (typeof pem !== "string" || !pem.includes("PRIVATE KEY")) {
      throw new Error(`secret ${ref} must be a PKCS8 PEM string`);
    }
    out.set(ref, createPrivateKey(pem));
  }
  return out;
}

function loadDataKey(path: string): Uint8Array {
  const st = statSync(path);
  if ((st.mode & 0o777) !== 0o600) throw new Error(`data key ${path} must be mode 0600`);
  const hex = readFileSync(path, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("data key must be 64 lowercase hex chars");
  return new Uint8Array(Buffer.from(hex, "hex"));
}

export function makeDeployment(opts: BrokerOptions): Deployment {
  const config = parseStrict(new Uint8Array(readFileSync(opts.configPath)));
  const secrets = loadSecrets(opts.secretsPath);
  const dataKey = loadDataKey(opts.dataKeyPath);
  const loadSeed = (p?: string): Record<string, Record<string, unknown>> => {
    if (p === undefined) return {};
    const doc = parseStrict(new Uint8Array(readFileSync(p)));
    if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw new Error(`seed file must be a JSON object: ${p}`);
    return doc as Record<string, Record<string, unknown>>;
  };
  const gw = config as {
    gateway_id: string;
    tools?: { documents_read_binding?: string; records_delete_binding?: string };
  };
  const now = () => Math.floor(Date.now() / 1000);
  const adapters = new Map<string, ToolAdapter>();
  if (typeof gw.tools?.documents_read_binding === "string") {
    adapters.set(gw.tools.documents_read_binding, new FakeDocumentsAdapter({
      gateway: gw.gateway_id, binding: gw.tools.documents_read_binding, now,
      docs: loadSeed(opts.docsPath) as never,
    }));
  }
  if (typeof gw.tools?.records_delete_binding === "string") {
    adapters.set(gw.tools.records_delete_binding, new FakeRecordsAdapter({
      gateway: gw.gateway_id, binding: gw.tools.records_delete_binding, now,
      records: loadSeed(opts.recordsPath) as never,
    }));
  }
  return deploy({
    config,
    secrets,
    dataKey,
    adapters,
    heraldAdapters: new Map(),
    ...(opts.dbPath !== undefined ? { dbPath: opts.dbPath } : {}),
  });
}

async function readBody(req: IncomingMessage): Promise<Uint8Array | null> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of req) {
    n += (c as Buffer).length;
    if (n > MAX_BODY) return null;
    chunks.push(c as Buffer);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

export function serve(opts: BrokerOptions): Promise<Deployment & { port: number }> {
  const d = makeDeployment(opts);
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const body = await readBody(req);
    if (body === null) {
      res.writeHead(413, { "content-type": "application/json" });
      res.end(JSON.stringify({ v: 1, call_id: null, outcome: "NOT_DISPATCHED", error: { code: "BODY_TOO_LARGE", request_id: null, retryable: false } }));
      return;
    }
    // rawHeaders preserves duplicates and order — required for the duplicate
    // Authorization rejection rule.
    const headers: [string, string][] = [];
    const raw = req.rawHeaders;
    for (let i = 0; i + 1 < raw.length; i += 2) headers.push([raw[i]!.toLowerCase(), raw[i + 1]!]);
    const wire: WireRequest = {
      method: (req.method ?? "GET").toUpperCase(),
      target: req.url ?? "/",
      headers,
      body,
    };
    const out = await d.handle(wire);
    const hs: Record<string, string> = {};
    for (const [k, v] of Object.entries(out.headers)) {
      hs[k.toLowerCase()] = Array.isArray(v) ? v.join(",") : v;
    }
    res.writeHead(out.status, hs);
    res.end(Buffer.from(out.body));
  });
  const { host, port } = opts.listen ?? { host: "127.0.0.1", port: 8787 };
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address();
      const p = typeof addr === "object" && addr !== null ? addr.port : port;
      resolve({ ...d, port: p });
    });
  });
}

export { openSync as _openSync };
