#!/usr/bin/env node
// lexscope-broker: local dev/conformance HTTP host for the LexScope gateway.
import { serve } from "../src/server.ts";

function arg(name, optional = false) {
  const i = process.argv.indexOf(name);
  if (i === -1 || i + 1 >= process.argv.length) {
    if (optional) return undefined;
    console.error(`missing required flag ${name}`);
    process.exit(2);
  }
  return process.argv[i + 1];
}

const listen = process.argv.includes("--listen") ? arg("--listen").split(":") : null;
const deployment = await serve({
  configPath: arg("--config"),
  secretsPath: arg("--secrets"),
  dataKeyPath: arg("--data-key"),
  dbPath: process.argv.includes("--db") ? arg("--db") : ":memory:",
  docsPath: arg("--docs", true),
  recordsPath: arg("--records", true),
  listen: listen
    ? { host: listen.slice(0, -1).join(":") || "127.0.0.1", port: Number(listen[listen.length - 1]) }
    : { host: "127.0.0.1", port: 8787 },
});
console.error(`lexscope-broker listening on 127.0.0.1:${deployment.port}`);
