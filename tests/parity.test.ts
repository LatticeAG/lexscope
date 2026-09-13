// TS side of the shared corpus: regenerate-check + spot verification that
// conformance/vectors.json canonical bytes match jcsString output exactly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { jcsString } from "../src/core/jcs.ts";
import { parseStrict } from "../src/core/strictjson.ts";

const doc = JSON.parse(readFileSync(new URL("../conformance/vectors.json", import.meta.url), "utf8"));

test("parity corpus: 10000 objects — canonical bytes and sha256 match", () => {
  assert.equal(doc.seed, 1800000000);
  assert.equal(doc.canon_objects.length, 10000);
  for (const o of doc.canon_objects) {
    const v = parseStrict(new TextEncoder().encode(o.input));
    const canon = jcsString(v);
    assert.equal(canon, o.canonical, `object ${o.i}`);
    assert.equal(createHash("sha256").update(canon, "utf8").digest("hex"), o.sha256);
  }
});
