import { World } from "./harness.ts";
import { READ, MINT, MINTED, T } from "./fixtures.ts";

const w2 = new World();
const mintRes = await w2.control("/mint", MINT, { proof_id: "lpf_" + "M".repeat(32) });
console.log("mint status", mintRes.status, JSON.stringify(mintRes.body));
console.log("exact MINTED:", JSON.stringify(mintRes.body) === JSON.stringify(MINTED));
const r = await w2.agent("/calls", READ);
console.log("status", r.status, "code", r.code, "dispatch", r.dispatch, "state", r.callState);
console.log("body", JSON.stringify(r.body));
