// Herald normalized adapter contract per §12 / INTERFACES E08.
// The normalized observation shape and its fail-closed validation are part of
// the OSS core; a real Herald source protocol is pinned separately (§17) and
// the live adapter below is a documented stub.

import type { HeraldBinding } from "../core/schemas.ts";
import { isId } from "../core/ids.ts";

export interface HeraldCheck {
  v: 1;
  tenant_id: string;
  sub: string;
  caller_jkt: string;
  binding: HeraldBinding;
  challenge: string;
  mode: "fresh" | "bounded_cache";
  now: number;
}

export interface HeraldObservation {
  v: 1;
  challenge: string;
  card_hash: string;
  sub: string;
  caller_jkt: string;
  status: "active" | "revoked";
  checked_at: number;
  valid_until: number;
  evidence_hash: string;
}

export interface HeraldAdapter {
  check(input: HeraldCheck): Promise<HeraldObservation>;
}

// Fresh checks: valid window <= 5 s; bounded_cache: <= 60 s.
export const FRESH_WINDOW = 5;
export const CACHE_WINDOW = 60;

export type HeraldVerdict = "active" | "revoked" | "unavailable";

// Validates a normalized observation against the request. challenge must echo
// the request's challenge exactly; freshness is carried by checked_at /
// valid_until (for bounded_cache the challenge is a routing nonce only).
export function validateObservation(input: HeraldCheck, obs: HeraldObservation): HeraldVerdict {
  if (!obs || typeof obs !== "object" || obs.v !== 1) return "unavailable";
  if (obs.challenge !== input.challenge) return "unavailable";
  if (obs.card_hash !== input.binding.card_hash) return "unavailable";
  if (obs.sub !== input.sub) return "unavailable";
  if (obs.caller_jkt !== input.caller_jkt) return "unavailable";
  if (typeof obs.checked_at !== "number" || typeof obs.valid_until !== "number") return "unavailable";
  const window = input.mode === "fresh" ? FRESH_WINDOW : CACHE_WINDOW;
  if (!(obs.checked_at <= input.now)) return "unavailable";
  if (!(input.now < obs.valid_until)) return "unavailable"; // exclusive end
  if (obs.valid_until - obs.checked_at > window) return "unavailable";
  if (obs.status === "revoked") return "revoked";
  if (obs.status !== "active") return "unavailable";
  return "active";
}

// Test/local adapter: serves scripted observations. Real source verification
// under pinned trust roots is the hosted/pinned-protocol surface.
export class FakeHeraldAdapter implements HeraldAdapter {
  observations: (HeraldObservation | "throw")[] = [];
  calls: HeraldCheck[] = [];
  next: HeraldObservation | null = null;
  async check(input: HeraldCheck): Promise<HeraldObservation> {
    this.calls.push(input);
    const o = this.observations.shift() ?? this.next;
    if (o === "throw") throw new Error("herald source unreachable");
    if (!o) throw new Error("herald adapter unscripted");
    return o;
  }
}

// The live Herald source adapter is intentionally not implemented in the OSS
// core: §17 pins required-card support on a tested signed Herald status/card
// contract that is published separately. It fails closed, never silently.
export class LiveHeraldAdapter implements HeraldAdapter {
  source: string;
  constructor(source: string) {
    this.source = source;
  }
  async check(_input: HeraldCheck): Promise<HeraldObservation> {
    void _input;
    throw new Error(
      `Herald source "${this.source}": live card protocol not pinned in lexscope/1 — ` +
        `see https://github.com/LatticeAG/lexscope/blob/main/docs/herald.md (HeraldAdapter contract, spec §12/§17)`,
    );
  }
}

export function isValidHeraldChallenge(v: unknown): v is string {
  return isId(v, "lrq") || isId(v, "lnn", 32);
}
