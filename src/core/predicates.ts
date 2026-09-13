// Predicate evaluation and the fixed §4.2 implication table.
// No regex, glob, eval, or theorem proving beyond the listed rows.

import { isObj, type Predicate, type Scope, type ToolName } from "./schemas.ts";

function fieldOf(ptr: string): string {
  return ptr.slice(1);
}

function typedEq(a: unknown, b: unknown): boolean {
  return typeof a === typeof b && a === b;
}

// path_prefix membership: matches p itself or anything strictly below it.
export function pathMatches(prefix: string, s: string): boolean {
  return s === prefix || s.startsWith(prefix + "/");
}

// Evaluate one predicate against a tool-call args object. A missing pointer,
// array traversal, type mismatch, or null operand never satisfies.
export function evalPredicate(p: Predicate, args: unknown): boolean {
  if (!isObj(args)) return false;
  const field = fieldOf(p.ptr);
  if (!Object.prototype.hasOwnProperty.call(args, field)) return false;
  const v = (args as Record<string, unknown>)[field];
  if (v === null || typeof v === "object") return false;
  switch (p.op) {
    case "eq":
      return typedEq(v, p.value);
    case "in":
      return p.values.some((x) => typedEq(v, x));
    case "int_range":
      return typeof v === "number" && Number.isInteger(v) && v >= p.min && v <= p.max;
    case "path_prefix":
      return typeof v === "string" && pathMatches(p.value, v);
  }
}

export function scopeHolds(scope: Scope, args: unknown): boolean {
  return scope.where.every((p) => evalPredicate(p, args));
}

// At least one same-tool scope must hold.
export function argsPermitted(scopes: Scope[], tool: ToolName, args: unknown): boolean {
  return scopes.some((s) => s.tool === tool && scopeHolds(s, args));
}

// ---------- mint-time subset proof (§4.2) ----------

function isSingletonIn(p: Predicate): p is { ptr: string; op: "in"; values: [string | number | boolean] } {
  return p.op === "in" && p.values.length === 1;
}

// Does request predicate Q imply policy predicate P (same pointer required)?
export function implies(q: Predicate, p: Predicate): boolean {
  if (q.ptr !== p.ptr) return false;
  switch (p.op) {
    case "eq": {
      if (q.op === "eq") return typedEq(q.value, p.value);
      if (isSingletonIn(q)) return typedEq(q.values[0], p.value);
      return false;
    }
    case "in": {
      if (q.op === "eq") return p.values.some((x) => typedEq(x, q.value));
      if (q.op === "in") return q.values.every((b) => p.values.some((a) => typedEq(a, b)));
      return false;
    }
    case "int_range": {
      if (q.op === "eq")
        return typeof q.value === "number" && Number.isInteger(q.value) && q.value >= p.min && q.value <= p.max;
      if (q.op === "in")
        return q.values.every(
          (b) => typeof b === "number" && Number.isInteger(b) && b >= p.min && b <= p.max,
        );
      if (q.op === "int_range") return q.min >= p.min && q.max <= p.max;
      return false;
    }
    case "path_prefix": {
      if (q.op === "eq") return typeof q.value === "string" && pathMatches(p.value, q.value);
      if (q.op === "in") return q.values.every((b) => typeof b === "string" && pathMatches(p.value, b));
      if (q.op === "path_prefix") return pathMatches(p.value, q.value);
      return false;
    }
  }
}

// A request scope implies a policy scope when every policy predicate has a
// same-pointer request predicate that implies it. Additional request
// predicates at schema-valid pointers are allowed (they only narrow).
export function scopeImplies(request: Scope, grant: Scope): boolean {
  if (request.tool !== grant.tool) return false;
  return grant.where.every((p) => request.where.some((q) => implies(q, p)));
}

export interface MintScopeResult {
  ok: boolean;
  hardDenied: boolean;
}

// Each requested scope must imply exactly one complete policy scope.
export function checkMintScopes(request: Scope[], grants: Scope[], hardDeny: string[]): MintScopeResult {
  for (const s of request) {
    if (hardDeny.includes(s.tool)) return { ok: false, hardDenied: true };
    if (!grants.some((g) => scopeImplies(s, g))) return { ok: false, hardDenied: false };
  }
  return { ok: true, hardDenied: false };
}
