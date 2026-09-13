// Deployment composition: one TenantAuthority per configured tenant plus the
// Gateway front. Local/single-process analog of Worker + TenantDO routing.

import type { KeyObject } from "node:crypto";
import { Store } from "./store.ts";
import { TenantAuthority } from "./authority.ts";
import { Gateway, type WireRequest, type WireResponse } from "./gateway.ts";
import { makeRowCipher } from "../core/box.ts";
import { validateGatewayConfig, type GatewayConfigT } from "../core/schemas.ts";
import { randomId, type IdGen } from "../core/ids.ts";
import { systemClock, type PhysicalClock } from "../core/clock.ts";
import type { ToolAdapter } from "./adapters.ts";
import type { HeraldAdapter } from "./herald.ts";

export interface Deployment {
  store: Store;
  authority: TenantAuthority;
  gateway: Gateway;
  handle(req: WireRequest): Promise<WireResponse>;
}

export interface DeployOptions {
  config: unknown; // validated via validateGatewayConfig
  secrets: Map<string, KeyObject>; // secret_ref -> Ed25519 private key
  dataKey: Uint8Array; // 32-byte AES-256-GCM key for encryption.key_ref
  clock?: PhysicalClock;
  idgen?: IdGen;
  adapters?: Map<string, ToolAdapter>;
  heraldAdapters?: Map<string, HeraldAdapter>;
  dbPath?: string;
  auditSign?: TenantAuthority["auditSign"];
  // deterministic lev_<seq> event ids for conformance fixtures only
  fixtureIds?: boolean;
}

export function deploy(opts: DeployOptions): Deployment {
  const config: GatewayConfigT = validateGatewayConfig(opts.config);
  const store = new Store(opts.dbPath ?? ":memory:");
  const authority = new TenantAuthority({
    store,
    config,
    secrets: { get: (ref) => opts.secrets.get(ref) },
    cipher: makeRowCipher(opts.dataKey, config.encryption.key_version),
    adapters: opts.adapters ?? new Map(),
    heraldAdapters: opts.heraldAdapters ?? new Map(),
    clock: opts.clock ?? systemClock,
    idgen: opts.idgen ?? randomId,
    ...(opts.auditSign ? { auditSign: opts.auditSign } : {}),
  });
  if (opts.fixtureIds) authority.fixtureIds = true;
  authority.bootstrap(authority.now());
  const gateway = new Gateway(authority, opts.idgen ?? randomId);
  return {
    store,
    authority,
    gateway,
    handle: (req) => gateway.handle(req),
  };
}
