// Hosted / paid / cloud surfaces (spec §16 Phase 4, §12 real-Herald
// integrations). These are documented stub interfaces — they throw
// NotImplemented with a pointer to the contract instead of faking behavior.
// Nothing in the OSS core depends on them; self-hosted operators get the full
// enforcement and audit surface without them.

const LINK =
  "https://github.com/LatticeAG/lexscope/blob/main/README.md#hosted";

function notImplemented(surface: string): Error {
  return new Error(`NotImplemented: ${surface} is a hosted LatticeAG surface outside the OSS core — see ${LINK}`);
}

// Phase 4 — hosted multi-tenant minting and rotation.
export class HostedTenantProvisioner {
  provisionTenant(): never {
    throw notImplemented("hosted tenant provisioning");
  }
  rotateTenantSigner(): never {
    throw notImplemented("hosted scheduled rotation");
  }
  tenantMetrics(): never {
    throw notImplemented("tenant-safe operational metrics");
  }
}

// Phase 5 — real Herald protocol adapter. The normalized §12 observation
// contract and its fail-closed semantics are implemented in engine/herald.ts;
// a pinned real-Herald transport is not part of this release.
export class HeraldProtocolAdapter {
  fetchObservation(): never {
    throw notImplemented("pinned real-Herald protocol adapter");
  }
  verifyCardSignature(): never {
    throw notImplemented("real Herald card-signature verification");
  }
}

// Production provider adapters. The OSS core ships only sandbox adapters; a
// real provider binding is an operator-configured deployment artifact that
// must satisfy the same ToolAdapter contract and §12 classification checks.
export class ProductionProviderAdapter {
  invoke(): never {
    throw notImplemented("production provider adapters (sandbox-only in OSS core)");
  }
}

export { HostedControlPlane } from "./sdk.ts";
