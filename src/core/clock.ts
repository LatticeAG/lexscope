// Authoritative time per §5.4. now = max(floor(physical), persisted_last_now);
// a physical clock more than 90 s behind persisted last_now is CLOCK_UNSAFE.

export interface PhysicalClock {
  nowSeconds(): number; // floor of wall time in UTC seconds
}

export const systemClock: PhysicalClock = {
  nowSeconds: () => Math.floor(Date.now() / 1000),
};

export function fixedClock(t: number): PhysicalClock {
  return { nowSeconds: () => t };
}

export const PROOF_LEEWAY = 90;
export const NONCE_TTL = 60;
export const TOKEN_TTL_MAX = 300;
export const TOKEN_TTL_MIN = 30;
export const TASK_TTL = 3600;
export const ADAPTER_DEADLINE = 20;
export const PROOF_RETENTION = 181;
export const RESULT_RETENTION = 86400;
export const OPERATION_RETENTION = 86400;
export const AUDIT_RETENTION = 30 * 86400;
export const ALARM_PERIOD = 60;
export const ALARM_BATCH = 500;
