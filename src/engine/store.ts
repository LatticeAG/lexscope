import { DatabaseSync } from "node:sqlite";

// Tenant authority storage — the TenantDO equivalent. One SQLite database,
// single writer, synchronous transactions, parameterized statements only.

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS policies (revision INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, sub TEXT NOT NULL, jkt TEXT NOT NULL, herald TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, sub TEXT NOT NULL, kid TEXT NOT NULL,
  digest TEXT NOT NULL, scope_hash TEXT NOT NULL, policy_hash TEXT NOT NULL,
  issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revocations (kind TEXT NOT NULL, target_id TEXT NOT NULL, effective_at INTEGER NOT NULL,
  reason TEXT NOT NULL, audit_seq INTEGER NOT NULL, PRIMARY KEY(kind,target_id));
CREATE TABLE IF NOT EXISTS proofs (kind TEXT NOT NULL, signer TEXT NOT NULL, jti TEXT NOT NULL,
  expires_at INTEGER NOT NULL, PRIMARY KEY(kind,signer,jti));
CREATE TABLE IF NOT EXISTS nonces (id TEXT PRIMARY KEY, token_id TEXT NOT NULL, call_hash TEXT NOT NULL,
  issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, state TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_nonce ON nonces(token_id,call_hash) WHERE state='OPEN';
CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, sub TEXT NOT NULL, jkt TEXT NOT NULL,
  token_id TEXT NOT NULL, scope_hash TEXT NOT NULL, call_hash TEXT NOT NULL,
  state TEXT NOT NULL, admitted_at INTEGER NOT NULL, completed_at INTEGER,
  result_cipher TEXT, error_code TEXT, audit_seq INTEGER NOT NULL, purge_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operations (kid TEXT NOT NULL, op_id TEXT NOT NULL, digest TEXT NOT NULL,
  response_cipher TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(kid,op_id));
CREATE TABLE IF NOT EXISTS signing_keys (kid TEXT PRIMARY KEY, jwk TEXT NOT NULL, secret_ref TEXT,
  state TEXT NOT NULL, last_exp INTEGER NOT NULL, activated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit_keys (kid TEXT PRIMARY KEY, jwk TEXT NOT NULL, activation_seq INTEGER NOT NULL,
  activated_at INTEGER NOT NULL, retired_seq INTEGER, secret_ref TEXT);
CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL,
  hash TEXT UNIQUE NOT NULL, signature TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS buckets (kind TEXT NOT NULL, subject TEXT NOT NULL, second INTEGER NOT NULL,
  count INTEGER NOT NULL, PRIMARY KEY(kind,subject,second));
CREATE INDEX IF NOT EXISTS tokens_expiry ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS nonces_expiry ON nonces(expires_at);
CREATE INDEX IF NOT EXISTS calls_recovery ON calls(state,admitted_at);
CREATE INDEX IF NOT EXISTS operations_expiry ON operations(expires_at);
`;

export class Store {
  db: DatabaseSync;
  constructor(path: string | ":memory:" = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA_SQL);
  }

  tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* already rolled back */
      }
      throw e;
    }
  }

  run(sql: string, ...args: (string | number | bigint | null | Uint8Array)[]): void {
    this.db.prepare(sql).run(...(args as never[]));
  }

  get<T = Record<string, unknown>>(sql: string, ...args: (string | number | bigint | null | Uint8Array)[]): T | undefined {
    return this.db.prepare(sql).get(...(args as never[])) as T | undefined;
  }

  all<T = Record<string, unknown>>(sql: string, ...args: (string | number | bigint | null | Uint8Array)[]): T[] {
    return this.db.prepare(sql).all(...(args as never[])) as T[];
  }

  meta(key: string): string | undefined {
    const r = this.get<{ value: string }>("SELECT value FROM meta WHERE key=?", key);
    return r?.value;
  }

  setMeta(key: string, value: string): void {
    this.run("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value);
  }

  // approximate storage usage in bytes for the §10 capacity rule
  storageBytes(): number {
    const pc = this.get<{ v: number | bigint }>("PRAGMA page_count");
    const ps = this.get<{ v: number | bigint }>("PRAGMA page_size");
    return Number(pc?.v ?? 0) * Number(ps?.v ?? 0);
  }

  close(): void {
    this.db.close();
  }
}
