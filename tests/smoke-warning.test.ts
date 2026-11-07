import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';

test('in-process smoke filters only the SQLite warning', () => {
  const preload = `setImmediate(() => {
    process.emitWarning('another experimental warning', 'ExperimentalWarning');
    process.emitWarning('ordinary warning');
  });`;
  const result = spawnSync(process.execPath, [
    '--import', `data:text/javascript,${encodeURIComponent(preload)}`,
    'tests/smoke-entry.mjs',
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /SQLite is an experimental feature/);
  assert.match(result.stderr, /ExperimentalWarning: another experimental warning/);
  assert.match(result.stderr, /Warning: ordinary warning/);
});
