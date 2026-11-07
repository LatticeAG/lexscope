// Node 22 warns when SQLite is first loaded. Limit the filter to that load and
// exact warning so other experimental and ordinary warnings remain visible.
if (Number(process.versions.node.split('.')[0]) === 22) {
  const emitWarning = process.emitWarning;
  process.emitWarning = function (warning, ...args) {
    const type = typeof args[0] === 'string' ? args[0] : args[0]?.type;
    if (warning === 'SQLite is an experimental feature and might change at any time' && type === 'ExperimentalWarning') return;
    return emitWarning.call(this, warning, ...args);
  };
  try {
    await import('node:sqlite');
  } finally {
    process.emitWarning = emitWarning;
  }
}
await import('./smoke.ts');
