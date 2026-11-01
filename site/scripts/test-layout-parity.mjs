import assert from 'node:assert/strict';
import { compareMeasurements, statesFor } from './check-layout-parity.mjs';
const base = [{ key: 'H1:Example', box: { x: 20, y: 80, width: 350, height: 48 }, style: { fontSize: '32px', color: 'rgb(0, 0, 0)' } }];
assert.deepEqual(compareMeasurements(base, structuredClone(base)), []);
const shifted = structuredClone(base); shifted[0].box.x += 3;
assert.ok(compareMeasurements(base, shifted).some(s => s.includes('x 20 -> 23 CSSpx')), 'planted 3px shift must fail the actual comparator');
const allowed = structuredClone(base); allowed[0].box.x += 1;
assert.deepEqual(compareMeasurements(base, allowed), []);
const styled = structuredClone(base); styled[0].style.fontSize = '34px';
assert.ok(compareMeasurements(base, styled).some(s => s.includes('fontSize')));
assert.ok(compareMeasurements(base, []).length);
console.log('test-layout-parity: equality, planted 3px fault, 1px boundary, style and missing-element assertions passed');
// Even startup failure must leave an explicit incomplete record, not an empty pass.
const { mkdtemp, readFile, rm } = await import('node:fs/promises');
const { tmpdir } = await import('node:os');
const { join } = await import('node:path');
const { compareLayouts } = await import('./check-layout-parity.mjs');
const temporary = await mkdtemp(join(tmpdir(), 'layout-parity-fixture-'));
try {
  await assert.rejects(compareLayouts(join(temporary, 'missing-base'), join(temporary, 'missing-head'), join(temporary, 'evidence')));
  const record = JSON.parse(await readFile(join(temporary, 'evidence/results.json'), 'utf8'));
  assert.equal(record.completed, false);
  assert.match(record.fatalError, /ENOENT/);
} finally { await rm(temporary, { recursive: true, force: true }); }
console.log('test-layout-parity: startup failure leaves incomplete evidence');

// Ordinary pages must not lose menu/search coverage when they have no screenshot slot.
assert.deepEqual(statesFor('webkit', false), [{ theme: 'light', state: 'page' }, { theme: 'light', state: 'menu' }]);
assert.deepEqual(statesFor('chromium', false), [{ theme: 'light', state: 'page' }, { theme: 'light', state: 'search' }]);
for (const engine of ['chromium', 'webkit']) {
  assert.deepEqual(statesFor(engine, true), [...statesFor(engine, false), { theme: 'dark', state: 'page' }]);
}
console.log('test-layout-parity: every page gets pattern-specific interaction coverage; dark is representative-only');
