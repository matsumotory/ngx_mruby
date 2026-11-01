import assert from 'node:assert/strict';
import { publicJson, deploymentProblems } from './lib/deployment-evidence.mjs';

const sha = 'a'.repeat(40);
const valid = {
  expectedSha: sha,
  artifact: { source_revision: sha, working_tree_clean: true },
  environment: { name: 'github-pages', deployment_branch_policy: { custom_branch_policies: true, protected_branches: false } },
  policies: { total_count: 1, branch_policies: [{ name: 'next', type: 'branch' }] },
  deployment: { id: 1, environment: 'github-pages', ref: 'next', sha },
  statuses: [{ state: 'success' }],
};
assert.deepEqual(deploymentProblems(valid), []);
for (const [field, value] of [
  ['expectedSha', 'short'], ['artifact', { source_revision: 'b'.repeat(40), working_tree_clean: true }],
  ['artifact', { source_revision: sha, working_tree_clean: false }], ['environment', null],
  ['policies', { total_count: 2, branch_policies: [{ name: 'next' }] }],
  ['policies', { total_count: 1, branch_policies: [{ name: 'next', type: 'tag' }] }],
  ['deployment', { ...valid.deployment, ref: 'master' }],
  ['deployment', { ...valid.deployment, sha: 'b'.repeat(40) }],
  ['statuses', []], ['statuses', [{ state: 'pending' }]],
]) assert.ok(deploymentProblems({ ...valid, [field]: value }).length, `${field} must fail closed`);
const U = 'https://api.github.com/example';
const quiet = (extra = {}) => ({ env: {}, sleep: async () => {}, log: () => {}, ...extra });
assert.deepEqual(await publicJson(U, async () => ({ ok: true, json: async () => valid }), quiet()), valid);
// 404 and 500 are not repeated; 403 and 429 are repeated 5 times, then rejected.
for (const status of [404, 500]) {
  let calls = 0;
  await assert.rejects(publicJson(U, async () => { calls++; return { ok: false, status }; }, quiet()), /evidence is unavailable/);
  assert.equal(calls, 1, `${status} is not repeated`);
}
for (const status of [403, 429]) {
  let calls = 0;
  await assert.rejects(publicJson(U, async () => { calls++; return { ok: false, status }; }, quiet()), /evidence is unavailable/);
  assert.equal(calls, 6, `${status} is repeated 5 times`);
}
await assert.rejects(publicJson(U, async () => { throw new Error('network unavailable'); }, quiet()), /network unavailable/);
// A 403 followed by success is repeated; the waits double from 10 s without headers.
{
  let calls = 0; const waits = []; const logs = [];
  const fetcher = async () => (++calls < 3 ? { ok: false, status: 403 } : { ok: true, json: async () => valid });
  assert.deepEqual(await publicJson(U, fetcher, quiet({ sleep: async (ms) => waits.push(ms), log: (m) => logs.push(m) })), valid);
  assert.deepEqual(waits, [10000, 20000]);
  assert.equal(logs.length, 2);
  assert.match(logs[0], /HTTP 403; waiting 10 s before repeat 1 of 5/);
}
// Retry-After wins over X-RateLimit-Reset; X-RateLimit-Reset is read against the clock.
{
  const waits = [];
  const h = (map) => ({ get: (k) => map[k] ?? null });
  const responses = [
    { ok: false, status: 429, headers: h({ 'retry-after': '7', 'x-ratelimit-reset': '9999999999' }) },
    { ok: false, status: 403, headers: h({ 'x-ratelimit-reset': '1005' }) },
    { ok: true, json: async () => valid },
  ];
  await publicJson(U, async () => responses.shift(), quiet({ sleep: async (ms) => waits.push(ms), now: () => 1000000 }));
  assert.deepEqual(waits, [7000, 6000]);
}
// The token header is added only when GITHUB_TOKEN is set.
{
  const seen = [];
  const fetcher = async (_u, init) => { seen.push(init.headers.authorization); return { ok: true, json: async () => valid }; };
  await publicJson(U, fetcher, quiet({ env: { GITHUB_TOKEN: 'tok' } }));
  await publicJson(U, fetcher, quiet());
  assert.deepEqual(seen, ['Bearer tok', undefined]);
}
console.log('test-deployment-evidence: valid source/deployment/policy accepted; mismatches, pending status, 403/429 repeated with waits, token header only when set, unavailable evidence rejected');
