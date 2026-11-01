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
const quiet = (extra = {}) => ({ env: {}, sleep: async () => {}, log: () => {}, waitBudget: { left: 1e9 }, ...extra });
const h = (map) => ({ get: (k) => map[k] ?? null });
assert.deepEqual(await publicJson(U, async () => ({ ok: true, json: async () => valid }), quiet()), valid);
// 404, 500 and a 403 for a missing permission (the reset header is on every response) are not repeated.
for (const [status, headers] of [[404, {}], [500, {}], [403, { 'x-ratelimit-remaining': '4999', 'x-ratelimit-reset': '9999999999' }], [403, { 'retry-after': '' }]]) {
  let calls = 0;
  await assert.rejects(publicJson(U, async () => { calls++; return { ok: false, status, headers: h(headers), json: async () => ({ message: 'Resource not accessible by integration' }) }; }, quiet()), /HTTP \d+: Resource not accessible by integration; deployment evidence is unavailable/);
  assert.equal(calls, 1, `${status} ${JSON.stringify(headers)} is not repeated`);
}
// 429 and a 403 with remaining 0 or Retry-After are repeated 5 times, then rejected.
for (const [status, headers] of [[429, {}], [403, { 'x-ratelimit-remaining': '0' }], [403, { 'retry-after': '1' }]]) {
  let calls = 0;
  await assert.rejects(publicJson(U, async () => { calls++; return { ok: false, status, headers: h(headers) }; }, quiet()), /evidence is unavailable/);
  assert.equal(calls, 6, `${status} ${JSON.stringify(headers)} is repeated 5 times`);
}
// A wait that does not fit in the budget fails at once with the reason.
{
  let calls = 0;
  await assert.rejects(publicJson(U, async () => { calls++; return { ok: false, status: 403, headers: h({ 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '9999999999' }) }; }, quiet({ waitBudget: { left: 240000 } })), /rate limited, and the wait of \d+ s does not fit in the 240 s left/);
  assert.equal(calls, 1);
}
await assert.rejects(publicJson(U, async () => { throw new Error('network unavailable'); }, quiet()), /network unavailable/);
// A 403 followed by success is repeated; the waits double from 60 s without headers.
{
  let calls = 0; const waits = []; const logs = [];
  const fetcher = async () => (++calls < 3 ? { ok: false, status: 429 } : { ok: true, json: async () => valid });
  assert.deepEqual(await publicJson(U, fetcher, quiet({ sleep: async (ms) => waits.push(ms), log: (m) => logs.push(m) })), valid);
  assert.deepEqual(waits, [60000, 120000]);
  assert.equal(logs.length, 2);
  assert.match(logs[0], /HTTP 429; waiting 60 s before repeat 1 of 5/);
}
// Retry-After wins over X-RateLimit-Reset; X-RateLimit-Reset is read against the clock.
{
  const waits = [];
  const responses = [
    { ok: false, status: 429, headers: h({ 'retry-after': '7', 'x-ratelimit-reset': '9999999999' }) },
    { ok: false, status: 403, headers: h({ 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '1005' }) },
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
