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
assert.deepEqual(await publicJson('https://api.github.com/example', async () => ({ ok: true, json: async () => valid })), valid);
for (const status of [403, 404, 429, 500]) await assert.rejects(publicJson('https://api.github.com/example', async () => ({ ok: false, status })), /evidence is unavailable/);
await assert.rejects(publicJson('https://api.github.com/example', async () => { throw new Error('network unavailable'); }), /network unavailable/);
console.log('test-deployment-evidence: valid source/deployment/policy accepted; mismatches, pending status, rate limits and unavailable evidence rejected');
