import fs from 'node:fs';
import path from 'node:path';
import { publicJson, deploymentProblems } from './lib/deployment-evidence.mjs';

const args = process.argv.slice(2);
let dist = path.resolve(new URL('../dist', import.meta.url).pathname);
let expectedSha;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--sha' && args[i + 1]) expectedSha = args[++i];
  else throw new Error(`unknown argument ${args[i]}`);
}
if (!/^[0-9a-f]{40}$/.test(expectedSha ?? '')) throw new Error('--sha must identify the exact deployed commit');
const base = 'https://api.github.com/repos/matsumotory/ngx_mruby/';
const artifact = JSON.parse(fs.readFileSync(path.join(dist, 'docs-index.json'), 'utf8'));
const environment = await publicJson(base + 'environments/github-pages');
const policies = await publicJson(base + 'environments/github-pages/deployment-branch-policies');
const deployments = await publicJson(base + 'deployments?environment=github-pages&per_page=1');
const deployment = deployments[0];
const statuses = deployment ? await publicJson(base + `deployments/${deployment.id}/statuses?per_page=1`) : [];
const problems = deploymentProblems({ expectedSha, artifact, environment, policies, deployment, statuses });
for (const problem of problems) console.error(problem);
if (problems.length) process.exit(1);
console.log(`check-public-deployment: artifact ${artifact.source_revision}; deployment ${deployment.id}, ${deployment.ref}@${deployment.sha}; success; github-pages allows only branch:next`);
