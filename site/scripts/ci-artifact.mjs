// Same-run artifact identity, not a cross-head cache. Reject stale/dirty builds.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
const sha=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
const digest=crypto.createHash('sha256').update(fs.readFileSync('package-lock.json')).digest('hex');
const identity={source:sha,v2:process.env.V2_REVISION,lock:digest,run:process.env.GITHUB_RUN_ID};
assert.match(identity.source,/^[0-9a-f]{40}$/);
assert.match(identity.v2 || '',/^[0-9a-f]{40}$/);
assert.ok(identity.run,'missing run identity');
for(const [file,expected] of [['dist/docs-index.json',sha],['dist/v2/docs-index.json',identity.v2]]) {
 const index=JSON.parse(fs.readFileSync(file,'utf8'));
 assert.equal(index.source_revision,expected,file);
 assert.equal(index.working_tree_clean,true,file);
}
if(process.argv[2]==='--write') fs.writeFileSync('generated/ci-identity.json',JSON.stringify(identity)+'\n');
else assert.deepEqual(JSON.parse(fs.readFileSync('generated/ci-identity.json','utf8')),identity);
console.log('Exact clean same-run artifact identity verified:',identity.source,identity.v2);
