// Actual Git endpoints and same-run artifact checks, without browser/network.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {sameDocumentContract} from './lib/ci-markdown.mjs';
assert.equal(sameDocumentContract('# Title\n\nOld prose.', '# Title\n\nNew prose.'),true);
assert.equal(sameDocumentContract('# Old\n\n# Next\n', ':::note\n# Old\n:::\n\n# Next\n'),false);
assert.equal(sameDocumentContract('Old\nTitle\n=====\nbody','New\nTitle\n=====\nbody'),false);
const scripts=path.dirname(new URL(import.meta.url).pathname);
const root=fs.mkdtempSync(path.join(os.tmpdir(),'site-ci-contract-'));
const site=path.join(root,'site');
const git=(...args)=>execFileSync('git',['-C',root,...args],{encoding:'utf8'}).trim();
const write=(p,data)=>{const file=path.join(root,p);fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,data);};
const run=(name,args=[],env={})=>spawnSync(process.execPath,[path.join(scripts,name),...args],{cwd:site,encoding:'utf8',env:{...process.env,...env}});
try {
 git('init','-q');git('config','user.name','CI fixture');git('config','user.email','ci@example.invalid');
 write('site/package-lock.json','{}\n');write('docs/guide.md','# Guide\n\nOld prose.\n');
 git('add','.');git('commit','-qm','base');const base=git('rev-parse','HEAD');
 write('docs/guide.md','# Guide\n\nNew prose with [link](/docs/).\n');git('add','.');git('commit','-qm','prose');const head=git('rev-parse','HEAD');
 write('site/generated/pages.json',JSON.stringify([{source:'docs/guide.md',lang:'en',route:'guide'}]));
 for(const route of ['guide','ja/guide'])write(`site/dist/${route}/index.html`,'page');
 const env={EVENT_NAME:'push',REF_TYPE:'branch',PUSH_BEFORE:base};
 assert.equal(run('ci-plan.mjs',[],env).status,0);
 let plan=JSON.parse(fs.readFileSync(path.join(site,'generated/ci-scope.json')));
 assert.equal(plan.mode,'targeted');assert.deepEqual(plan.pages,['/guide/','/ja/guide/']);
 assert.equal(run('ci-plan.mjs',[],{...env,PUSH_BEFORE:'0'.repeat(40)}).status,0);
 assert.equal(JSON.parse(fs.readFileSync(path.join(site,'generated/ci-scope.json'))).mode,'full');
 assert.equal(run('ci-plan.mjs',[],{EVENT_NAME:'pull_request'}).status,0); // linear checkout is not a PR merge
 assert.equal(JSON.parse(fs.readFileSync(path.join(site,'generated/ci-scope.json'))).mode,'full');
 for(const file of ['docs-index.json','v2/docs-index.json']) write('site/dist/'+file,JSON.stringify({source_revision:head,working_tree_clean:true}));
 const identity={V2_REVISION:head,GITHUB_RUN_ID:'fixture-run'};
 assert.equal(run('ci-artifact.mjs',['--write'],identity).status,0);
 assert.equal(run('ci-artifact.mjs',[],identity).status,0);
 for(const patch of [{GITHUB_RUN_ID:'other-run'},{V2_REVISION:base}]) assert.notEqual(run('ci-artifact.mjs',[],{...identity,...patch}).status,0);
 write('site/package-lock.json','{"different":true}\n');assert.notEqual(run('ci-artifact.mjs',[],identity).status,0);
 write('site/package-lock.json','{}\n');write('site/dist/docs-index.json',JSON.stringify({source_revision:head,working_tree_clean:false}));
 assert.notEqual(run('ci-artifact.mjs',[],identity).status,0);
 console.log('Actual Git push range, absent merge parent, zero base and stale/dirty/lock/run/v2 artifact rejection: PASS');
} finally {fs.rmSync(root,{recursive:true});}
