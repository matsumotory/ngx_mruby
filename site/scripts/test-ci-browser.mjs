import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {commandsFor,LANES,siteGate} from './ci-browser.mjs';
import {scopedPages,codePageScope} from './lib/ci-pages.mjs';
import {japaneseNoticePages} from './lib/site.mjs';
const full={mode:'full',pages:[]}, target={mode:'targeted',pages:['/guides/install/','/ja/guides/install/']};
assert.equal(LANES.length,6);
assert.deepEqual(commandsFor(full,'styles-chromium'),[['check-styles.mjs','--engine','chromium']]);
assert.deepEqual(commandsFor(full,'styles-webkit'),[['check-styles.mjs','--engine','webkit']]);
assert.deepEqual(commandsFor(full,'interaction'),[['check-copy-idle.mjs'],['check-home-interaction.mjs'],['check-code-layout.mjs']]);
assert.deepEqual(commandsFor(target,'interaction'),[['check-code-layout.mjs']]);
assert.deepEqual(commandsFor(target,'japanese'),[['check-japanese-lines.mjs','--pages','/ja/guides/install/']]);
assert.deepEqual(commandsFor(full,'screenshots'),[['check-project-badges.mjs','--browser'],['screenshots.mjs','--out','build-screenshots']]);
// The badge's 375px acceptance is covered by check-project-badges --browser,
// not a new width requirement for the style lanes or existing docs prose.
assert.deepEqual(commandsFor(full,'japanese'),[['check-japanese-lines.mjs']]);
assert.deepEqual(commandsFor(target,'styles-chromium'),[['check-styles.mjs','--engine','chromium']]);
assert.deepEqual(commandsFor(target,'screenshots'),[['ci-screenshots.mjs','--out','build-screenshots']]);
for(const lane of LANES) assert.deepEqual(commandsFor({mode:'none',pages:[]},lane),[]);
assert.throws(()=>commandsFor({mode:'targeted',pages:[]},'interaction'));
assert.throws(()=>commandsFor(full,'bad'));
assert.throws(()=>commandsFor({mode:'typo'},'interaction'));
const success={build:'success',browserNeeded:'true',browser:'success',maintenance:'success'};
assert.ok(siteGate(success));
for(const key of ['build','browser','maintenance']) for(const value of ['skipped','failure','cancelled','',undefined]) assert.equal(siteGate({...success,[key]:value}),false);
// A skip of the lanes passes only when the build job decided it.
const notNeeded={build:'success',browserNeeded:'false',browser:'skipped',maintenance:'skipped'};
assert.ok(siteGate(notNeeded));
for(const key of ['build','browser','maintenance']) for(const value of ['success','failure','cancelled','',undefined]) if(!(key==='build'&&value==='success')) assert.equal(siteGate({...notNeeded,[key]:value}),false);
for(const value of ['','yes',undefined]) {assert.equal(siteGate({...success,browserNeeded:value}),false);assert.equal(siteGate({...notNeeded,browserNeeded:value}),false);}
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ci-pages-'));
try {
 fs.mkdirSync(path.join(dir,'docs'));fs.writeFileSync(path.join(dir,'docs/index.html'),'ok');
 assert.deepEqual(scopedPages(dir,'["/docs/"]'),['/docs/']);
 for(const value of ['[]','null','{}','["/docs/","/docs/"]','["/missing/"]','["/../docs/"]','["//docs/"]']) assert.throws(()=>scopedPages(dir,value));
} finally {fs.rmSync(dir,{recursive:true});}
// A targeted Japanese line check measures the fallback pages under /ja/
// (English text with a notice) as a full run does: their notice only.
assert.deepEqual(japaneseNoticePages(['/ja/contributing/handoff/','/ja/guides/install/','/ja/reference/directives/','/v2/ja/','/contributing/handoff/']),['/ja/contributing/handoff/','/ja/reference/directives/']);
console.log('CI lane coverage, malformed scopes, route existence, failure/cancel/skip gate contracts: PASS');

const all=['/','/ja/','/start/','/v2/','/v2/ja/','/v2/reference/ruby/'];
const reps=['/','/v2/'];
const v3=codePageScope(all,reps,null,'3'),v2=codePageScope(all,reps,null,'2');
assert.deepEqual([...v3.pages,...v2.pages].sort(),[...all].sort());
assert.deepEqual([...v3.stressPages,...v2.stressPages].sort(),[...reps].sort());
assert.deepEqual(codePageScope(all,reps,['/start/'],'3'),{pages:['/start/'],stressPages:['/start/']});
assert.throws(()=>codePageScope(all,reps,null,'invalid'));
console.log('Version sharding preserves the exact full code-layout union: PASS');
const workflow=fs.readFileSync(new URL('../../.github/workflows/site.yml',import.meta.url),'utf8');
assert.ok(workflow.includes('lane: ['+LANES.join(', ')+']'));
assert.ok(workflow.includes('needs: [build, browser, maintenance-lines]'));
assert.ok(workflow.includes('BROWSER_NEEDED: ${{ needs.build.outputs.browser }}'));
assert.equal(workflow.split("if: needs.build.outputs.browser == 'true'").length,3);
assert.ok(workflow.includes('needs: [build, site-ok]'));
assert.ok(workflow.includes('digest-mismatch: error'));
assert.ok(workflow.includes('node scripts/check-v2.mjs --no-browser'));
assert.ok(workflow.includes('SITE_CI_VERSION=2 node scripts/check-code-layout.mjs'));
assert.ok(workflow.includes('node scripts/check-search-identifiers.mjs'));
assert.ok(workflow.includes('node scripts/ci-artifact.mjs --write'));
assert.ok(workflow.includes('node scripts/ci-artifact.mjs\n'));
console.log('Workflow suite wiring and exact-artifact/deployment gate contracts: PASS');

const maintenance=workflow.split('  maintenance-lines:')[1].split('  site-ok:')[0];
assert.ok(maintenance.includes('name: site-validation'));
assert.ok(maintenance.includes('tar -xzf'));
assert.ok(maintenance.includes('node scripts/ci-artifact.mjs'));
console.log('Maintenance suite receives bound generated manifests as well as HTML: PASS');

// The latest publication safety checks must survive workflow decomposition.
assert.ok(maintenance.includes('node scripts/test-read-only-browser.mjs'));
assert.ok(maintenance.includes('node scripts/screenshots-live.mjs --local --out build-screenshots/predeploy-smoke'));
assert.ok(workflow.includes('  verify-live:'));
assert.ok(workflow.includes('node scripts/check-public-deployment.mjs --sha'));
assert.ok(workflow.includes('node scripts/check-live.mjs --no-gh'));
assert.ok(workflow.includes('measure_scope: ${{ steps.scope.outputs.measure_scope }}'));
console.log('Publication regression checks and policy-only measurement wiring: PASS');

assert.ok(workflow.includes('node scripts/check-project-badges.mjs'));
console.log('Quality badge markup and 375px footer checks remain wired after lane integration: PASS');
