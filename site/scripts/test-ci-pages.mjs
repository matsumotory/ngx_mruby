// The optional page set of the browser checks (lib/ci-pages.mjs) and the
// notice pages of a partial Japanese line check, without a browser.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {scopedPages,codePageScope} from './lib/ci-pages.mjs';
import {japaneseNoticePages} from './lib/site.mjs';

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'ci-pages-'));
try {
  fs.mkdirSync(path.join(dir,'docs'));fs.writeFileSync(path.join(dir,'docs/index.html'),'ok');
  assert.equal(scopedPages(dir,undefined),null);
  assert.deepEqual(scopedPages(dir,'["/docs/"]'),['/docs/']);
  for(const value of ['[]','null','{}','["/docs/","/docs/"]','["/missing/"]','["/../docs/"]','["//docs/"]']) assert.throws(()=>scopedPages(dir,value));
} finally {fs.rmSync(dir,{recursive:true});}
console.log('Page sets: missing means every page; malformed, empty and missing routes fail: PASS');

// A partial Japanese line check measures the fallback pages under /ja/
// (English text with a notice) as a full run does: their notice only.
assert.deepEqual(japaneseNoticePages(['/ja/contributing/handoff/','/ja/guides/install/','/ja/reference/directives/','/v2/ja/','/contributing/handoff/']),['/ja/contributing/handoff/','/ja/reference/directives/']);
console.log('Notice pages of a partial Japanese line check: PASS');

const all=['/','/ja/','/start/','/v2/','/v2/ja/','/v2/reference/ruby/'];
const reps=['/','/v2/'];
const v3=codePageScope(all,reps,null,'3'),v2=codePageScope(all,reps,null,'2');
assert.deepEqual([...v3.pages,...v2.pages].sort(),[...all].sort());
assert.deepEqual([...v3.stressPages,...v2.stressPages].sort(),[...reps].sort());
assert.deepEqual(codePageScope(all,reps,null),{pages:all,stressPages:reps});
assert.deepEqual(codePageScope(all,reps,['/start/'],'3'),{pages:['/start/'],stressPages:['/start/']});
assert.throws(()=>codePageScope(all,reps,null,'invalid'));
console.log('The two versions of check-code-layout.mjs add up to every page: PASS');
