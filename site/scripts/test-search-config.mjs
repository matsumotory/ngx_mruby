import assert from 'node:assert/strict';
import fs from 'node:fs';
import { pagefindOptions } from '../src/search-config.mjs';
import { writeSearchIndex } from './lib/search-index.mjs';
assert.deepEqual(pagefindOptions.ranking, { pageLength:.1,termFrequency:.1,termSaturation:2,termSimilarity:9,diacriticSimilarity:.8 });
const config=fs.readFileSync(new URL('../astro.config.mjs',import.meta.url),'utf8');
const ui=fs.readFileSync(new URL('../src/own/Search.astro',import.meta.url),'utf8');
assert.doesNotMatch(config,/@astrojs\/starlight|NGX_MRUBY_SITE_SHELL/);
assert.match(ui,/new PagefindUI\(\{\s*\.\.\.pagefindOptions,/);
for(const fail of [null,'create','add','write']) {
 const calls=[];
 const response=stage=>{calls.push(stage);return {errors:stage===fail?['injected failure']:[]};};
 const index={addDirectory:async()=>response('add'),writeFiles:async()=>response('write')};
 const api={createIndex:async()=>({...response('create'),index}),close:async()=>calls.push('close')};
 const run=writeSearchIndex(new URL('file:///tmp/site-search-fixture/'),api);
 if(fail)await assert.rejects(run,/injected failure/);else await run;
 assert.equal(calls.at(-1),'close');assert.equal(calls.filter(x=>x==='close').length,1);
}
console.log('search options and Pagefind cleanup fixtures passed');
