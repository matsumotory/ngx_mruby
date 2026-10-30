// API names must reach their reference pages, independently of homepage samples.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { distDir } from './lib/site.mjs';
import { serve } from './lib/serve.mjs';
const server = await serve(distDir);
const browser = await chromium.launch();
const failures = [];
let checks = 0;
try {
  for (const prefix of ['', '/ja', '/v2', '/v2/ja']) {
    const page = await browser.newPage();
    await page.goto(`${server.url}${prefix}/reference/directives/`);
    const bundle = prefix.startsWith('/v2') ? '/v2/pagefind/pagefind.js' : '/pagefind/pagefind.js';
    for (const [term, target] of [
      ['mruby_content_handler', '/reference/directives/'],
      ['Nginx::Request', '/reference/ruby/'],
      ['zzqv_zzqw_74931', null],
    ]) {
      try {
        const urls = await page.evaluate(async ({ bundle, term }) => {
          const index = await import(bundle);
          const result = await index.search(term);
          return Promise.all(result.results.map(async item => new URL((await item.data()).url, location.href).pathname));
        }, { bundle, term });
        if (target) assert.ok(urls.includes(prefix + target), `${prefix || '/'}: ${term} must reach ${prefix + target}`);
        else assert.equal(urls.length, 0, `${prefix || '/'}: unknown identifier must not return unrelated pages`);
        assert.ok(urls.every(url => prefix.startsWith('/v2') ? url.startsWith('/v2/') : !url.startsWith('/v2/')), 'versions must remain separate');
        checks++;
      } catch (error) { failures.push(error.message); }
    }
    await page.close();
  }
} finally { await browser.close(); await server.close(); }
if (failures.length) { console.error(failures.join('\n')); process.exitCode = 1; }
console.log(`check-search-identifiers: ${checks}/12 exact-reference and negative searches passed`);
