// API names must reach their reference pages, independently of homepage samples.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { distDir } from './lib/site.mjs';
import { serve } from './lib/serve.mjs';
const server = await serve(process.argv[2] ?? distDir);
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
      ['"zzqv_zzqw_74931"', null],
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
    try {
      await page.locator('button[data-open-modal]').click();
      await page.locator('#starlight__search input').fill('mruby_content_handler');
      const metadata = page.locator('[data-pagefind-ui-meta="identifiers"]').first();
      await metadata.waitFor({ state: 'attached', timeout: 15000 });
      assert.equal(await metadata.isVisible(), false, `${prefix || '/'}: indexing metadata must not become a visible result tag`);
      checks++;
    } catch (error) { failures.push(error.message); }
    await page.close();
  }
} finally { await browser.close(); await server.close(); }
if (failures.length) { console.error(failures.join('\n')); process.exitCode = 1; }
console.log(`check-search-identifiers: ${checks}/16 exact-reference, negative and search-presentation checks passed`);
