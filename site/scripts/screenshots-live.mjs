// A small, read-only production smoke check: twelve page visits, no form
// submission, provider request, search query or load/performance loop.
// --local exercises the same code against the artifact in pre-deploy CI.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { serve } from './lib/serve.mjs';
import { readOnlyContext } from './lib/read-only-browser.mjs';
import { OPENSSF_BADGE } from './lib/project-badges.mjs';

const site = path.resolve(new URL('..', import.meta.url).pathname);
let dist = path.join(site, 'dist'), out = path.join(site, 'live-screenshots'), local = false;
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--out' && args[i + 1]) out = path.resolve(args[++i]);
  else if (args[i] === '--local') local = true;
  else throw new Error(`unknown argument ${args[i]}`);
}
const manifest = JSON.parse(fs.readFileSync(path.join(dist, 'docs-index.json'), 'utf8'));
const v2Manifest = JSON.parse(fs.readFileSync(path.join(dist, 'v2/docs-index.json'), 'utf8'));
const server = local ? await serve(dist) : null;
const origin = server?.url ?? 'https://ngx.mruby.org';
fs.mkdirSync(out, { recursive: true });
const records = [];
let browser;
let complete = false;
try {
  browser = await chromium.launch();
  for (const lang of ['en', 'ja']) for (const width of [390, 1440]) {
    const pages = [
      ['home', lang === 'ja' ? '/ja/' : '/'],
      ['v2-entry', lang === 'ja' ? '/v2/ja/' : '/v2/'],
      ...(width === 390 ? [['start', lang === 'ja' ? '/ja/start/' : '/start/'], ['docs', lang === 'ja' ? '/ja/docs/' : '/docs/']] : []),
    ];
    const { context, blocked, close } = await readOnlyContext(browser, origin, { viewport: { width, height: width < 640 ? 664 : 900 }, colorScheme: 'dark', deviceScaleFactor: 1 }, [OPENSSF_BADGE.src]);
    const errors = [];
    let closing = false;
    try {
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      page.on('response', response => { if (response.status() >= 400) errors.push(`HTTP ${response.status()} ${response.url()}`); });
      page.on('requestfailed', request => { if (!closing) errors.push(`${request.failure()?.errorText} ${request.url()}`); });
      for (const [id, route] of pages) {
        const response = await page.goto(origin + route, { waitUntil: 'load' });
        assert.equal(response.status(), 200, route);
        assert.ok((await response.body()).equals(fs.readFileSync(path.join(dist, route.slice(1), 'index.html'))), `${route}: live HTML differs from the verified artifact`);
        await page.evaluate(() => document.fonts.ready);
        const base = `${id}-${lang}-${width}`;
        await page.screenshot({ path: path.join(out, `${base}-first.png`) });
        await page.locator('.project-badge').scrollIntoViewIfNeeded();
        await page.waitForFunction(() => {
          const image = document.querySelector('.project-badge img');
          return image.complete && image.naturalWidth > 0;
        });
        await page.locator('.project-badge img').evaluate(async image => {
          await image.decode();
          if (!image.complete || image.naturalWidth === 0) throw new Error('footer badge did not load');
        });
        await page.screenshot({ path: path.join(out, `${base}-footer.png`) });
        await page.screenshot({ path: path.join(out, `${base}-full.png`), fullPage: true });
        if (id === 'home') {
          await page.locator('.route-controls button[data-model="b"]').click();
          assert.equal(await page.locator('.v3-flow').getAttribute('data-route'), 'b');
          await page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
          await page.locator('.route-result:visible').scrollIntoViewIfNeeded();
          await page.screenshot({ path: path.join(out, `${base}-model-b-result.png`) });
        }
        assert.deepEqual(blocked, [], 'unexpected request outside the read-only page/badge boundary was blocked');
        assert.deepEqual(errors, [], 'page exception or failed resource request');
        records.push({ route, width, height: width < 640 ? 664 : 900, html_matches_artifact: true, files: base });
      }
    } finally {
      closing = true;
      await close();
      assert.deepEqual(blocked, [], 'unexpected network activity before the verification context closed');
      assert.deepEqual(errors, [], 'page/resource errors before the verification context closed');
    }
  }
  complete = true;
} finally {
  await browser?.close();
  await server?.close();
  fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify({ origin, source_revision: manifest.source_revision, v2_source_revision: v2Manifest.source_revision, working_tree_clean: manifest.working_tree_clean, captured_at: new Date().toISOString(), complete: complete && records.length === 12, pages: records }, null, 2) + '\n');
}
console.log(`screenshots-live: ${records.length} read-only page visits at ${origin}; exact artifact HTML matched; desktop/mobile pixels saved for independent review`);
