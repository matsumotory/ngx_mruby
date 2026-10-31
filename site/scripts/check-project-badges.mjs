// Offline markup validation by default. --browser additionally checks the
// footer at 375 px with the badge served from a local stand-in (never from
// bestpractices.dev): decoding, geometry, keyboard focus and light/dark
// pixels, in five states. check-live.mjs fetches the real image after the
// deploy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent } from './lib/html.mjs';
import { htmlFiles } from './lib/site.mjs';
import { OPENSSF_BADGE, OPENSSF_BADGE_FIXTURE } from './lib/project-badges.mjs';
const args = process.argv.slice(2);
let browserCheck = false, dist = path.resolve('dist'), out = path.resolve('build-screenshots/badges');
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--browser') browserCheck = true;
  else if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--out' && args[i + 1]) out = path.resolve(args[++i]);
  else throw new Error(`unknown argument ${args[i]}`);
}
const pages = htmlFiles(dist, { v2: true });
assert.ok(pages.length, 'built HTML is required');
for (const file of pages) {
  const all = elements(readHtml(path.join(dist, file)));
  const footer = all.find(el => hasClass(el, 'site-footer'));
  assert.ok(footer, `${file}: shared footer missing`);
  const links = elements(footer).filter(el => el.tagName === 'a');
  const badges = links.filter(el => hasClass(el, 'project-badge'));
  assert.equal(badges.length, 1, `${file}: exactly one project badge`);
  assert.equal(badges[0].properties.href, OPENSSF_BADGE.href, file);
  const images = elements(badges[0]).filter(el => el.tagName === 'img');
  assert.equal(images.length, 1, file);
  for (const key of ['src', 'alt', 'width', 'height']) assert.equal(String(images[0].properties[key]), String(OPENSSF_BADGE[key]), `${file}: ${key}`);
  assert.equal(images[0].properties.referrerPolicy, 'no-referrer', `${file}: badge referrer policy`);
  const ref = file.startsWith('v2/') ? 'master' : 'next';
  assert.ok(links.some(el => el.properties.href === `https://github.com/matsumotory/ngx_mruby/blob/${ref}/LICENSE` && textContent(el) === 'MIT'), `${file}: real MIT license link`);
}
console.log(`check-project-badges: ${pages.length} footers have the exact OpenSSF image/link/alt and version-appropriate LICENSE link; no external fetch in this static check`);
if (browserCheck) {
  const { chromium, webkit } = await import('playwright');
  const { serve } = await import('./lib/serve.mjs');
  const { readOnlyContext } = await import('./lib/read-only-browser.mjs');
  const server = await serve(dist);
  fs.mkdirSync(out, { recursive: true });
  const records = [];
  let complete = false;
  try {
    // One footer component serves every page: v3 English and v2 Japanese in
    // Chromium in both themes, and one WebKit state for its Option-Tab focus.
    const states = [
      ...['/', '/v2/ja/'].flatMap(route => ['light', 'dark'].map(colorScheme => ({ engineName: 'chromium', route, colorScheme }))),
      { engineName: 'webkit', route: '/ja/', colorScheme: 'light' },
    ];
    const width = 375;
    for (const engineName of ['chromium', 'webkit']) {
      const browser = await { chromium, webkit }[engineName].launch();
      try {
        for (const { route, colorScheme } of states.filter(state => state.engineName === engineName)) {
          const { context, blocked, close } = await readOnlyContext(browser, server.url, { viewport: { width, height: 664 }, colorScheme }, { [OPENSSF_BADGE.src]: OPENSSF_BADGE_FIXTURE });
          try {
            const page = await context.newPage();
            const errors = [];
            page.on('pageerror', error => errors.push(error.message));
            await page.goto(server.url + route, { waitUntil: 'load' });
            const badge = page.locator('.project-badge');
            await badge.scrollIntoViewIfNeeded();
            await page.evaluate(() => document.fonts.ready);
            // Lazy image fetch starts after intersection; WebKit may reject
            // decode() while that fetch has not yet produced an image.
            await page.waitForFunction(() => {
              const image = document.querySelector('.project-badge img');
              return image.complete && image.naturalWidth > 0;
            });
            const image = await badge.locator('img').evaluate(async el => {
              await el.decode();
              const r = el.getBoundingClientRect();
              return { complete: el.complete, naturalWidth: el.naturalWidth, naturalHeight: el.naturalHeight, left: r.left, right: r.right, width: r.width, height: r.height };
            });
            assert.ok(image.complete && image.naturalWidth > 0 && image.naturalHeight > 0, 'badge image must decode');
            assert.ok(image.left >= 0 && image.right <= width, `${route}: badge clips at ${width}`);
            assert.ok(Math.abs(image.width / image.height - image.naturalWidth / image.naturalHeight) < 0.02, 'badge aspect ratio');
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'no horizontal page scroll');
            await page.locator('.site-footer a[href="https://github.com/matsumotory/ngx_mruby"]').focus();
            // Match check-focus.mjs: WebKit's native link navigation uses
            // Option-Tab; plain Tab visits form controls by default.
            await page.keyboard.press(engineName === 'webkit' ? 'Alt+Tab' : 'Tab', { delay: 60 });
            assert.equal(await badge.evaluate(el => el === document.activeElement), true, 'badge is keyboard reachable');
            const name = `${engineName}-${route.replaceAll('/', '-').replace(/^-|-$/g, '') || 'home'}-${colorScheme}-${width}.png`;
            await page.screenshot({ path: path.join(out, name) });
            assert.deepEqual(blocked, [], 'only same-origin GET and the badge stand-in are allowed');
            assert.deepEqual(errors, [], 'no page exception');
            records.push({ route, engine: engineName, width, colorScheme, image, file: name });
          } catch (error) {
            console.error(`check-project-badges state: ${engineName} ${route} ${colorScheme}; ${records.length}/${states.length} complete`);
            throw error;
          } finally { await close(); }
        }
      } finally { await browser.close(); }
    }
    complete = true;
  } finally {
    try { await server.close(); } catch (error) { complete = false; throw error; }
    finally {
      const manifest = JSON.parse(fs.readFileSync(path.join(dist, 'docs-index.json'), 'utf8'));
      const v2 = JSON.parse(fs.readFileSync(path.join(dist, 'v2/docs-index.json'), 'utf8'));
      fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify({ source_revision: manifest.source_revision, v2_source_revision: v2.source_revision, working_tree_clean: manifest.working_tree_clean, complete: complete && records.length === 5, pages: records }, null, 2) + '\n');
    }
  }
  console.log(`check-project-badges: ${records.length} footer/focus checks and screenshots at 375 px with the local badge stand-in (Chromium: / and /v2/ja/, light and dark; WebKit: /ja/ light)`);
}
