// Owner's code-reading requirement: every line fits without horizontal scrolling.
// Scan all generated pages at 320px, then stress representative code surfaces
// at phone/tablet/desktop widths and 200% text enlargement in both engines.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { scopedPages, codePageScope } from './lib/ci-pages.mjs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { loadSample } from './lib/samples.mjs';
const site = path.resolve(new URL('..', import.meta.url).pathname);
const dist = path.resolve(process.argv[2] || path.join(site, 'dist'));
const allPages = fs.readdirSync(dist, { recursive: true }).filter(p => /(^|\/)index\.html$/.test(p)).map(p => '/' + p.replace(/index\.html$/, ''));
const representatives = ['/', '/ja/', '/start/', '/ja/start/', '/guides/agent-proxy/', '/ja/guides/agent-proxy/', '/v2/', '/v2/ja/', '/v2/reference/ruby/', '/v2/ja/reference/ruby/'];
const {pages,stressPages} = codePageScope(allPages, representatives, scopedPages(dist), process.env.SITE_CI_VERSION);
const failures = [];
let count = 0;
const server = await serve(dist);
const sample = loadSample({ case: 'test/t/cases/agent_proxy.rb', conf: 'test/conf/conf.d/60-agent-proxy.conf', script: ['test/html/agent_proxy_route.rb'], compared: ['test/html/agent_proxy_route.expected'] }, path.dirname(site), 'code layout check');
const canonical = new Set(sample.shown.map(item => item.text.replace(/\n$/, '')));
async function inspect(page, label) {
  const errors = await page.evaluate(() => {
    const errors = [];
    for (const el of document.querySelectorAll('pre, .expressive-code .ec-line .code, .home-v3 code')) {
      if (!el.getClientRects().length) continue;
      // Inline code can span lines; its parent owns the available width.
      if (getComputedStyle(el).display === 'inline') continue;
      if (el.scrollWidth > el.clientWidth + 1) errors.push(`${el.tagName}.${el.className}: ${el.scrollWidth} > ${el.clientWidth}`);
      if (el.scrollHeight > el.clientHeight + 1) errors.push(`${el.tagName}: vertical clipping`);
    }
    for (const pre of document.querySelectorAll('.home-v3 .expressive-code pre')) {
      if (!pre.getClientRects().length) continue;
      const frame = pre.closest('.frame').getBoundingClientRect();
      const box = pre.getBoundingClientRect();
      if (box.left < frame.left - 1 || box.right > frame.right + 1) errors.push('code plane extends beyond its frame');
    }
    for (const header of document.querySelectorAll('.expressive-code .frame .header')) {
      if (!header.getClientRects().length) continue;
      const frame = header.closest('.frame').getBoundingClientRect();
      const box = header.getBoundingClientRect();
      if (Math.abs(box.left - frame.left) > 1 || Math.abs(box.right - frame.right) > 1) errors.push('code header does not span its frame');
    }
    if (document.documentElement.scrollWidth > innerWidth + 1) errors.push('page overflow');
    return errors;
  });
  failures.push(...errors.map(e => `${label}: ${e}`)); count++;
}
try {
  for (const engine of [chromium, webkit]) {
    const browser = await engine.launch();
    const context = await browser.newContext({ viewport: { width: 320, height: 900 }, colorScheme: 'dark', ...(engine === chromium ? { permissions: ['clipboard-read', 'clipboard-write'] } : {}) });
    const page = await context.newPage();
    try {
      for (const route of pages) {
        await page.goto(server.url + route);
        await page.evaluate(() => { document.querySelectorAll('details').forEach(el => { el.open = true; }); });
        await inspect(page, `${engine.name()} ${route} 320`);
      }
      for (const route of stressPages) for (const width of [320, 390, 768, 1440]) for (const enlarged of [false, true]) {
        await page.setViewportSize({ width, height: 900 });
        await page.goto(server.url + route);
        await page.evaluate(enlarged => {
          document.querySelectorAll('details').forEach(el => { el.open = true; });
          if (enlarged) {
            const sizes = [...document.querySelectorAll('pre, pre > code, .home-v3 code')].map(el => [el, parseFloat(getComputedStyle(el).fontSize)]);
            for (const [el, size] of sizes) el.style.fontSize = `${size * 2}px`;
            for (const [el, size] of sizes) if (Math.abs(parseFloat(getComputedStyle(el).fontSize) - size * 2) > 0.01) throw new Error('code text was not enlarged to 200%');
          }
        }, enlarged);
        await inspect(page, `${engine.name()} ${route} ${width} enlarged=${enlarged}`);
        // Keyboard activation and raw clipboard bytes, checked against source
        // files (not merely against the rendered button's own data attribute).
        if ((route === '/' || route === '/ja/') && !enlarged && engine === chromium) {
          for (const button of await page.locator('.sample .copy button').all()) {
            const raw = (await button.getAttribute('data-code')).replaceAll('\x7f', '\n');
            assert.ok(canonical.has(raw), 'sample copy differs from its canonical source');
            await button.focus();
            assert.equal(await button.evaluate(el => el === document.activeElement), true);
            await page.keyboard.press('Enter');
            await page.waitForFunction(async raw => await navigator.clipboard.readText() === raw, raw);
          }
        }
        // URL/token with no convenient word boundary: keep the actual line
        // structure/styles, changing only text in a temporary browser document.
        await page.evaluate(() => {
          const line = document.querySelector('.expressive-code .ec-line .code');
          if (line) line.textContent = 'https://example.invalid/' + 'longtoken'.repeat(40);
        });
        await inspect(page, `${engine.name()} ${route} ${width} long token enlarged=${enlarged}`);
      }
    } finally { await context.close(); await browser.close(); }
  }
} finally { await server.close(); }
assert.deepEqual(failures, [], `code layout failures (${failures.length}):\n${failures.slice(0, 30).join('\n')}`);
console.log(`check-code-layout: ${count} page conditions; ${pages.length} selected pages, EN/JA where selected, 320/390/768/1440, 200% code text, long tokens; canonical clipboard and keyboard activation passed`);
