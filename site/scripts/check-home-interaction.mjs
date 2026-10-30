// Functional homepage checks: fixture routing, finite/reduced motion, code copy,
// disclosure and narrow-screen overflow. The illustration never calls an API.
import assert from 'node:assert/strict';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
const site = path.resolve(new URL('..', import.meta.url).pathname);
const server = await serve(path.join(site, 'dist'));
let count = 0;
try {
  for (const engine of [chromium, webkit]) {
    const browser = await engine.launch();
    try {
      for (const route of ['/', '/ja/']) for (const width of [320, 390, 768, 1440]) for (const reducedMotion of ['reduce', 'no-preference']) for (const colorScheme of ['light', 'dark']) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, colorScheme, reducedMotion,
          ...(engine === chromium ? { permissions: ['clipboard-read', 'clipboard-write'] } : {}) });
        const page = await context.newPage();
        await page.goto(server.url + route);
        await page.evaluate(() => document.fonts.ready);
        // Starlight initializes Pagefind in requestIdleCallback after load.
        // Wait for its input to exist before measuring the illustration's
        // requests; do not count that unrelated lazy module as route traffic.
        await page.locator('#starlight__search .pagefind-ui__search-input').waitFor({ state: 'attached' });
        const wire = page.locator('.flow-wire').first();
        assert.equal(await wire.isVisible(), width > 800, 'only the desktop request direction needs an arrow');
        assert.deepEqual(await page.locator('.home-v3 a').evaluateAll(links => links.filter(a => /[→↓]\s*$/.test(a.textContent)).map(a => a.textContent)), [], 'links use layout, not trailing arrows');
        const peerSizes = await page.locator('.flow-title').evaluateAll(headings => headings.map(el => getComputedStyle(el).fontSize));
        assert.equal(peerSizes.length, 3);
        assert.equal(new Set(peerSizes).size, 1, 'peer diagram headings share one type role');
        if (width > 800) {
          const tops = await page.locator('.flow-title').evaluateAll(headings => headings.map(el => el.getBoundingClientRect().top));
          assert.ok(Math.max(...tops) - Math.min(...tops) <= 1, 'peer diagram headings align');
        }
        assert.equal(await page.locator('.try-path[role=list] > [role=listitem]').count(), 3);
        assert.equal(await page.locator('.ruby-core ul').getAttribute('role'), 'list');
        const transform = await wire.evaluate(el => { const m = new DOMMatrix(getComputedStyle(el).transform); return [m.a, m.b, m.c, m.d]; });
        const requests = [];
        page.on('request', r => requests.push(r.url()));
        for (const model of ['a', 'b']) {
          await page.locator(`[data-model="${model}"]`).click();
          assert.equal(await page.locator('.v3-flow').getAttribute('data-route'), model);
          assert.equal(await page.locator(`[data-model="${model}"]`).getAttribute('aria-pressed'), 'true');
          assert.equal(await page.locator('.route-result').textContent(), `mock-model-${model} → agent_proxy_llm_${model}`);
          assert.deepEqual(await wire.evaluate(el => { const m = new DOMMatrix(getComputedStyle(el).transform); return [m.a, m.b, m.c, m.d]; }), transform, 'routing must preserve the request direction');
          if (reducedMotion === 'reduce') assert.equal(await page.evaluate(() => document.getAnimations().filter(a => a.playState === 'running').length), 0);
          else {
            // Freeze several points of the actual CSS animation. Text-bearing
            // route nodes must remain opaque, including in the light theme.
            const fadedText = await page.evaluate(() => {
              const animations = document.getAnimations().filter(a => a.effect?.target?.matches('.route-pulse'));
              const failures = [];
              for (const animation of animations) {
                animation.pause();
                for (const fraction of [0, .1, .5, .99]) {
                  animation.currentTime = Number(animation.effect.getTiming().duration) * fraction;
                  let opacity = 1;
                  for (let el = animation.effect.target; el; el = el.parentElement) opacity *= Number(getComputedStyle(el).opacity);
                  if (opacity < 1) failures.push({ fraction, opacity });
                }
                animation.finish();
              }
              return failures;
            });
            assert.deepEqual(fadedText, [], `${route} ${width} ${colorScheme}: route motion fades text`);
            await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running'));
          }
        }
        assert.deepEqual(requests, [], 'illustration sent a network request');
        await page.locator('.sample-output summary').click();
        assert.equal(await page.locator('.sample-output').getAttribute('open'), '');
        await page.locator('.sample-config summary').click();
        assert.equal(await page.locator('.sample-config').getAttribute('open'), '');
        for (const pre of await page.locator('.sample pre').all()) {
          assert.ok(await pre.evaluate(el => el.scrollWidth <= el.clientWidth + 1), `${route} ${width}: code requires horizontal scrolling`);
        }
        if (engine === chromium) {
          for (const button of await page.locator('.sample .copy button').all()) {
            const expected = (await button.getAttribute('data-code')).replaceAll('\x7f', '\n');
            await button.click();
            await page.waitForFunction(async expected => (await navigator.clipboard.readText()) === expected, expected);
          }
        }
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        await context.close(); count++;
      }
    } finally { await browser.close(); }
  }
} finally { await server.close(); }
console.log(`check-home-interaction: ${count} Chromium/WebKit viewports; route/no-network/disclosure/wrapping/reduced-motion pass; actual clipboard bytes checked in Chromium`);
