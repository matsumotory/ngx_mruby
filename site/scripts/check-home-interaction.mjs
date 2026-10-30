// One executable local example: request model -> verbatim Ruby mapping ->
// selected upstream/credential -> mock response. The browser sends no API call.
// Preserve source copies, keyboard control, finite/reduced motion and wrapping.
import assert from 'node:assert/strict';
import path from 'node:path';
import fs from 'node:fs';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { loadSample } from './lib/samples.mjs';
const site = path.resolve(new URL('..', import.meta.url).pathname);
const server = await serve(path.join(site, 'dist'));
let count = 0;
const repo = path.dirname(site);
const handler = fs.readFileSync(path.join(repo, 'examples/start/route.rb'), 'utf8');
const canonicalMapping = handler.slice(handler.indexOf('  routes = {'), handler.indexOf('\n  begin')).trimEnd();
const walkthrough = fs.readFileSync(path.join(repo, 'examples/start/README.md'), 'utf8');
const canonicalStart = walkthrough.match(/```console\n([\s\S]*?)\n```/)[1].split('\n').filter(line => line.startsWith('$ ')).map(line => line.slice(2)).join('\n');
const sample = loadSample({ case: 'test/t/cases/agent_proxy.rb', conf: 'test/conf/conf.d/60-agent-proxy.conf', script: ['test/html/agent_proxy_route.rb'], compared: ['test/html/agent_proxy_route.expected'] }, repo, 'homepage interaction');
const canonicalSamples = new Set(sample.shown.map(item => item.text.replace(/\n$/, '')));
async function copyExact(page, button, expected) {
  assert.equal((await button.getAttribute('data-code')).replaceAll('\x7f', '\n'), expected, 'copy data differs from canonical source');
  await button.click();
  await page.waitForFunction(async expected => (await navigator.clipboard.readText()) === expected, expected);
}
async function openDisclosure(page, selector) {
  const summary = page.locator(`${selector} > summary`);
  assert.equal(await page.locator(selector).evaluate(el => el.open), false, `${selector} starts closed`);
  await summary.click();
  // Wait for the native details state, not an immediate string attribute read.
  // Do not set the property or retry a click to manufacture an open state.
  await page.waitForFunction(selector => document.querySelector(selector).open, selector);
  await summary.focus();
  await page.keyboard.press('Enter');
  await page.waitForFunction(selector => !document.querySelector(selector).open, selector);
  await summary.click();
  await page.waitForFunction(selector => document.querySelector(selector).open, selector);
}
const codeText = locator => locator.locator('.ec-line').allTextContents().then(lines => lines.join('\n'));
async function assertRoute(page, model) {
  assert.equal(await page.locator('.v3-flow').getAttribute('data-route'), model);
  assert.equal(await page.locator('.route-controls [aria-pressed="true"]').count(), 1);
  assert.equal(await page.locator(`[data-model="${model}"]`).getAttribute('aria-pressed'), 'true');
  assert.deepEqual(JSON.parse(await page.locator('.request-model').textContent()), { model: `mock-model-${model}` });
  assert.equal(await page.locator('.provider-node:visible').count(), 1);
  const provider = page.locator(`[data-provider="${model}"]`);
  assert.ok(await provider.isVisible());
  assert.equal(await provider.locator('code').first().textContent(), `local_api_${model}`);
  assert.equal(await provider.locator('.provider-credential').textContent(), `Authorization: Bearer local-upstream-${model}`);
  assert.equal(await page.locator('.route-result:visible').count(), 1);
  assert.deepEqual(JSON.parse(await codeText(page.locator(`[data-response="${model}"] pre`))), {
    upstream: model, model: `mock-model-${model}`, credential_replaced: true,
  });
  const selectedLine = page.locator(`.route-selection[data-rule="${model}"]`);
  assert.equal(await page.locator('.route-selection:visible').count(), 1);
  assert.ok(await selectedLine.isVisible(), 'the selected rule stays next to its result');
  assert.ok((await selectedLine.textContent()).includes(`"mock-model-${model}" => ["local_api_${model}", "Bearer local-upstream-${model}"]`));

}
try {
  for (const engine of [chromium, webkit]) {
    const browser = await engine.launch();
    let lastPage, lastState;
    try {
      for (const route of ['/', '/ja/']) for (const width of [320, 390, 768, 1440]) for (const reducedMotion of ['reduce', 'no-preference']) for (const colorScheme of ['light', 'dark']) {
        const context = await browser.newContext({ viewport: { width, height: 900 }, colorScheme, reducedMotion,
          ...(engine === chromium ? { permissions: ['clipboard-read', 'clipboard-write'] } : {}) });
        const page = await context.newPage();
        lastPage = page; lastState = `${engine.name()} ${route} ${width} ${reducedMotion} ${colorScheme}`;
        await page.goto(server.url + route);
        await page.evaluate(() => document.fonts.ready);
        // Exclude Pagefind's unrelated lazy initialization from route traffic.
        await page.locator('#starlight__search .pagefind-ui__search-input').waitFor({ state: 'attached' });
        assert.deepEqual(await page.locator('.home-v3 a').evaluateAll(links => links.filter(a => /[→↓]\s*$/.test(a.textContent)).map(a => a.textContent)), [], 'links use layout, not trailing arrows');
        const peerSizes = await page.locator('.flow-title').evaluateAll(headings => headings.map(el => getComputedStyle(el).fontSize));
        assert.equal(peerSizes.length, 3);
        assert.equal(new Set(peerSizes).size, 1, 'peer diagram headings share the h3 role');
        if (width > 800) {
          const tops = await page.locator('.routing-workspace .flow-title').evaluateAll(headings => headings.map(el => el.getBoundingClientRect().top));
          assert.ok(Math.max(...tops) - Math.min(...tops) <= 1, 'the rule and its output align');
        }
        await assertRoute(page, 'a'); // useful selected state before any click
        const requests = [];
        page.on('request', r => requests.push(r.url()));
        for (const model of ['b', 'a', 'b']) {
          // Capture and pause the actual click-triggered CSS animation in the
          // same event turn, before awaited state assertions let 180 ms elapse.
          await page.evaluate(() => {
            document.querySelector('.route-controls').addEventListener('click', () => {
              const animations = document.getAnimations().filter(a => a.effect?.target?.matches('.route-pulse'));
              const failures = [];
              for (const animation of animations) {
                const timing = animation.effect.getTiming();
                const duration = Number(timing.duration);
                if (duration > 800 || timing.iterations !== 1) failures.push('motion is not finite');
                animation.pause();
                for (const fraction of [0, .1, .5, .99]) {
                  animation.currentTime = duration * fraction;
                  let opacity = 1;
                  for (let el = animation.effect.target; el; el = el.parentElement) opacity *= Number(getComputedStyle(el).opacity);
                  if (opacity < 1) failures.push({ fraction, opacity });
                }
                animation.finish();
              }
              window.__ngxRouteMotion = { count: animations.length, failures };
            }, { once: true });
          });
          await page.locator(`[data-model="${model}"]`).click();
          const motion = await page.evaluate(() => window.__ngxRouteMotion);
          assert.equal(motion.count, reducedMotion === 'reduce' ? 0 : 1, 'capture the actual route animation, not an empty late sample');
          assert.deepEqual(motion.failures, [], `${route} ${width} ${colorScheme}: route motion fades text or does not finish`);
          await assertRoute(page, model);
          await page.waitForFunction(() => document.getAnimations().every(a => a.playState !== 'running'));
        }

        // Native buttons remain keyboard-operable; selection and focus are distinct.
        await page.locator('[data-model="a"]').focus();
        await page.keyboard.press('Space');
        await assertRoute(page, 'a');
        await page.keyboard.press('Tab');
        assert.equal(await page.locator('[data-model="b"]').evaluate(el => document.activeElement === el), true);
        await page.keyboard.press('Enter');
        await assertRoute(page, 'b');
        if (width <= 800) {
          await page.locator('.route-response').scrollIntoViewIfNeeded();
          const relation = await page.evaluate(() => {
            const controls = document.querySelector('.route-controls').getBoundingClientRect();
            const result = document.querySelector('.route-response').getBoundingClientRect();
            const header = document.querySelector('header.header').getBoundingClientRect();
            return { controlsTop: controls.top, controlsBottom: controls.bottom, resultTop: result.top, resultBottom: result.bottom, headerBottom: header.bottom, viewport: innerHeight };
          });
          assert.ok(relation.controlsTop >= relation.headerBottom - 1, 'model controls must not hide under the header');
          assert.ok(relation.controlsBottom <= relation.resultTop + 1 && relation.resultBottom <= relation.viewport + 1, 'selection and response remain visible together');
        }
        assert.deepEqual(requests, [], 'illustration sent a network request');
        await openDisclosure(page, '.route-source-all');
        await openDisclosure(page, '.source-proof');
        await openDisclosure(page, '.sample-output');
        await openDisclosure(page, '.sample-config');
        for (const pre of await page.locator('.home-v3 pre:visible').all()) {
          assert.ok(await pre.evaluate(el => el.scrollWidth <= el.clientWidth + 1), `${route} ${width}: code requires horizontal scrolling`);
        }
        if (engine === chromium) {
          await copyExact(page, page.locator('.route-source-all .copy button'), canonicalMapping);
          await copyExact(page, page.locator('.v3-try .copy button'), canonicalStart);
          for (const model of ['a', 'b']) {
            await page.locator(`[data-model="${model}"]`).click();
            await copyExact(page, page.locator(`[data-response="${model}"] .copy button`), JSON.stringify({ upstream: model, model: `mock-model-${model}`, credential_replaced: true }, null, 2).replaceAll('": ', '":'));
          }
          for (const button of await page.locator('.sample .copy button').all()) {
            const expected = (await button.getAttribute('data-code')).replaceAll('\x7f', '\n');
            assert.ok(canonicalSamples.has(expected), 'integration sample copy differs from canonical source');
            await copyExact(page, button, expected);
          }
        }
        assert.deepEqual(requests, [], 'model changes and source copies sent a network request');
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        await context.close(); count++;
      }
      for (const route of ['/', '/ja/']) {
        const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 900 } });
        const page = await context.newPage(); await page.goto(server.url + route);
        assert.equal(await page.locator('.route-controls').isVisible(), false);
        assert.equal(await page.locator('.provider-node:visible').getAttribute('data-provider'), 'a');
        assert.deepEqual(JSON.parse(await codeText(page.locator('.route-result:visible pre'))), { upstream: 'a', model: 'mock-model-a', credential_replaced: true });
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        await context.close();
      }
    } catch (error) {
      console.error(`check-home-interaction state: ${lastState}`);
      if (lastPage && !lastPage.isClosed()) {
        const dir = path.join(site, 'build-screenshots/interaction');
        fs.mkdirSync(dir, { recursive: true });
        await lastPage.screenshot({ path: path.join(dir, 'failure.png'), fullPage: true, scale: 'css' }).catch(() => {});
        console.error(await lastPage.locator('details').evaluateAll(elements => elements.map(el => ({ class: el.className, open: el.open }))));
      }
      throw error;
    } finally { await browser.close(); }
  }
} finally { await server.close(); }
console.log(`check-home-interaction: ${count} Chromium/WebKit states; selected request/rule/upstream/response, keyboard, no-network, disclosure, wrapping and reduced-motion pass; real clipboard bytes checked in Chromium; static no-JS example checked in both engines`);
