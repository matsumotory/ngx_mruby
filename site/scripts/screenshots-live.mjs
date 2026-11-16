// A small, read-only production smoke check: twelve page visits, no form
// submission, provider request, search query or load/performance loop.
// --local exercises the same code against the artifact in pre-deploy CI.
// --origin URL checks another server that serves the artifact (the test of
// the retry below, test-screenshots-live.mjs); --wait-limit SECONDS sets
// the limit of that retry's wait.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium, webkit } from 'playwright';
import { PATTERNS, PHONE } from './lib/patterns.mjs';
import { serve } from './lib/serve.mjs';
import { readOnlyContext } from './lib/read-only-browser.mjs';
import { BADGE_FIXTURES, projectBadges } from './lib/project-badges.mjs';

// Right after a deploy, GitHub Pages answers some files of the site with
// 503 for a short time. From 2026-10-29 to 2026-11-16, 8 of the 14 runs of
// site.yml on next that failed or passed only on a re-run failed on that
// alone, 1.5 to 2 minutes after the deploy. 3 of them were re-run: the
// re-runs started this check 126, 144 and 289 seconds after the failure,
// and got 200 within the 27 seconds that the check took. So the 503 ended
// within 153 seconds in the quickest case.
// A context (an engine and a language) whose only errors are 5xx answers of
// this origin, and request failures of the same URLs, waits until each
// such URL answers 200 outside the browser, then runs once more. All the
// waits of a run share WAIT_LIMIT, 240 seconds, which keeps the job inside
// its timeout-minutes: 10 (the steps before this one take about 2 minutes,
// and this one 25 seconds without a retry).
const POLL_MS = 5_000;
let waitLimitMs = 240_000; // WAIT_LIMIT

const site = path.resolve(new URL('..', import.meta.url).pathname);
let dist = path.join(site, 'dist'), out = path.join(site, 'live-screenshots'), local = false, liveOrigin = 'https://ngx.mruby.org';
const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--out' && args[i + 1]) out = path.resolve(args[++i]);
  else if (args[i] === '--local') local = true;
  else if (args[i] === '--origin' && args[i + 1]) liveOrigin = new URL(args[++i]).origin;
  else if (args[i] === '--wait-limit' && args[i + 1]) waitLimitMs = Number(args[++i]) * 1000;
  else throw new Error(`unknown argument ${args[i]}`);
}
if (!(waitLimitMs >= 0)) throw new Error('--wait-limit takes a number of seconds');
if (local && liveOrigin !== 'https://ngx.mruby.org') throw new Error('--local serves the artifact itself; it takes no --origin');
const manifest = JSON.parse(fs.readFileSync(path.join(dist, 'docs-index.json'), 'utf8'));
const v2Manifest = JSON.parse(fs.readFileSync(path.join(dist, 'v2/docs-index.json'), 'utf8'));
const server = local ? await serve(dist) : null;
const origin = server?.url ?? liveOrigin;
fs.mkdirSync(out, { recursive: true });
const records = [];
const retries = [];
let browser;
let complete = false;

async function visitContext(engine, width, height, lang, pages) {
  const { context, blocked, close } = await readOnlyContext(browser, origin, { viewport: { width, height }, colorScheme: 'dark', deviceScaleFactor: 1 }, BADGE_FIXTURES);
  const errors = [], issues = [], visited = [];
  let closing = false, htmlDiffers = false, closeFailed = false, closeError, failure;
  try {
    const page = await context.newPage();
    page.on('pageerror', error => { errors.push(error.message); issues.push({ kind: 'pageerror' }); });
    page.on('response', response => {
      if (response.status() < 400) return;
      errors.push(`HTTP ${response.status()} ${response.url()}`);
      issues.push({ kind: 'status', status: response.status(), url: response.url() });
    });
    page.on('requestfailed', request => {
      if (closing) return;
      errors.push(`${request.failure()?.errorText} ${request.url()}`);
      issues.push({ kind: 'requestfailed', url: request.url() });
    });
    for (const [id, route] of pages) {
      const response = await page.goto(origin + route, { waitUntil: 'load' });
      assert.equal(response.status(), 200, route);
      if (!(await response.body()).equals(fs.readFileSync(path.join(dist, route.slice(1), 'index.html')))) {
        htmlDiffers = true;
        assert.fail(`${route}: live HTML differs from the verified artifact`);
      }
      await page.evaluate(() => document.fonts.ready);
      const base = `${engine}-${id}-${lang}-${width}`;
      // The strip of development practices of the index pages shows the
      // local stand-ins here; check-live.mjs fetches the real images with
      // retries, so this smoke never waits on the services.
      if (id === 'home' || id === 'v2-entry') {
        const count = projectBadges(id === 'home' ? 'next' : 'master', 'en').length;
        await page.waitForFunction((count) => {
          const images = [...document.querySelectorAll('.project-badges img')];
          return images.length === count && images.every(image => image.complete && image.naturalWidth > 0);
        }, count);
        await page.locator('.project-badges img').evaluateAll(images => Promise.all(images.map(image => image.decode())));
      }
      await page.screenshot({ path: path.join(out, `${base}-first.png`) });
      await page.locator('.site-footer').scrollIntoViewIfNeeded();
      await page.screenshot({ path: path.join(out, `${base}-footer.png`) });
      await page.screenshot({ path: path.join(out, `${base}-full.png`), fullPage: true });
      if (id === 'home') {
        await page.locator('.route-controls button[data-model="b"]').click();
        assert.equal(await page.locator('.v3-flow').getAttribute('data-route'), 'b');
        await page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
        await page.locator('.route-result:visible').scrollIntoViewIfNeeded();
        await page.screenshot({ path: path.join(out, `${base}-model-b-result.png`) });
      }
      assert.deepEqual(blocked, [], 'unexpected request outside the read-only page boundary was blocked');
      assert.deepEqual(errors, [], 'page exception or failed resource request');
      visited.push({ route, engine, width, height, html_matches_artifact: true, files: base });
    }
  } catch (error) {
    failure = error;
  }
  closing = true;
  try {
    await close();
  } catch (error) {
    closeFailed = true;
    closeError = error;
    failure ??= error;
  }
  if (!failure) {
    try {
      assert.deepEqual(blocked, [], 'unexpected network activity before the verification context closed');
      assert.deepEqual(errors, [], 'page/resource errors before the verification context closed');
    } catch (error) {
      failure = error;
    }
  }
  return { failure, closeError, errors, issues, blocked, htmlDiffers, closeFailed, records: visited };
}

// The URLs to wait for, or null when the failure is not one to retry: any
// 4xx, page exception, blocked request, HTML that differs from the
// artifact, error of the request interception, or error of another origin.
function retryableUrls({ issues, blocked, htmlDiffers, closeFailed }) {
  if (local || !issues.length || blocked.length || htmlDiffers || closeFailed) return null;
  const sameOrigin = url => new URL(url).origin === origin;
  const urls = new Set(issues.filter(i => i.kind === 'status' && i.status >= 500 && sameOrigin(i.url)).map(i => i.url));
  const ok = urls.size && issues.every(i => (i.kind === 'status' && i.status >= 500 || i.kind === 'requestfailed') && urls.has(i.url));
  return ok ? [...urls] : null;
}

// Fetches url outside the browser until it answers 200, within what is
// left of the limit of the run.
async function waitFor200(url) {
  const started = Date.now(), deadline = started + waitLimitMs;
  let polls = 0, last;
  for (;;) {
    polls++;
    try {
      const signal = AbortSignal.timeout(Math.max(1_000, Math.min(10_000, deadline - Date.now())));
      const response = await fetch(url, { redirect: 'manual', cache: 'no-store', signal });
      last = response.status;
      await response.arrayBuffer();
    } catch (error) {
      last = error.message;
    }
    if (last === 200 || Date.now() >= deadline) break;
    await sleep(Math.max(0, Math.min(POLL_MS, deadline - Date.now())));
  }
  const elapsed = Date.now() - started;
  waitLimitMs = Math.max(0, waitLimitMs - elapsed);
  return { ok: last === 200, seconds: Math.round(elapsed / 100) / 10, polls, last };
}

// What failed a context, for the log: the error that stopped it, and every
// error the context collected, which that error may not show.
function describe({ failure, closeError, errors, blocked }) {
  const closing = closeError && closeError !== failure ? [`closing the context: ${closeError.message}`, ...(closeError.errors ?? []).map(error => `  ${error.message}`)] : [];
  return [failure?.message?.split('\n')[0], ...closing, ...errors, ...blocked.map(item => `blocked: ${item}`)].filter(Boolean);
}

try {
  for (const { engine, width, height } of PATTERNS) {
    browser = await { chromium, webkit }[engine].launch();
    for (const lang of ['en', 'ja']) {
      const pages = [
        ['home', lang === 'ja' ? '/ja/' : '/'],
        ['v2-entry', lang === 'ja' ? '/v2/ja/' : '/v2/'],
        ...(width === PHONE.width ? [['start', lang === 'ja' ? '/ja/start/' : '/start/'], ['docs', lang === 'ja' ? '/ja/docs/' : '/docs/']] : []),
      ];
      const name = `${engine}-${lang}-${width}`;
      let result = await visitContext(engine, width, height, lang, pages);
      const urls = result.failure && retryableUrls(result);
      if (urls) {
        const firstFailure = describe(result);
        console.log(`screenshots-live: ${name}: failed on a 5xx of the site:\n  ${firstFailure.join('\n  ')}`);
        for (const url of urls) {
          const status = result.issues.find(i => i.kind === 'status' && i.url === url).status;
          const waited = await waitFor200(url);
          retries.push({ context: name, url, status, waited_seconds: waited.seconds, polls: waited.polls, recovered: waited.ok, last: waited.last, first_failure: firstFailure });
          console.log(waited.ok
            ? `screenshots-live: ${name}: ${url} answered ${status}; it answered 200 after ${waited.seconds} s (${waited.polls} fetches); checking the context again`
            : `screenshots-live: ${name}: ${url} answered ${status}; it still answered ${waited.last} after ${waited.seconds} s (${waited.polls} fetches), at the limit of the wait`);
          if (!waited.ok) throw result.failure;
        }
        // The second visit takes the records and screenshots of the context
        // again; none of the first may stay if it stops at an earlier page.
        for (const file of fs.readdirSync(out)) {
          if (pages.some(([id]) => file.startsWith(`${engine}-${id}-${lang}-${width}-`))) fs.rmSync(path.join(out, file));
        }
        result = await visitContext(engine, width, height, lang, pages);
      }
      if (result.failure) {
        console.error(`screenshots-live: ${name}: failed${urls ? ' again after the retry' : ''}:\n  ${describe(result).join('\n  ')}`);
        throw result.failure;
      }
      records.push(...result.records);
    }
    await browser.close();
    browser = null;
  }
  complete = true;
} finally {
  await browser?.close();
  await server?.close();
  fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify({ origin, source_revision: manifest.source_revision, v2_source_revision: v2Manifest.source_revision, working_tree_clean: manifest.working_tree_clean, captured_at: new Date().toISOString(), complete: complete && records.length === 12, pages: records, retries }, null, 2) + '\n');
}
console.log(`screenshots-live: ${records.length} read-only page visits at ${origin}${retries.length ? ` (${new Set(retries.map(r => r.context)).size} context(s) checked again after a 5xx)` : ''}; exact artifact HTML matched; desktop/mobile pixels saved for independent review`);
