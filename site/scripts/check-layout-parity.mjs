// Base/head browser geometry and computed-style acceptance, proposal 5.4.
// node scripts/check-layout-parity.mjs --base DIR --head DIR --out DIR [--ja-face noto] [--pages /,/ja/]
// Only Chromium 1440px and WebKit 402px. Requires their installed browsers.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, webkit } from 'playwright';
import sharp from 'sharp';
import { serve } from './lib/serve.mjs';
import { PATTERNS } from './lib/patterns.mjs';
import { serveBadgeFixture } from './lib/project-badges.mjs';

export function compareMeasurements(base, head, tolerance = 1) {
  const failures = [];
  if (base.length !== head.length) failures.push(`visible semantic elements: ${base.length} -> ${head.length}`);
  for (let i = 0; i < Math.min(base.length, head.length); i++) {
    const a = base[i], b = head[i], label = `${i} ${a.key}`;
    if (a.key !== b.key) { failures.push(`${label}: identity -> ${b.key}`); continue; }
    for (const k of ['x', 'y', 'width', 'height']) if (Math.abs(a.box[k] - b.box[k]) > tolerance) failures.push(`${label}: ${k} ${a.box[k]} -> ${b.box[k]} CSSpx`);
    for (const k of Object.keys(a.style)) if (a.style[k] !== b.style[k]) failures.push(`${label}: ${k} ${a.style[k]} -> ${b.style[k]}`);
  }
  return failures;
}

async function measure(page) {
  return page.evaluate(() => {
    const properties = ['display', 'position', 'fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'color', 'backgroundColor', 'borderTopWidth', 'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth', 'borderRadius', 'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'marginTop', 'marginRight', 'marginBottom', 'marginLeft', 'gap', 'textAlign', 'whiteSpace', 'overflowX'];
    // Semantic surfaces survive wrapper/class renames. Decorative hidden
    // SVGs and empty shell-only wrappers are deliberately not measurement keys.
    return [...document.querySelectorAll('header,main,footer,aside,nav,h1,h2,h3,h4,p,li,pre,table,th,td,figure,figcaption,button,input,summary,a,img')].filter(el => {
      const s = getComputedStyle(el), b = el.getBoundingClientRect();
      return s.display !== 'none' && s.visibility !== 'hidden' && b.width > 0 && b.height > 0 && !el.closest('[hidden],template');
    }).map(el => {
      const b = el.getBoundingClientRect(), s = getComputedStyle(el);
      const text = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('alt') || '').replace(/\s+/g, ' ').trim();
      return { key: `${el.tagName}:${text}`, box: { x: b.x, y: b.y, width: b.width, height: b.height }, style: Object.fromEntries(properties.map(k => [k, s[k]])) };
    });
  });
}

async function htmlFiles(root, prefix = '') {
  const result = [];
  for (const entry of await fs.readdir(path.join(root, prefix), { withFileTypes: true })) {
    const name = path.join(prefix, entry.name);
    if (entry.isDirectory()) result.push(...await htmlFiles(root, name));
    else if (entry.name.endsWith('.html') && !entry.name.startsWith('google')) result.push(name);
  }
  return result.sort();
}
const routeOf = file => '/' + file.replaceAll(path.sep, '/').replace(/index\.html$/, '');
const evidenceRoutes = new Set(['/', '/ja/', '/concepts/request-phases/', '/ja/concepts/request-phases/', '/reference/directives/', '/ja/reference/directives/']);

// Interaction coverage is independent of representative screenshot selection.
export function statesFor(engine, representative) {
  assert.ok(['chromium', 'webkit'].includes(engine), `unknown engine: ${engine}`);
  const states = [{ theme: 'light', state: 'page' },
    { theme: 'light', state: engine === 'webkit' ? 'menu' : 'search' }];
  if (representative) states.push({ theme: 'dark', state: 'page' });
  return states;
}

async function writeImages(a, b, dir) {
  await fs.mkdir(dir, { recursive: true });
  const shots = await Promise.all([a, b].map(p => p.screenshot({ fullPage: false, scale: 'css' })));
  await fs.writeFile(path.join(dir, 'base.png'), shots[0]);
  await fs.writeFile(path.join(dir, 'head.png'), shots[1]);
  const [left, right] = await Promise.all(shots.map(s => sharp(s).ensureAlpha().raw().toBuffer({ resolveWithObject: true })));
  assert.equal(left.info.width, right.info.width); assert.equal(left.info.height, right.info.height);
  const { width, height, channels } = left.info;
  const diff = Buffer.alloc(left.data.length);
  let differentPixels = 0;
  for (let i = 0; i < diff.length; i += channels) {
    let changed = false;
    for (let j = 0; j < 3; j++) { diff[i + j] = Math.abs(left.data[i + j] - right.data[i + j]); changed ||= diff[i + j] > 0; }
    diff[i + 3] = 255;
    if (changed) differentPixels++;
  }
  await sharp(diff, { raw: { width, height, channels } }).png().toFile(path.join(dir, 'diff.png'));
  await sharp({ create: { width: width * 2, height, channels: 4, background: '#ffffff' } }).composite([{ input: shots[0], left: 0, top: 0 }, { input: shots[1], left: width, top: 0 }]).png().toFile(path.join(dir, 'side-by-side.png'));
  // Raster differences are evidence, not a pass/fail substitute for geometry.
  return { differentPixels, pixels: width * height };
}

async function prepare(page, url, state, noto) {
  await page.goto(url, { waitUntil: 'load' });
  if (noto) await page.addStyleTag({ content: ':root { --font-ja-faces: "Noto Sans JP Variable", "Noto Sans JP" !important; }' });
  await page.evaluate(() => document.fonts.ready);
  // Both shells start Pagefind's UI and the table of contents when the
  // browser is idle. Wait for both on each side, so that a side measured
  // before its idle callback ran does not show as a difference.
  await page.locator('dialog .pagefind-ui__search-input').waitFor({ state: 'attached' });
  // An idle callback queued now runs after the one that the table of
  // contents queued while the page was parsed; two frames later its
  // IntersectionObserver has delivered the first entries.
  await page.evaluate(() => new Promise(resolve => (window.requestIdleCallback || (f => setTimeout(f, 1)))(() => requestAnimationFrame(() => requestAnimationFrame(resolve)))));
  if (state === 'menu') {
    const button = page.locator('button.site-menu-button,button.sl-menu-button');
    assert.equal(await button.count(), 1, 'expected a single mobile menu button');
    await button.click();
  } else if (state === 'search') {
    await page.locator('button[data-open-modal]').click();
    // Pagefind's UI renders its field as input type="text".
    const input = page.locator('dialog .pagefind-ui__search-input');
    await input.fill('mruby_content_handler');
    await page.locator('dialog .pagefind-ui__result-link').first().waitFor({ state: 'visible' });
  }
  // Both sides request reduced motion. Wait only for finite transitions;
  // a perpetual decorative SVG animation must not stall the comparison.
  await page.waitForFunction(() => document.getAnimations().filter(a => Number.isFinite(a.effect?.getComputedTiming().endTime)).every(a => a.playState !== 'running'));
  await page.evaluate(() => document.getAnimations().filter(a => !Number.isFinite(a.effect?.getComputedTiming().endTime)).forEach(a => { a.pause(); a.currentTime = 0; }));
}

export async function compareLayouts(base, head, out, options = {}) {
  let files = [];
  const servers = [];
  const failures = [], records = [];
  let completed = false, fatalError = null;
  await fs.mkdir(out, { recursive: true });
  try {
    files = await htmlFiles(base);
    assert.deepEqual(await htmlFiles(head), files, 'base/head HTML route sets differ');
    if (options.pages) {
      for (const route of options.pages) assert.ok(files.some(f => routeOf(f) === route), `unknown selected page: ${route}`);
      files = files.filter(f => options.pages.includes(routeOf(f)));
    }
    assert.ok(files.length, 'no HTML pages selected');
    // Sequential startup keeps the first server available for cleanup when
    // the second server fails. Startup errors are recorded in results.json.
    servers.push(await serve(base));
    servers.push(await serve(head));
    for (const { engine, width, height } of PATTERNS) {
      const browser = await { chromium, webkit }[engine].launch();
      try {
        for (const file of files) {
          const route = routeOf(file), selected = evidenceRoutes.has(route);
          const states = statesFor(engine, selected);
          for (const { theme, state } of states) {
            const contexts = await Promise.all(servers.map(() => browser.newContext({ viewport: { width, height }, colorScheme: theme, reducedMotion: 'reduce' })));
            const label = `${engine}-${width}-${route.replaceAll('/', '_')}-${theme}-${state}`;
            try {
              await Promise.all(contexts.map(serveBadgeFixture));
              const pages = await Promise.all(contexts.map(c => c.newPage()));
              await Promise.all(pages.map((page, i) => prepare(page, servers[i].url + route, state, options.noto)));
              const [before, after] = await Promise.all(pages.map(measure));
              const errors = compareMeasurements(before, after);
              failures.push(...errors.map(e => `${label}: ${e}`));
              const images = selected || errors.length ? await writeImages(...pages, path.join(out, label)) : null;
              records.push({ label, elements: before.length, failures: errors, images });
            } catch (error) { failures.push(`${label}: ${error.message}`); records.push({ label, error: error.message }); }
            finally { await Promise.all(contexts.map(c => c.close())); }
          }
        }
      } finally { await browser.close(); }
    }
    completed = true;
  } catch (error) { fatalError = error.message; throw error; } finally {
    await Promise.all(servers.map(s => s.close()));
    await fs.writeFile(path.join(out, 'results.json'), JSON.stringify({ completed, fatalError, font: options.noto ? 'Noto Sans JP override' : 'platform default', motion: 'reduced; finite transitions awaited; infinite animations paused at time 0 on both sides', records, failures }, null, 2));
  }
  assert.deepEqual(failures, [], `layout parity failures (${failures.length}):\n${failures.slice(0, 40).join('\n')}`);
  console.log(`check-layout-parity: ${records.length} states, ${files.length} HTML, ${PATTERNS.map(p => `${p.engine} ${p.width}`).join(' / ')}; boxes within 1 CSSpx and computed styles equal`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2), get = name => args[args.indexOf(name) + 1];
  assert.ok(['--base', '--head', '--out'].every(k => args.includes(k) && get(k)), 'usage: --base DIR --head DIR --out DIR');
  const noto = args.includes('--ja-face');
  if (noto) assert.equal(get('--ja-face'), 'noto', 'only --ja-face noto is supported');
  const pages = args.includes('--pages') ? get('--pages').split(',').filter(Boolean) : null;
  await compareLayouts(...['--base', '--head', '--out'].map(k => path.resolve(get(k))), { noto, pages });
}
