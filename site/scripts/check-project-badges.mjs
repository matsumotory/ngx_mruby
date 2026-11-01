// The row of project badges above the heading of the four index pages
// (docs/proposals/site.md, 4.4 and 4.10).
//
//   node scripts/check-project-badges.mjs [--dist DIR] [--out DIR] [--browser]
//
// Offline markup validation by default: on /, /ja/, /v2/ and /v2/ja/ one
// row, inside the heading's block and before the h1, with the exact links,
// images, sizes and alt text of projectBadges() for the branch that the
// page describes (next for 3.x, master for 2.x), and no lazy loading; no
// row on any other page; the shared footer holds text links only, with the
// version's LICENSE link. --browser additionally checks the row in the two
// accepted patterns (patterns.mjs) in light and dark, with the external
// images served from local stand-ins (never from GitHub or
// bestpractices.dev): decoding, the size of each badge, the left edge and
// the 4 px above the heading, at most one row at 1440 px and two at 402 px,
// the heading on one line at 1440 px and on at most two at 402 px,
// keyboard order, and that the heading stays where it is when the external
// images fail. check-live.mjs fetches the real images after the deploy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent } from './lib/html.mjs';
import { patternsFor } from './lib/patterns.mjs';
import { htmlFiles } from './lib/site.mjs';
import { BADGE_FIXTURES, LICENSE_BADGE_SRC, projectBadges } from './lib/project-badges.mjs';
const args = process.argv.slice(2);
let browserCheck = false, dist = path.resolve('dist'), out = path.resolve('build-screenshots/badges');
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--browser') browserCheck = true;
  else if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--out' && args[i + 1]) out = path.resolve(args[++i]);
  else throw new Error(`unknown argument ${args[i]}`);
}
const INDEX_PAGES = { 'index.html': ['next', 'en'], 'ja/index.html': ['next', 'ja'], 'v2/index.html': ['master', 'en'], 'v2/ja/index.html': ['master', 'ja'] };
const pages = htmlFiles(dist, { v2: true });
assert.ok(pages.length, 'built HTML is required');
for (const file of Object.keys(INDEX_PAGES)) assert.ok(pages.includes(file), `${file}: index page missing (run build-v2.mjs after npm run build)`);
const license = fs.readFileSync(path.join(dist, LICENSE_BADGE_SRC), 'utf8');
assert.match(license, /^<svg [^>]*width="78" height="20"/, `${LICENSE_BADGE_SRC}: a 78 by 20 SVG`);
for (const file of pages) {
  const all = elements(readHtml(path.join(dist, file)));
  const footer = all.find(el => hasClass(el, 'site-footer'));
  assert.ok(footer, `${file}: shared footer missing`);
  const footerLinks = elements(footer).filter(el => el.tagName === 'a');
  assert.equal(elements(footer).filter(el => el.tagName === 'img' || hasClass(el, 'project-badge')).length, 0, `${file}: the footer holds text links only`);
  const ref = file.startsWith('v2/') ? 'master' : 'next';
  assert.ok(footerLinks.some(el => el.properties.href === `https://github.com/matsumotory/ngx_mruby/blob/${ref}/LICENSE` && textContent(el) === 'MIT'), `${file}: real MIT license link`);
  const rows = all.filter(el => hasClass(el, 'project-badges'));
  if (!INDEX_PAGES[file]) {
    assert.equal(rows.length, 0, `${file}: the badges belong to the index pages only`);
    continue;
  }
  const [pageRef, lang] = INDEX_PAGES[file];
  assert.equal(pageRef, ref, file);
  assert.equal(rows.length, 1, `${file}: exactly one row of project badges`);
  const heading = all.find(el => hasClass(el, 'hero-heading') && elements(el).includes(rows[0]));
  assert.ok(heading, `${file}: the row is inside .hero-heading`);
  const inside = elements(heading);
  const h1 = inside.find(el => el.tagName === 'h1' && el.properties.id === '_top');
  assert.ok(h1, `${file}: the row's block holds h1#_top`);
  assert.ok(inside.indexOf(rows[0]) < inside.indexOf(h1), `${file}: the row comes before the heading`);
  assert.equal(rows[0].tagName, 'ul', file);
  assert.ok(rows[0].properties.ariaLabel, `${file}: the row has a name`);
  const links = elements(rows[0]).filter(el => el.tagName === 'a');
  const want = projectBadges(ref, lang);
  assert.deepEqual(links.map(el => el.properties.dataBadge), want.map(b => b.id), `${file}: order of the badges`);
  want.forEach((badge, i) => {
    assert.equal(links[i].properties.href, badge.href, `${file}: ${badge.id} href`);
    const images = elements(links[i]).filter(el => el.tagName === 'img');
    assert.equal(images.length, 1, `${file}: ${badge.id} image`);
    for (const key of ['src', 'alt', 'width', 'height']) assert.equal(String(images[0].properties[key]), String(badge[key]), `${file}: ${badge.id} ${key}`);
    assert.equal(images[0].properties.referrerPolicy, 'no-referrer', `${file}: ${badge.id} referrer policy`);
    assert.equal(images[0].properties.loading, undefined, `${file}: ${badge.id} is in the first view: no lazy loading`);
  });
}
console.log(`check-project-badges: the 4 index pages have one row of the exact CI, CodeQL, OpenSSF and license badges for next or master before the h1; ${pages.length - 4} other pages have none; ${pages.length} footers hold text links only with the version's LICENSE link; no external fetch in this static check`);

if (browserCheck) {
  const { chromium, webkit } = await import('playwright');
  const { serve } = await import('./lib/serve.mjs');
  const { readOnlyContext } = await import('./lib/read-only-browser.mjs');
  const server = await serve(dist);
  fs.mkdirSync(out, { recursive: true });
  const routes = ['/', '/ja/', '/v2/', '/v2/ja/'];
  const records = [];
  const total = routes.length * 2 * 3;
  let complete = false;
  // Geometry of the row and the heading, in CSS px.
  const measure = page => page.evaluate(() => {
    const box = el => { const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height }; };
    const row = document.querySelector('.project-badges');
    return {
      row: box(row),
      h1: box(document.querySelector('h1#_top')),
      links: [...row.querySelectorAll('a')].map(box),
      images: [...row.querySelectorAll('img')].map(el => ({ ...box(el), attrWidth: Number(el.getAttribute('width')), attrHeight: Number(el.getAttribute('height')), complete: el.complete, naturalWidth: el.naturalWidth })),
      // Lines of the heading: the distinct tops of its text's line boxes.
      h1Lines: (() => {
        const tops = [];
        const walker = document.createTreeWalker(document.querySelector('h1#_top'), NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          if (!n.data.trim()) continue;
          const range = document.createRange();
          range.selectNodeContents(n);
          for (const r of range.getClientRects()) if (r.width > 0 && !tops.some(t => Math.abs(t - r.top) < r.height / 2)) tops.push(r.top);
        }
        return tops.length;
      })(),
      scrollWidth: document.documentElement.scrollWidth,
      innerWidth,
    };
  });
  try {
    for (const engineName of ['chromium', 'webkit']) {
      const { width, height } = patternsFor(engineName)[0];
      const phone = engineName === 'webkit';
      const browser = await { chromium, webkit }[engineName].launch();
      try {
        for (const route of routes) {
          const loaded = {};
          // Light and dark with the stand-ins, then light with every external
          // image failing (no stand-in: the read-only context blocks them).
          for (const [colorScheme, failing] of [['light', false], ['dark', false], ['light', true]]) {
            const label = `${engineName} ${route} ${colorScheme}${failing ? ' failing images' : ''}`;
            const { context, blocked, close } = await readOnlyContext(browser, server.url, { viewport: { width, height }, colorScheme, reducedMotion: 'reduce' }, failing ? {} : BADGE_FIXTURES);
            try {
              const page = await context.newPage();
              const errors = [];
              page.on('pageerror', error => errors.push(error.message));
              await page.goto(server.url + route, { waitUntil: 'load' });
              await page.evaluate(() => document.fonts.ready);
              if (!failing) {
                await page.waitForFunction(() => [...document.querySelectorAll('.project-badges img')].every(image => image.complete && image.naturalWidth > 0));
                await page.locator('.project-badges img').evaluateAll(images => Promise.all(images.map(image => image.decode())));
              } else {
                await page.waitForFunction(() => [...document.querySelectorAll('.project-badges img')].every(image => image.complete));
              }
              const m = await measure(page);
              assert.equal(m.images.length, 4, `${label}: four badges`);
              m.images.forEach((image, i) => {
                assert.ok(Math.abs(image.width - image.attrWidth) < 0.5 && Math.abs(image.height - image.attrHeight) < 0.5, `${label}: badge ${i} is ${image.width} by ${image.height}, not ${image.attrWidth} by ${image.attrHeight}`);
                assert.ok(image.left >= 0 && image.right <= width, `${label}: badge ${i} clips at ${width}`);
              });
              const external = m.images.filter((_, i) => i < 3);
              if (!failing) assert.ok(m.images.every(image => image.complete && image.naturalWidth > 0), `${label}: every badge decodes`);
              else assert.ok(external.every(image => image.naturalWidth === 0), `${label}: the external badges failed`);
              assert.ok(Math.abs(m.row.left - m.h1.left) < 1, `${label}: the row starts at ${m.row.left}, the heading at ${m.h1.left}`);
              assert.ok(Math.abs(m.h1.top - m.row.bottom - 4) < 1, `${label}: ${m.h1.top - m.row.bottom} px between the row and the heading, not 4`);
              const tops = [...new Set(m.links.map(link => Math.round(link.top)))];
              assert.ok(tops.length <= (phone ? 2 : 1), `${label}: the row takes ${tops.length} lines at ${width} px`);
              m.links.forEach((link, i) => {
                assert.ok(link.height >= 24, `${label}: badge link ${i} is ${link.height} px high, under 24 (4.9)`);
                const next = m.links[i + 1];
                if (next && Math.round(next.top) === Math.round(link.top)) assert.ok(Math.abs(next.left - link.right - 8) < 1, `${label}: ${next.left - link.right} px between badges ${i} and ${i + 1}, not 8`);
              });
              assert.ok(m.scrollWidth <= m.innerWidth + 1, `${label}: no horizontal page scroll`);
              // 4.4: the heading of an index page takes one line at 1440 px
              // and at most two at 402 px.
              assert.ok(m.h1Lines >= 1 && m.h1Lines <= (phone ? 2 : 1), `${label}: the heading takes ${m.h1Lines} lines at ${width} px`);
              if (failing) {
                const base = loaded.light;
                assert.ok(Math.abs(m.h1.top - base.h1.top) < 0.5 && Math.abs(m.h1.left - base.h1.left) < 0.5, `${label}: the heading moved from ${base.h1.top} to ${m.h1.top} when the images failed`);
                assert.deepEqual(blocked.length, 3, `${label}: the three external images were refused`);
              } else {
                loaded[colorScheme] = m;
                // Keyboard order through the row. WebKit's native link
                // navigation uses Option-Tab, as in check-focus.mjs.
                await page.locator('.project-badges a').first().focus();
                for (let i = 1; i < 4; i++) {
                  await page.keyboard.press(phone ? 'Alt+Tab' : 'Tab', { delay: 60 });
                  assert.equal(await page.evaluate(i => document.activeElement === document.querySelectorAll('.project-badges a')[i], i), true, `${label}: Tab reaches badge ${i}`);
                }
                await page.evaluate(() => document.activeElement.blur());
                assert.deepEqual(blocked, [], `${label}: only same-origin GET and the badge stand-ins are allowed`);
              }
              const name = `${engineName}-${width}-${route.replaceAll('/', '-').replace(/^-|-$/g, '') || 'home'}-${colorScheme}${failing ? '-failing' : ''}.png`;
              await page.screenshot({ path: path.join(out, name), clip: { x: 0, y: 0, width, height: Math.min(height, Math.ceil(m.h1.bottom + 32)) } });
              assert.deepEqual(errors, [], `${label}: no page exception`);
              records.push({ route, engine: engineName, width, colorScheme, failing, rowLines: tops.length, headingLines: m.h1Lines, gapAboveHeading: m.h1.top - m.row.bottom, h1Top: m.h1.top, file: name });
            } catch (error) {
              console.error(`check-project-badges state: ${label}; ${records.length}/${total} complete`);
              throw error;
            } finally { await close(); }
          }
        }
      } finally { await browser.close(); }
    }
    complete = true;
  } finally {
    try { await server.close(); } catch (error) { complete = false; throw error; }
    finally {
      const manifest = JSON.parse(fs.readFileSync(path.join(dist, 'docs-index.json'), 'utf8'));
      const v2 = JSON.parse(fs.readFileSync(path.join(dist, 'v2/docs-index.json'), 'utf8'));
      fs.writeFileSync(path.join(out, 'evidence.json'), JSON.stringify({ source_revision: manifest.source_revision, v2_source_revision: v2.source_revision, working_tree_clean: manifest.working_tree_clean, complete: complete && records.length === total, pages: records }, null, 2) + '\n');
    }
  }
  console.log(`check-project-badges: ${records.length} states of the row at Chromium ${patternsFor('chromium')[0].width} px and WebKit ${patternsFor('webkit')[0].width} px with the local stand-ins (/, /ja/, /v2/, /v2/ja/; light, dark, and light with the external images failing): sizes, left edge, 4 px above the heading, line counts of the row and the heading, keyboard order, and the heading unmoved when the images fail`);
}
