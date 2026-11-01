// The project's state on the site (docs/proposals/site.md, 4.10): the strip
// of development practices of the four index pages, the release badge of
// the status line of the home pages, and the star count of the GitHub link.
//
//   node scripts/check-project-badges.mjs [--dist DIR] [--out DIR] [--browser]
//
// Offline markup validation by default. On /, /ja/, /v2/ and /v2/ja/: one
// strip, after the h1 and outside its heading block (on / and /ja/ a child
// of .home-v3 between the hero and the first section), with the exact
// links, images, sizes and alt text of projectBadges() for the branch that
// the page describes (next for 3.x, master for 2.x), and no lazy loading; no
// strip on any other page. On / and /ja/: one release badge in the status
// line, for the newest stable tag of the repository when its tags are there
// (a checkout without tags checks the form only). On every page: the shared
// footer holds text links only, with the version's LICENSE link, and the
// GitHub links of the header and the menu carry the same star count or none;
// with NGX_MRUBY_SITE_STARS set, that count. --browser additionally checks,
// in the two accepted patterns (patterns.mjs) in light and dark, with the
// external images served from local stand-ins (never from GitHub or
// bestpractices.dev): decoding, the size of each badge, the left edge of the
// strip at the heading's, the space above it, one line at 1440 px on / and
// /ja/ (two in the documentation column of /v2/ and /v2/ja/) and at most four
// at 402 px, the heading on one line at 1440 px and on at most two
// at 402 px, the release badge in the status line, keyboard order, and that
// the strip keeps its box when the external images fail.
// check-live.mjs fetches the real images after the deploy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent } from './lib/html.mjs';
import { patternsFor } from './lib/patterns.mjs';
import { htmlFiles, repoDir } from './lib/site.mjs';
import { latestReleaseTag } from './lib/release-state.mjs';
import { BADGE_FIXTURES, LICENSE_BADGE_SRC, githubStars, projectBadges, releaseBadge } from './lib/project-badges.mjs';
const args = process.argv.slice(2);
let browserCheck = false, dist = path.resolve('dist'), out = path.resolve('build-screenshots/badges');
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--browser') browserCheck = true;
  else if (args[i] === '--dist' && args[i + 1]) dist = path.resolve(args[++i]);
  else if (args[i] === '--out' && args[i + 1]) out = path.resolve(args[++i]);
  else throw new Error(`unknown argument ${args[i]}`);
}
const INDEX_PAGES = { 'index.html': ['next', 'en'], 'ja/index.html': ['next', 'ja'], 'v2/index.html': ['master', 'en'], 'v2/ja/index.html': ['master', 'ja'] };
const HOME_PAGES = ['index.html', 'ja/index.html'];
const pages = htmlFiles(dist, { v2: true });
assert.ok(pages.length, 'built HTML is required');
for (const file of Object.keys(INDEX_PAGES)) assert.ok(pages.includes(file), `${file}: index page missing (run build-v2.mjs after npm run build)`);
const license = fs.readFileSync(path.join(dist, LICENSE_BADGE_SRC), 'utf8');
assert.match(license, /^<svg [^>]*width="78" height="20"/, `${LICENSE_BADGE_SRC}: a 78 by 20 SVG`);
// The release that the home pages must name: the newest stable tag, when
// this checkout has the tags (the build job has the whole history; the
// browser lanes check out without tags).
let releaseTag = null;
try { releaseTag = latestReleaseTag(repoDir); } catch { releaseTag = null; }
// The star count that the build was given, when this process has it.
const givenStars = githubStars('en');
const starCounts = new Set();
for (const file of pages) {
  const all = elements(readHtml(path.join(dist, file)));
  const footer = all.find(el => hasClass(el, 'site-footer'));
  assert.ok(footer, `${file}: shared footer missing`);
  const footerLinks = elements(footer).filter(el => el.tagName === 'a');
  assert.equal(elements(footer).filter(el => el.tagName === 'img' || hasClass(el, 'project-badge')).length, 0, `${file}: the footer holds text links only`);
  const ref = file.startsWith('v2/') ? 'master' : 'next';
  const lang = file.startsWith('ja/') || file.startsWith('v2/ja/') ? 'ja' : 'en';
  assert.ok(footerLinks.some(el => el.properties.href === `https://github.com/matsumotory/ngx_mruby/blob/${ref}/LICENSE` && textContent(el) === 'MIT'), `${file}: real MIT license link`);
  // The GitHub links of the header and the menu: the same count or none.
  const githubLinks = all.filter(el => el.tagName === 'a' && hasClass(el, 'github-link'));
  assert.ok(githubLinks.length >= 1, `${file}: GitHub link missing`);
  for (const link of githubLinks) {
    const stars = elements(link).filter(el => hasClass(el, 'github-stars'));
    assert.ok(stars.length <= 1, `${file}: one star count per GitHub link`);
    if (!stars.length) { starCounts.add('none'); continue; }
    const { dataStars, dataStarsDate } = stars[0].properties;
    const want = githubStars(lang, { NGX_MRUBY_SITE_STARS: String(dataStars), NGX_MRUBY_SITE_STARS_DATE: String(dataStarsDate) });
    const spans = elements(stars[0]).filter(el => el.tagName === 'span');
    assert.equal(textContent(spans.find(el => el.properties.ariaHidden === 'true') ?? { children: [] }), want.short, `${file}: the short star count`);
    assert.equal(textContent(spans.find(el => hasClass(el, 'sr-only')) ?? { children: [] }), want.label, `${file}: the star count read by assistive technology`);
    assert.equal(stars[0].properties.title, want.title, `${file}: the title of the star count`);
    starCounts.add(`${dataStars} ${dataStarsDate}`);
  }
  // The release badge: on the home pages only.
  const releases = all.filter(el => el.tagName === 'a' && hasClass(el, 'release-badge'));
  if (HOME_PAGES.includes(file)) {
    assert.equal(releases.length, 1, `${file}: one release badge`);
    const status = all.find(el => hasClass(el, 'v3-status') && elements(el).includes(releases[0]));
    assert.ok(status, `${file}: the release badge is in the status line`);
    const tag = releases[0].properties.dataRelease;
    if (releaseTag) assert.equal(tag, releaseTag, `${file}: the release badge names ${tag}, not the newest stable tag ${releaseTag}`);
    const want = releaseBadge(tag, lang);
    assert.equal(releases[0].properties.href, want.href, `${file}: release badge href`);
    const images = elements(releases[0]).filter(el => el.tagName === 'img');
    assert.equal(images.length, 1, `${file}: the release badge is one image`);
    for (const key of ['src', 'alt', 'width', 'height']) assert.equal(String(images[0].properties[key]), String(want[key]), `${file}: release badge ${key}`);
    assert.equal(images[0].properties.loading, undefined, `${file}: the release badge is in the first view: no lazy loading`);
  } else {
    assert.equal(releases.length, 0, `${file}: the release badge belongs to the home pages only`);
  }
  const rows = all.filter(el => hasClass(el, 'project-badges'));
  if (!INDEX_PAGES[file]) {
    assert.equal(rows.length, 0, `${file}: the strip belongs to the index pages only`);
    continue;
  }
  const [pageRef] = INDEX_PAGES[file];
  assert.equal(pageRef, ref, file);
  assert.equal(rows.length, 1, `${file}: exactly one strip of development practices`);
  const h1 = all.find(el => el.tagName === 'h1' && el.properties.id === '_top');
  assert.ok(h1, `${file}: h1#_top`);
  assert.ok(all.indexOf(h1) < all.indexOf(rows[0]), `${file}: the strip comes after the heading`);
  assert.ok(!all.some(el => hasClass(el, 'hero-heading') && elements(el).includes(rows[0])), `${file}: the strip is outside the heading's block`);
  if (HOME_PAGES.includes(file)) {
    const home = all.find(el => hasClass(el, 'home-v3'));
    const children = (home.children ?? []).filter(el => el.type === 'element');
    const at = children.indexOf(rows[0]);
    assert.ok(at > 0 && hasClass(children[at - 1], 'v3-intro') && children[at + 1]?.tagName === 'section', `${file}: the strip stands between the hero and the first section`);
  }
  assert.equal(rows[0].tagName, 'ul', file);
  assert.ok(rows[0].properties.ariaLabel, `${file}: the strip has a name`);
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
assert.equal(starCounts.size, 1, `the GitHub links of the pages carry different star counts: ${[...starCounts].join(', ')}`);
const [starCount] = starCounts;
if (givenStars) assert.equal(starCount, `${givenStars.count} ${givenStars.date}`, `the pages carry the star count ${starCount}, not the given ${givenStars.count} of ${givenStars.date}`);
console.log(`check-project-badges: the 4 index pages have one strip of the exact workflow, OpenSSF and license badges for next or master after the h1; ${pages.length - 4} other pages have none; the home pages name the release ${releaseTag ? `${releaseTag}, the newest stable tag` : 'a stable tag (no tags in this checkout to compare)'}; ${pages.length} pages carry the star count ${starCount === 'none' ? 'none' : starCount}${givenStars ? ', as given' : ''}; ${pages.length} footers hold text links only with the version's LICENSE link; no external fetch in this static check`);

if (browserCheck) {
  const { chromium, webkit } = await import('playwright');
  const { serve } = await import('./lib/serve.mjs');
  const { readOnlyContext } = await import('./lib/read-only-browser.mjs');
  const server = await serve(dist);
  fs.mkdirSync(out, { recursive: true });
  const routes = { '/': 'next', '/ja/': 'next', '/v2/': 'master', '/v2/ja/': 'master' };
  const records = [];
  const total = Object.keys(routes).length * 2 * 3;
  let complete = false;
  // Geometry of the strip, the heading and the line above the strip, in CSS px.
  const measure = page => page.evaluate(() => {
    const box = el => { const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height }; };
    const row = document.querySelector('.project-badges');
    // The element above the strip: the status line of the hero on / and
    // /ja/, the heading on /v2/ and /v2/ja/.
    const above = document.querySelector('.home-v3 .v3-status') ?? document.querySelector('h1#_top');
    const release = document.querySelector('.release-badge');
    return {
      row: box(row),
      above: box(above),
      h1: box(document.querySelector('h1#_top')),
      release: release && { link: box(release), image: box(release.querySelector('img')), status: box(release.closest('.v3-status')) },
      links: [...row.querySelectorAll('a')].map(box),
      images: [...row.querySelectorAll('img')].map(el => ({ ...box(el), attrWidth: Number(el.getAttribute('width')), attrHeight: Number(el.getAttribute('height')), complete: el.complete, naturalWidth: el.naturalWidth, external: /^https:/.test(el.getAttribute('src')) })),
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
        for (const [route, ref] of Object.entries(routes)) {
          const loaded = {};
          const home = !route.startsWith('/v2/');
          const want = projectBadges(ref, 'en');
          // The space above the strip (home-v3.css, site.css): 32 px below
          // the status line of the hero (24 px up to 800 px), 16 px below
          // the title of /v2/ and /v2/ja/.
          const spaceAbove = home ? (width > 800 ? 32 : 24) : 16;
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
              assert.equal(m.images.length, want.length, `${label}: ${want.length} badges`);
              m.images.forEach((image, i) => {
                assert.ok(Math.abs(image.width - image.attrWidth) < 0.5 && Math.abs(image.height - image.attrHeight) < 0.5, `${label}: badge ${i} is ${image.width} by ${image.height}, not ${image.attrWidth} by ${image.attrHeight}`);
                assert.ok(image.left >= 0 && image.right <= width, `${label}: badge ${i} clips at ${width}`);
              });
              const external = m.images.filter(image => image.external);
              if (!failing) assert.ok(m.images.every(image => image.complete && image.naturalWidth > 0), `${label}: every badge decodes`);
              else assert.ok(external.every(image => image.naturalWidth === 0), `${label}: the external badges failed`);
              assert.ok(Math.abs(m.row.left - m.h1.left) < 1 && Math.abs(m.links[0].left - m.h1.left) < 1, `${label}: the strip starts at ${m.row.left} and its first badge at ${m.links[0].left}, the heading at ${m.h1.left}`);
              assert.ok(Math.abs(m.row.top - m.above.bottom - spaceAbove) < 1, `${label}: ${m.row.top - m.above.bottom} px above the strip, not ${spaceAbove}`);
              const tops = [...new Set(m.links.map(link => Math.round(link.top)))];
              // One line in the 1032 px of the home page at 1440 px; two in the 720 px
              // column of the documentation of /v2/ and /v2/ja/.
              assert.ok(tops.length <= (phone ? 4 : home ? 1 : 2), `${label}: the strip takes ${tops.length} lines at ${width} px`);
              m.links.forEach((link, i) => {
                assert.ok(link.height >= 24, `${label}: badge link ${i} is ${link.height} px high, under 24 (4.9)`);
                const next = m.links[i + 1];
                if (next && Math.round(next.top) === Math.round(link.top)) assert.ok(Math.abs(next.left - link.right - 8) < 1, `${label}: ${next.left - link.right} px between badges ${i} and ${i + 1}, not 8`);
              });
              assert.ok(m.scrollWidth <= m.innerWidth + 1, `${label}: no horizontal page scroll`);
              // 4.4: the heading of an index page takes one line at 1440 px
              // and at most two at 402 px.
              assert.ok(m.h1Lines >= 1 && m.h1Lines <= (phone ? 2 : 1), `${label}: the heading takes ${m.h1Lines} lines at ${width} px`);
              if (home) {
                assert.ok(m.release, `${label}: release badge`);
                assert.ok(Math.abs(m.release.image.height - 20) < 0.5 && m.release.link.height >= 24, `${label}: the release badge is ${m.release.image.height} px high in a link of ${m.release.link.height} px`);
                assert.ok(m.release.link.top >= m.release.status.top - 0.5 && m.release.link.bottom <= m.release.status.bottom + 0.5 && m.release.link.right <= width, `${label}: the release badge stands in the status line`);
              }
              if (failing) {
                const base = loaded.light;
                for (const key of ['top', 'left', 'width', 'height']) assert.ok(Math.abs(m.row[key] - base.row[key]) < 0.5, `${label}: the strip's ${key} changed from ${base.row[key]} to ${m.row[key]} when the images failed`);
                assert.deepEqual(blocked.length, external.length, `${label}: the ${external.length} external images were refused`);
              } else {
                loaded[colorScheme] = m;
                // Keyboard order through the strip. WebKit's native link
                // navigation uses Option-Tab, as in check-focus.mjs.
                await page.locator('.project-badges a').first().focus();
                for (let i = 1; i < want.length; i++) {
                  await page.keyboard.press(phone ? 'Alt+Tab' : 'Tab', { delay: 60 });
                  assert.equal(await page.evaluate(i => document.activeElement === document.querySelectorAll('.project-badges a')[i], i), true, `${label}: Tab reaches badge ${i}`);
                }
                await page.evaluate(() => document.activeElement.blur());
                assert.deepEqual(blocked, [], `${label}: only same-origin GET and the badge stand-ins are allowed`);
              }
              const name = `${engineName}-${width}-${route.replaceAll('/', '-').replace(/^-|-$/g, '') || 'home'}-${colorScheme}${failing ? '-failing' : ''}.png`;
              const scrollY = await page.evaluate(() => scrollY);
              await page.screenshot({ path: path.join(out, name), fullPage: true, clip: { x: 0, y: 0, width, height: Math.ceil(scrollY + m.row.bottom + 32) } });
              assert.deepEqual(errors, [], `${label}: no page exception`);
              records.push({ route, engine: engineName, width, colorScheme, failing, rowLines: tops.length, headingLines: m.h1Lines, spaceAboveStrip: m.row.top - m.above.bottom, stripTop: m.row.top, file: name });
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
  console.log(`check-project-badges: ${records.length} states of the strip at Chromium ${patternsFor('chromium')[0].width} px and WebKit ${patternsFor('webkit')[0].width} px with the local stand-ins (/, /ja/, /v2/, /v2/ja/; light, dark, and light with the external images failing): sizes, left edge, the space above the strip, line counts of the strip and the heading, the release badge in the status line, keyboard order, and the strip's box kept when the images fail`);
}
