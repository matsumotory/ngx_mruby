// The screenshots of step 3 (docs/proposals/site.md, section 6): the home
// page, the page of the request phases diagram and a reference page, in
// English and Japanese, light and dark, at 320 by 664, 390 by 664 and 1440
// by 900 px, in Chromium and WebKit; and the two images that the owner
// reviews in step 3, the definition of the home page (3.3 item 1) and the
// first diagram, in Chromium, light and dark, at 390 and 1440 px.
//
//   node scripts/screenshots.mjs [--dist DIR] [--out DIR]
//
// It reads dist/ (npm run build) and writes DIR/pages/<engine>-<page>-
// <lang>-<theme>-<size>-first.png (the first screen) and -full.png (the
// whole page), DIR/review/<part>-<lang>-<theme>-<width>.png and
// DIR/index.md, the list of the files (default DIR: build-screenshots/).
// site.yml uploads DIR as the workflow artifact `screenshots`; no image is
// committed or attached to the pull request (4.12, the owner's decision of
// 2026-10-19).
import fs from 'node:fs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

export const PAGES = [
  { id: 'home', path: { en: '/', ja: '/ja/' } },
  { id: 'request-phases', path: { en: '/concepts/request-phases/', ja: '/ja/concepts/request-phases/' } },
  { id: 'directives', path: { en: '/reference/directives/', ja: '/ja/reference/directives/' } },
];
export const SIZES = [
  { width: 320, height: 664 },
  { width: 390, height: 664 },
  { width: 1440, height: 900 },
];
const THEMES = ['light', 'dark'];
const ENGINES = { chromium, webkit };

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist'), out: path.join(SITE, 'build-screenshots') };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--out') out.out = path.resolve(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

async function open(browser, url, size, theme) {
  const context = await browser.newContext({ viewport: size, colorScheme: theme, deviceScaleFactor: size.width < 640 ? 2 : 1 });
  const tab = await context.newPage();
  await tab.goto(url, { waitUntil: 'load' });
  await tab.evaluate(() => document.fonts.ready);
  return { context, tab };
}

async function main() {
  const opt = args();
  if (!fs.existsSync(path.join(opt.dist, 'index.html'))) throw new Error(`${opt.dist} has no index.html: run npm run build first`);
  const server = await serve(opt.dist);
  const pagesDir = path.join(opt.out, 'pages');
  const reviewDir = path.join(opt.out, 'review');
  fs.mkdirSync(pagesDir, { recursive: true });
  fs.mkdirSync(reviewDir, { recursive: true });
  let count = 0;
  // A failed shot does not stop the others: the images written so far are
  // uploaded, and the script exits 1 at the end.
  const failures = [];
  for (const [engineName, engine] of Object.entries(ENGINES)) {
    const browser = await engine.launch();
    for (const page of PAGES) {
      for (const lang of ['en', 'ja']) {
        for (const theme of THEMES) {
          for (const size of SIZES) {
            const { context, tab } = await open(browser, server.url + page.path[lang], size, theme);
            const base = `${engineName}-${page.id}-${lang}-${theme}-${size.width}x${size.height}`;
            try {
              await tab.screenshot({ path: path.join(pagesDir, `${base}-first.png`) });
              count++;
              // Browsers on Linux refuse an image of more than 32767 device
              // pixels: a long page is taken at one device pixel per CSS
              // pixel, and cut at 32000 px when it is still longer.
              const height = await tab.evaluate(() => document.documentElement.scrollHeight);
              const scale = height * (size.width < 640 ? 2 : 1) > 32000 ? 'css' : 'device';
              const clip = height > 32000 ? { x: 0, y: 0, width: size.width, height: 32000 } : undefined;
              await tab.screenshot({ path: path.join(pagesDir, `${base}-full.png`), fullPage: true, scale, clip });
              count++;
            } catch (e) {
              failures.push(`${base}: ${e.message.split('\n')[0]}`);
            }
            await context.close();
          }
        }
      }
    }
    await browser.close();
  }
  // What the owner reviews in step 3: the definition (the heading and the
  // first paragraph of the home page) and the request phases diagram.
  const review = [];
  {
    const browser = await chromium.launch();
    for (const lang of ['en', 'ja']) {
      for (const theme of THEMES) {
        for (const size of [SIZES[1], SIZES[2]]) {
          const home = await open(browser, server.url + PAGES[0].path[lang], size, theme);
          const box = await home.tab.evaluate(() => {
            const h1 = document.querySelector('h1#_top').getBoundingClientRect();
            const p = document.querySelector('.home .lede').getBoundingClientRect();
            return { x: 0, y: Math.max(0, h1.top - 24 + scrollY), width: innerWidth, height: p.bottom - h1.top + 48 };
          });
          const f1 = path.join(reviewDir, `definition-${lang}-${theme}-${size.width}.png`);
          await home.tab.screenshot({ path: f1, clip: box, fullPage: true });
          await home.context.close();
          const phases = await open(browser, server.url + PAGES[1].path[lang], size, theme);
          // The figure, with its caption
          const f2 = path.join(reviewDir, `request-phases-${lang}-${theme}-${size.width}.png`);
          await phases.tab.locator('figure.diagram').screenshot({ path: f2 });
          await phases.context.close();
          review.push(f1, f2);
          count += 2;
        }
      }
    }
    await browser.close();
  }
  await server.close();
  const lines = ['# Screenshots of step 3 (docs/proposals/site.md, section 6)', ''];
  lines.push('## For the owner: the definition and the request phases diagram (Chromium)', '');
  for (const f of review) lines.push(`- review/${path.basename(f)}`);
  lines.push('', '## Pages: Chromium and WebKit, light and dark, 320x664, 390x664, 1440x900', '');
  for (const f of fs.readdirSync(pagesDir).sort()) lines.push(`- pages/${f}`);
  fs.writeFileSync(path.join(opt.out, 'index.md'), `${lines.join('\n')}\n`);
  for (const f of failures) console.log(`screenshots: failed: ${f}`);
  console.log(`screenshots: ${count} screenshots in ${opt.out} (${review.length} for the owner's review in review/)`);
  if (failures.length) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
