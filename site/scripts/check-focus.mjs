// The focus check of step 3 (docs/proposals/site.md, 4.9 and section 6):
// tabbing through each page in Chromium and WebKit, at 390 by 664 and 1440
// by 900 px, every element that takes the focus shows a focus ring (an
// outline of 2 px or more, or one that is not none on a focused text
// field) and is not covered by the fixed header (WCAG 2.4.11): its box
// starts below the header, unless it is in the header or the open menu,
// (and Starlight's fixed bar "On this page" below 72rem), and the
// element at the center of its first line box is the element
// itself or inside it.
//
// WebKit's default setting moves Tab only between form controls and
// elements with tabindex; Option-Tab (Alt) also moves to links, so WebKit
// gets Alt+Tab, each key held 60 ms.
//
//   node scripts/check-focus.mjs [--dist DIR] [--engine chromium|webkit]
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
export const PAGES = ['/', '/ja/', '/concepts/request-phases/', '/ja/concepts/request-phases/', '/reference/directives/'];
const SIZES = [
  { width: 390, height: 664 },
  { width: 1440, height: 900 },
];
const MAX_TABS = 120;

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist'), engines: ['chromium', 'webkit'] };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--engine') out.engines = [a[++i]];
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

// Runs in the page: the state of the focused element.
function focused() {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const name = `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${el.classList[0] ? `.${el.classList[0]}` : ''} "${(el.textContent ?? '').trim().slice(0, 30)}"`;
  const cs = getComputedStyle(el);
  const ring = cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 2;
  const r = el.getBoundingClientRect();
  const header = document.querySelector('header.header');
  // The fixed header, and below 72rem Starlight's fixed "On this page" bar
  const toc = document.querySelector('mobile-starlight-toc nav');
  const fixedBottom = (e) => (e && getComputedStyle(e).position === 'fixed' && e.getClientRects().length ? e.getBoundingClientRect().bottom : 0);
  const hb = Math.max(header ? header.getBoundingClientRect().bottom : 0, fixedBottom(toc));
  const inChrome = !!el.closest('header.header, .sidebar-pane, dialog, .sl-skip-link, .sl-menu-button, mobile-starlight-toc');
  const visible = r.width > 0 && r.height > 0;
  let covered = '';
  if (visible && !inChrome) {
    // An element taller than the screen below the header (a table that
    // scrolls in its own box) only needs a part below the header; any
    // other element starts below it
    const tall = r.height > innerHeight - hb;
    if (tall ? r.bottom <= hb : r.top < hb - 0.5) covered = `its top at ${r.top.toFixed(0)} px is under the header, which ends at ${hb.toFixed(0)} px`;
    // A link that wraps has one box per line: the center of its first box
    const first = el.getClientRects()[0] ?? r;
    const cx = Math.min(Math.max(first.left + first.width / 2, 0), innerWidth - 1);
    const cy = Math.min(Math.max(Math.max(first.top, tall ? hb + 1 : first.top) + Math.min(first.height, 40) / 2, 0), innerHeight - 1);
    const at = document.elementFromPoint(cx, cy);
    if (!covered && at && at !== el && !el.contains(at)) covered = `the element at its center is ${at.tagName.toLowerCase()}${at.className && typeof at.className === 'string' ? `.${at.className.split(' ')[0]}` : ''}`;
  }
  return { name, ring, outline: `${cs.outlineStyle} ${cs.outlineWidth}`, covered, visible, key: `${name}@${Math.round(r.top + scrollY)}:${Math.round(r.left)}` };
}

async function main() {
  const opt = args();
  const server = await serve(opt.dist);
  const failures = [];
  let stops = 0;
  for (const engineName of opt.engines) {
    const browser = await { chromium, webkit }[engineName].launch();
    const key = engineName === 'webkit' ? 'Alt+Tab' : 'Tab';
    for (const page of PAGES) {
      for (const size of SIZES) {
        const context = await browser.newContext({ viewport: size });
        const tab = await context.newPage();
        await tab.goto(server.url + page, { waitUntil: 'load' });
        await tab.evaluate(() => document.fonts.ready);
        const tag = `${page} ${engineName} ${size.width}x${size.height}`;
        const seen = new Set();
        let count = 0;
        for (let i = 0; i < MAX_TABS; i++) {
          await tab.keyboard.press(key, { delay: 60 });
          const f = await tab.evaluate(focused);
          if (!f) {
            if (i > 0) break;
            continue;
          }
          if (seen.has(f.key)) break;
          seen.add(f.key);
          if (!f.visible) continue;
          count++;
          if (!f.ring) failures.push(`${tag}: ${f.name}: no focus ring (outline ${f.outline})`);
          if (f.covered) failures.push(`${tag}: ${f.name}: covered: ${f.covered}`);
        }
        if (count < 5) failures.push(`${tag}: only ${count} element(s) took the focus by ${key}`);
        stops += count;
        await context.close();
      }
    }
    await browser.close();
  }
  await server.close();
  for (const f of failures) console.log(f);
  const summary = `${stops} focus stops on ${PAGES.length} pages in ${opt.engines.join(' and ')} at ${SIZES.map((s) => `${s.width}x${s.height}`).join(' and ')}`;
  if (failures.length) {
    console.log(`check-focus: ${failures.length} failure(s); ${summary}`);
    process.exit(1);
  }
  console.log(`check-focus: ok; ${summary}, each with a focus ring of 2 px or more and not covered by the header`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
