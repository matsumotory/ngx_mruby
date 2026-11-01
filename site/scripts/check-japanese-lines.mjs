// The browser checks of the Japanese pages of step 5 (docs/proposals/site.md,
// section 6; 4.4 and 4.9), in Chromium and WebKit (Playwright), on every
// page under /ja/ that comes from a Japanese source (generated/pages.json),
// except the home page, whose heading check-styles.mjs checks, in the light
// theme, in the two patterns of lib/patterns.mjs: PC at full screen (1440 by
// 900 px in Chromium) and iPhone Safari (402 by 664 px in WebKit):
//
// - at 1440 px, at most 40 Japanese characters (kana, kanji and full-width
//   punctuation) on a line of body text (4.4, "Measure");
// - at 1440 px, the line height of body text 1.75 to 2.0 times its font
//   size (4.4, "Line height");
// - the page title (h1) on one line at 402 px (4.4, "Page titles");
// - at 402 px, the right edge of Japanese text blocks of two or more lines:
//   the longest line ends less than 2 em from the block's right edge; an h2
//   takes at most two lines and its longest line ends less than 6 em from
//   the edge (4.9);
// - in both patterns, no paragraph, list item, caption, table cell, definition
//   or heading whose last line holds one or two characters (the owner's
//   rule for text);
// - in both patterns, every diagram label is 14 px or more and its text
//   stays inside its place (3.5);
// - the notice above an English page under /ja/ (FallbackContentNotice.astro):
//   on one page of each kind of notice, its last line and, at 402 px, its
//   right edge.
//
//   node scripts/check-japanese-lines.mjs [--dist DIR] [--manifest FILE] [--engine chromium|webkit] [--ja-face noto] [--pages /ja/a/,/ja/b/]
//
// Japanese text takes Hiragino Sans where the system has it (macOS) and the
// served Noto Sans JP elsewhere (Linux, CI), so its lines break at other
// places. --ja-face noto sets Japanese in Noto Sans JP on any system, so
// that a run on macOS sees what CI sees. --pages limits the run to the
// pages named.
//
// --engine runs one engine, and so its pattern only. It exits 1 and lists
// every failure by page, engine, size and element.
import fs from 'node:fs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { PC, PHONE, patternsFor } from './lib/patterns.mjs';
import { GENERATED_REFERENCE, japaneseNoticePages, loadManifest, manifestFile, NOT_TRANSLATED_YET } from './lib/site.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
// The release notes in Japanese, longer than any other page, still have
// last lines of one or two characters and table cells with long names that
// end far from the right edge. The 2.x notes come from master as released
// (2.7.4 included), and their heading 「アップグレードの前に読む挙動の変更」
// takes two lines at 402 px. Their failures are printed as notes until the
// pull request of step 5 that rewrites them removes them from this list;
// every other Japanese page fails.
const NOTES_ONLY = ['/ja/releases/v2.7.1/', '/ja/releases/v2.7.2/', '/ja/releases/v2.7.3/', '/ja/releases/v2.7.4/', '/ja/releases/v3.0.0/'];

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist'), manifest: manifestFile, engines: ['chromium', 'webkit'], pages: null };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--manifest') out.manifest = path.resolve(a[++i]);
    else if (a[i] === '--engine') out.engines = [a[++i]];
    else if (a[i] === '--pages') out.pages = a[++i].split(',').filter(Boolean);
    else if (a[i] === '--ja-face' && a[i + 1] === 'noto') {
      out.noto = true;
      i++;
    } else {
      console.error(`check-japanese-lines: unknown argument ${a[i]}`);
      process.exit(2);
    }
  }
  return out;
}

// Runs in the page: returns a list of failures and counts.
function inspect(cfg) {
  const fails = [];
  const counts = { blocks: 0, lines: 0, labels: 0, maxChars: 0 };
  const name = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += `#${el.id}`;
    const cls = [...el.classList].filter((c) => !c.startsWith('astro-')).slice(0, 2);
    if (cls.length) s += `.${cls.join('.')}`;
    return s;
  };
  const snippet = (el) => el.textContent.trim().replace(/\s+/g, ' ').slice(0, 30);
  // The lines of the block, so that a failure in CI shows where the runner
  // broke them (its font rendering differs from that of other systems)
  const fail = (el, what) => fails.push(`${name(el)}: ${what}: "${snippet(el)}..." lines: ${lines(el).map((l) => `[${l.text.trim()}]`).join(' ')}`);
  const visible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') return false;
    if (el.closest('.sr-only, [hidden], template')) return false;
    return el.getClientRects().length > 0;
  };
  const JA = /[　-〿぀-ヿ㐀-鿿豈-﫿＀-￯]/;
  const lines = (el) => {
    const out = new Map();
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    const range = document.createRange();
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (n.parentElement.closest('.sr-only, svg')) continue;
      for (let i = 0; i < n.length; i++) {
        range.setStart(n, i);
        range.setEnd(n, i + 1);
        const r = range.getClientRects()[0];
        if (!r || r.width === 0) continue;
        const top = Math.round(r.top + r.height / 2);
        const key = [...out.keys()].find((k) => Math.abs(k - top) < r.height / 2) ?? top;
        const line = out.get(key) ?? { right: -Infinity, text: '' };
        line.text += n.data[i];
        line.right = Math.max(line.right, r.right);
        out.set(key, line);
      }
    }
    return [...out.values()];
  };
  // A page that shows an English page under /ja/: only its Japanese notice
  if (cfg.noticeOnly) {
    const notice = document.querySelector('[data-notice]');
    if (!notice) return { fails: ['the page has no [data-notice]'], counts };
    const ls = lines(notice);
    counts.lines += ls.length;
    if (ls.length >= 2 && ls.at(-1).text.trim().length <= 2) fail(notice, `the last line holds "${ls.at(-1).text.trim()}", ${ls.at(-1).text.trim().length} character(s)`);
    if (cfg.phone && ls.length >= 2) {
      const box = notice.getBoundingClientRect();
      const fsz = parseFloat(getComputedStyle(notice).fontSize);
      const gap = box.right - parseFloat(getComputedStyle(notice).paddingRight) - Math.max(...ls.map((l) => l.right));
      if (gap >= 2 * fsz) fail(notice, `the longest line ends ${gap.toFixed(1)} px from the right edge, 2 em (${2 * fsz} px) or more`);
    }
    return { fails, counts };
  }
  const content = document.querySelector('.site-markdown-content');
  if (!content) return { fails: ['the page has no .site-markdown-content'], counts };
  // Body text: paragraphs and list items outside code, diagrams, tables
  // and samples; captions (p.caption) have the caption size and line height
  const body = [...content.querySelectorAll('p:not(.caption), li')].filter((el) => visible(el) && !el.closest('.expressive-code, figure, table, .not-content') && !el.querySelector('p, ul, ol'));
  if (cfg.pc) {
    for (const el of body) {
      for (const l of lines(el)) {
        const n = [...l.text].filter((c) => JA.test(c)).length;
        counts.maxChars = Math.max(counts.maxChars, n);
        if (n > 40) fail(el, `a line of ${n} Japanese characters, over 40`);
      }
      const cs = getComputedStyle(el);
      const ratio = parseFloat(cs.lineHeight) / parseFloat(cs.fontSize);
      if (!(ratio >= 1.749 && ratio <= 2.001)) fail(el, `line height ${cs.lineHeight} at ${cs.fontSize}, ${ratio.toFixed(3)} times, outside 1.75 to 2.0`);
    }
  }
  // The page title
  const h1 = document.querySelector('h1#_top');
  if (!h1) fails.push('the page has no h1#_top');
  else if (cfg.phone) {
    const n = lines(h1).length;
    if (n > 1) fail(h1, `the page title takes ${n} lines at ${cfg.width} px, over 1`);
  }
  // The right edge at the phone width (4.9)
  if (cfg.phone) {
    for (const el of content.querySelectorAll('p, li, figcaption, figcaption > span, td, th, dd, h2')) {
      if (!visible(el) || el.closest('.expressive-code, .diagram-grid') || el.querySelector('p, ul, ol')) continue;
      if (getComputedStyle(el).display === 'flex') continue;
      if (!JA.test(el.textContent)) continue;
      const ls = lines(el);
      if (ls.length < 2) continue;
      counts.blocks++;
      const box = el.getBoundingClientRect();
      const pad = parseFloat(getComputedStyle(el).paddingRight);
      const fsz = parseFloat(getComputedStyle(el).fontSize);
      const gap = box.right - pad - Math.max(...ls.map((l) => l.right));
      if (el.tagName === 'H2') {
        if (ls.length > 2) fail(el, `a Japanese h2 of ${ls.length} lines at ${cfg.width} px, over 2`);
        if (gap >= 6 * fsz) fail(el, `the longest line of a Japanese h2 ends ${gap.toFixed(1)} px from the right edge, 6 em or more`);
      } else if (gap >= 2 * fsz) fail(el, `the longest line ends ${gap.toFixed(1)} px from the right edge, 2 em (${2 * fsz} px) or more`);
    }
  }
  // Last lines of one or two characters
  for (const el of document.querySelectorAll('main :is(p, li, figcaption, figcaption > span, td, th, dd, h1, h2, h3, h4)')) {
    if (!visible(el) || el.closest('.expressive-code, .diagram-grid') || el.querySelector('p, ul, ol')) continue;
    const ls = lines(el);
    counts.lines += ls.length;
    if (ls.length < 2) continue;
    const last = ls.at(-1).text.trim();
    if (last.length <= 2) fail(el, `the last line holds "${last}", ${last.length} character(s)`);
  }
  // Diagram labels in both patterns
  {
    for (const label of document.querySelectorAll('figure.diagram .diagram-label')) {
      if (!visible(label)) continue;
      counts.labels++;
      for (const t of [label, ...label.querySelectorAll('*')]) {
        const own = [...t.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
        if (own && parseFloat(getComputedStyle(t).fontSize) < 13.95) fail(t, `a diagram label at ${getComputedStyle(t).fontSize}, under 14 px`);
      }
      if (label.scrollWidth > label.clientWidth + 1 || label.scrollHeight > label.clientHeight + 1) fail(label, `a diagram label overflows its place (${label.scrollWidth}x${label.scrollHeight} in ${label.clientWidth}x${label.clientHeight})`);
      const box = label.getBoundingClientRect();
      const range = document.createRange();
      range.selectNodeContents(label);
      for (const r of [...range.getClientRects()].filter((x) => x.width > 0)) {
        if (r.left < box.left - 0.5 || r.right > box.right + 0.5 || r.top < box.top - 0.5 || r.bottom > box.bottom + 0.5) {
          fail(label, 'the text of a diagram label goes outside its place');
          break;
        }
      }
    }
  }
  return { fails, counts };
}

async function main() {
  const opt = args();
  if (!fs.existsSync(path.join(opt.dist, 'index.html'))) {
    console.error(`check-japanese-lines: ${opt.dist} has no index.html: run npm run build first`);
    process.exit(2);
  }
  const pages = opt.pages ?? loadManifest(opt.manifest).filter((p) => p.lang === 'ja' && !p.home).map((p) => `/${p.route}/`);
  // One page of each kind of notice (its English text is not measured); with
  // --pages, the English fallback pages among the pages named
  const noticePages = opt.pages ? japaneseNoticePages(opt.pages) : [GENERATED_REFERENCE[0], NOT_TRANSLATED_YET[0]].filter(Boolean).map((r) => `/ja/${r}/`);
  if (!opt.pages) pages.push(...noticePages);
  if (!pages.length) {
    console.error('check-japanese-lines: no Japanese page to check');
    process.exit(1);
  }
  const server = await serve(opt.dist);
  const failures = [];
  const notes = [];
  let loads = 0;
  let blocks = 0;
  let labels = 0;
  let maxChars = 0;
  for (const engineName of opt.engines) {
    const browser = await { chromium, webkit }[engineName].launch();
    for (const size of patternsFor(engineName)) {
      const context = await browser.newContext({ viewport: size, colorScheme: 'light' });
      for (const page of pages) {
        const tab = await context.newPage();
        const response = await tab.goto(server.url + page, { waitUntil: 'load' });
        if (!response || response.status() !== 200) {
          failures.push(`${page} ${engineName} ${size.width}: answers ${response?.status()}`);
          await tab.close();
          continue;
        }
        if (opt.noto) await tab.addStyleTag({ content: ':root { --font-ja-faces: "Noto Sans JP Variable", "Noto Sans JP" !important; }' });
        await tab.evaluate(() => document.fonts.ready);
        const result = await tab.evaluate(inspect, { width: size.width, phone: size.width === PHONE.width, pc: size.width === PC.width, noticeOnly: noticePages.includes(page) });
        // A note leaves out the lines of its block, which only failures need
        for (const f of result.fails) (NOTES_ONLY.includes(page) ? notes : failures).push(`${page} ${engineName} ${size.width}x${size.height}: ${NOTES_ONLY.includes(page) ? f.replace(/ lines: .*$/, '') : f}`);
        blocks += result.counts.blocks;
        labels += result.counts.labels;
        maxChars = Math.max(maxChars, result.counts.maxChars);
        loads++;
        await tab.close();
      }
      await context.close();
    }
    await browser.close();
  }
  await server.close();
  // One note per page and element, whatever the engine or size
  const distinctNotes = [...new Set(notes.map((n) => n.replace(/^(\S+) \S+ \S+: /, '$1: ')))];
  for (const n of distinctNotes) console.log(`note: ${n}`);
  if (distinctNotes.length) console.log(`check-japanese-lines: ${distinctNotes.length} note(s) on the pages of NOTES_ONLY`);
  for (const f of failures) console.log(f);
  const summary = `${loads} page loads of ${pages.length} Japanese pages in ${opt.engines.join(' and ')}${opt.noto ? ' (Noto Sans JP)' : ''} at ${opt.engines.flatMap(patternsFor).map((s) => s.width).join(' and ')} px; ${blocks} blocks of two or more lines measured at ${PHONE.width} px, ${labels} diagram labels, at most ${maxChars} Japanese characters on a line of body text at 1440 px`;
  if (failures.length) {
    console.log(`check-japanese-lines: ${failures.length} failure(s); ${summary}`);
    // exitCode, not process.exit(): stdout to a pipe (CI) is written
    // asynchronously, and process.exit() dropped the lines still queued
    process.exitCode = 1;
    return;
  }
  console.log(`check-japanese-lines: ok; ${summary}`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
