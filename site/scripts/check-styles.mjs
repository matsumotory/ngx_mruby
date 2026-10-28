// The browser checks of step 2 (docs/proposals/site.md, section 6), on
// computed styles in Chromium and WebKit (Playwright), for every page of
// PAGES in light and dark, at 390 by 664 and 1440 by 900 px:
//
// - font sizes: every visible text has a size of the scale of its page's
//   language (4.4), the roles take their size, and nothing is below 14 px;
// - colors: every computed text, background, border, outline, decoration,
//   fill and stroke color is a token value of the palette or transparent,
//   code blocks and diagrams included (4.6); the colors in the style
//   attributes of highlighted spans are code colors, text or text-muted;
//   in dark, no color is #000000 and surface is lighter than bg (4.7);
// - monospace only where 4.3, item 2 puts it;
// - no box-shadow, text-shadow, backdrop-filter or gradient (4.3 item 5),
//   also with the search dialog open (while its results load and after
//   they have loaded), and at 390 px with the menu open;
// - margins, paddings, gaps and radii from the sets of 4.5 (computed values
//   through the CSS Typed OM, so that auto and percentages stay keywords);
// - durations of 4.8: 200 ms or less, 0 under prefers-reduced-motion, no
//   animation running after the load;
// - at most 90 characters per line of English body text at 1440 px (4.4);
// - no horizontal scroll of the page, and at 390 px the right edge of
//   Japanese text blocks (4.9);
// - with JavaScript off, the OS setting chooses the theme (4.7).
//
//   node scripts/check-styles.mjs [--dist DIR] [--engine chromium|webkit]
//
// DIR defaults to dist-specimens/, the build of `SITE_SPECIMENS=1 npm run
// build`, whose specimen pages hold a diagram, code blocks and tables. It
// exits 1 and lists every failure by page, engine, theme, size and element.
import fs from 'node:fs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { themeColors } from './lib/tokens.mjs';
import { allowedSpanColors } from './lib/code-themes.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

// Three page types (4.3 item 5, 4.6, 4.8): the home page, a reference page
// with a diagram and a sample, and pages rendered from docs/; in English
// and Japanese.
export const PAGES = ['/specimens/home/', '/specimens/reference/', '/ja/specimens/home/', '/ja/specimens/reference/', '/directives/', '/install/', '/ja/'];
const SIZES = [
  { width: 390, height: 664 },
  { width: 1440, height: 900 },
];

// 4.4, table "Scale": the sizes other than the home page heading.
const SCALE = {
  en: { h1: 32, h2: 26, h3: 22, body: 16, nav: 15, caption: 14 },
  ja: { h1: 26, h2: 22, h3: 18, body: 16, nav: 15, caption: 14 },
};
// The home page heading: clamp(2rem, 1.4rem + 2vw, 2.375rem) and
// clamp(1.625rem, 1.2rem + 1.5vw, 2rem).
function homeSize(lang, vw) {
  const clamp = (lo, v, hi) => Math.min(Math.max(lo, v), hi);
  return lang === 'ja' ? clamp(26, 19.2 + 0.015 * vw, 32) : clamp(32, 22.4 + 0.02 * vw, 38);
}
// 4.5: --space-1 to --space-9, and 20 px, the narrow gutter of 4.5.
const SPACES = [0, 4, 8, 12, 16, 24, 32, 48, 64, 80];
const GUTTER_NARROW = 20;
const RADII = [0, 8, 12, 999];

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist-specimens'), engines: ['chromium', 'webkit'] };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--engine') out.engines = [a[++i]];
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

// Runs in the page: returns a list of failures.
function inspect(cfg) {
  const fails = [];
  const root = document.documentElement;
  const lang = root.lang === 'ja' ? 'ja' : 'en';
  const scale = cfg.scale[lang];
  const sizes = new Set(Object.values(scale));
  const isHome = !!document.querySelector('.home-specimen');
  const tokens = new Set(cfg.tokens);
  const spans = new Set(cfg.spans);
  const name = (el) => {
    let s = el.tagName.toLowerCase();
    if (el.id) s += `#${el.id}`;
    const cls = [...el.classList].filter((c) => !c.startsWith('astro-')).slice(0, 2);
    if (cls.length) s += `.${cls.join('.')}`;
    const p = el.parentElement;
    return p && p !== document.body ? `${p.tagName.toLowerCase()}${p.classList[0] ? `.${p.classList[0]}` : ''} > ${s}` : s;
  };
  const fail = (el, what) => fails.push(`${name(el)}: ${what}`);
  const visible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') return false;
    if (el.closest('.sr-only, [hidden], template')) return false;
    return el.getClientRects().length > 0;
  };
  const hex = (c) => {
    const m = c.match(/^rgba?\(([^)]+)\)$/);
    if (!m) return { other: c };
    const [r, g, b, a = '1'] = m[1].split(/[ ,/]+/).filter(Boolean);
    if (parseFloat(a) === 0) return { transparent: true };
    const h = '#' + [r, g, b].map((x) => Math.round(parseFloat(x)).toString(16).padStart(2, '0')).join('');
    return parseFloat(a) < 1 ? { other: `${h} at alpha ${a}` } : { hex: h };
  };
  const checkColor = (el, prop, value, where = '') => {
    const c = hex(value);
    if (c.transparent) return;
    if (c.other) return fail(el, `${prop}${where} ${c.other} is not a token value`);
    if (!tokens.has(c.hex)) fail(el, `${prop}${where} ${c.hex} is not a token value`);
    if (cfg.theme === 'dark' && c.hex === '#000000') fail(el, `${prop}${where} is #000000 in dark`);
  };
  const all = [document.body, ...document.querySelectorAll('body *')];
  for (const el of all) {
    if (!visible(el)) continue;
    const cs = getComputedStyle(el);
    const isSvg = el instanceof SVGElement;
    // Colors (4.6)
    for (const [where, style] of [['', cs], ['::before', getComputedStyle(el, '::before')], ['::after', getComputedStyle(el, '::after')]]) {
      if (where && (style.content === 'none' || style.content === 'normal' || style.display === 'none')) continue;
      if (!isSvg) checkColor(el, 'color', style.color, where);
      checkColor(el, 'background-color', style.backgroundColor, where);
      for (const side of ['top', 'right', 'bottom', 'left']) {
        if (parseFloat(style[`border-${side}-width`]) > 0 && style[`border-${side}-style`] !== 'none') checkColor(el, `border-${side}-color`, style[`border-${side}-color`], where);
      }
      if (style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0) checkColor(el, 'outline-color', style.outlineColor, where);
      if (!isSvg && style.textDecorationLine !== 'none') checkColor(el, 'text-decoration-color', style.textDecorationColor, where);
      // 4.3 item 5
      if (style.boxShadow !== 'none') fail(el, `box-shadow${where} ${style.boxShadow}`);
      if (style.textShadow !== 'none') fail(el, `text-shadow${where} ${style.textShadow}`);
      const bf = style.backdropFilter ?? style.webkitBackdropFilter;
      if (bf && bf !== 'none') fail(el, `backdrop-filter${where} ${bf}`);
      if (/gradient/.test(style.backgroundImage)) fail(el, `background-image${where} ${style.backgroundImage.slice(0, 80)}`);
    }
    if (isSvg) {
      for (const p of ['fill', 'stroke']) {
        const v = cs[p];
        if (v && v !== 'none' && !v.startsWith('url(')) checkColor(el, p, v);
      }
      continue;
    }
    // Font sizes (4.4): elements with their own text
    const ownText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim());
    if (ownText) {
      const fs = parseFloat(cs.fontSize);
      const allowed = new Set(sizes);
      if (isHome) allowed.add(cfg.home);
      if (![...allowed].some((s) => Math.abs(s - fs) < 0.05)) fail(el, `font-size ${fs}px is not a size of the ${lang} scale (${[...allowed].join(', ')})`);
      if (fs < 13.95) fail(el, `font-size ${fs}px is below 14 px`);
    }
    // Spacing and radii (4.5), computed values through the Typed OM
    const map = el.computedStyleMap();
    for (const p of ['margin-top', 'margin-right', 'margin-bottom', 'margin-left', 'padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'row-gap', 'column-gap']) {
      // Starlight's layout reserves the size of its fixed header, its
      // mobile table of contents and its sidebar with padding: sizes of
      // those elements, not spacing between content.
      if (cfg.layoutOffsets.some(([sel, prop]) => prop === p && el.matches(sel))) continue;
      const v = map.get(p)?.toString() ?? '';
      if (/^(auto|normal)$/.test(v) || v.includes('%')) continue;
      const m = v.match(/^(-?[0-9.]+)px$/);
      if (!m) {
        fail(el, `${p} ${v} is not a length in px`);
        continue;
      }
      const n = Math.abs(parseFloat(m[1]));
      const ok = cfg.spaces.some((s) => Math.abs(s - n) < 0.01) || (/(left|right)$/.test(p) && Math.abs(n - cfg.gutterNarrow) < 0.01 && cfg.width <= 640);
      if (!ok) fail(el, `${p} ${v} is not a value of 4.5`);
    }
    for (const p of ['border-top-left-radius', 'border-top-right-radius', 'border-bottom-right-radius', 'border-bottom-left-radius']) {
      const v = map.get(p)?.toString() ?? '';
      if (v === '50%') continue;
      const m = v.match(/^([0-9.]+)px$/);
      if (!m || !cfg.radii.some((r) => Math.abs(r - parseFloat(m[1])) < 0.01)) fail(el, `${p} ${v} is not 0, 8, 12, 999 px or 50%`);
    }
    // Durations (4.8)
    const durations = `${cs.transitionDuration},${cs.animationDuration}`.split(',').map((d) => parseFloat(d) * (d.trim().endsWith('ms') ? 1 : 1000));
    const longest = Math.max(...durations.filter((d) => !Number.isNaN(d)));
    if (longest > (cfg.reduced ? 0 : 200)) fail(el, `a transition or animation of ${longest} ms${cfg.reduced ? ' under reduced motion' : ''}`);
    if (parseFloat(cs.transitionDuration) > 0) {
      for (const tp of cs.transitionProperty.split(',').map((x) => x.trim())) {
        if (!cfg.transitions.includes(tp)) fail(el, `transition-property ${tp} is not one of 4.8`);
      }
    }
  }
  // Highlighted spans of Expressive Code (4.6)
  for (const el of document.querySelectorAll('.expressive-code [style]')) {
    for (const m of el.getAttribute('style').matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
      if (!spans.has(m[0].toLowerCase())) fail(el, `a highlighted span carries ${m[0]}, not a code color, text or text-muted`);
    }
  }
  if (document.querySelector('.is-terminal')) fail(document.querySelector('.is-terminal'), 'a terminal frame (is-terminal)');
  // Monospace only where 4.3, item 2 puts it
  const first = (el) => getComputedStyle(el).fontFamily.split(',')[0].trim().replace(/^["']|["']$/g, '');
  const mono = cfg.mono;
  for (const el of document.querySelectorAll('code, pre, kbd, samp, .site-title, td.num, th.num')) {
    if (visible(el) && first(el) !== mono) fail(el, `font-family starts with ${first(el)}, not ${mono}`);
  }
  for (const el of document.querySelectorAll('.sl-markdown-content :is(p, li, h1, h2, h3, h4, td:not(.num), th:not(.num), figcaption), h1#_top, .sidebar-content a, starlight-toc a, .starlight-aside__title')) {
    if (visible(el) && !el.closest('pre, code, .expressive-code') && first(el) === mono) fail(el, `font-family starts with the monospace face ${mono}`);
  }
  // Roles of the scale
  const role = (sel, px, what) => {
    for (const el of document.querySelectorAll(sel)) if (visible(el) && Math.abs(parseFloat(getComputedStyle(el).fontSize) - px) > 0.05) fail(el, `${what} at ${getComputedStyle(el).fontSize}, expected ${px}px`);
  };
  role('h1#_top', isHome ? cfg.home : scale.h1, isHome ? 'the home page heading' : 'the page title');
  role('.sl-markdown-content h2:not(.not-content *)', scale.h2, 'h2');
  role('.sl-markdown-content h3:not(.not-content *)', scale.h3, 'h3');
  role('.sl-markdown-content > p:not(.caption), .sl-markdown-content li > p', scale.body, 'body text');
  role('.expressive-code pre, .sl-markdown-content :is(td, th)', scale.nav, 'code blocks and tables');
  role('figcaption, .sl-markdown-content p.caption', scale.caption, 'captions');
  // Dark: surface lighter than bg (4.7)
  if (cfg.theme === 'dark') {
    const lum = (h) => {
      const c = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    };
    const rs = getComputedStyle(root);
    const bg = rs.getPropertyValue('--color-bg-primary').trim();
    const surface = rs.getPropertyValue('--color-bg-tertiary').trim();
    if (!(lum(surface) > lum(bg))) fails.push(`:root: surface ${surface} is not lighter than bg ${bg}`);
  }
  // No horizontal scroll of the page (4.9)
  if (document.scrollingElement.scrollWidth > innerWidth) fails.push(`the page scrolls sideways: ${document.scrollingElement.scrollWidth} px wide at ${innerWidth} px`);
  // Lines (4.4, 4.9)
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
        const line = out.get(key) ?? { chars: 0, right: -Infinity, text: '' };
        line.chars += 1;
        line.text += n.data[i];
        line.right = Math.max(line.right, r.right);
        out.set(key, line);
      }
    }
    return [...out.values()].map((l) => ({ ...l, chars: l.text.trimEnd().length }));
  };
  if (lang === 'en' && cfg.width === 1440) {
    for (const el of document.querySelectorAll('.sl-markdown-content :is(p, li)')) {
      if (!visible(el) || el.closest('.expressive-code, .diagram, table')) continue;
      for (const l of lines(el)) if (l.chars > 90) fail(el, `a line of ${l.chars} characters, over 90: "${l.text.slice(0, 40)}..."`);
    }
  }
  if (lang === 'ja' && cfg.width === 390) {
    for (const el of document.querySelectorAll('.sl-markdown-content :is(p, li, figcaption, td, th), .sl-markdown-content h2')) {
      if (!visible(el) || el.closest('.expressive-code, .diagram-grid') || el.querySelector('p, ul, ol')) continue;
      // A block of Latin text only (such as "server, location" in a table)
      // wraps between words, as English does (4.9).
      if (!/[\u3040-\u30ff\u3400-\u9fff]/.test(el.textContent)) continue;
      const ls = lines(el);
      if (ls.length < 2) continue;
      const box = el.getBoundingClientRect();
      const pad = parseFloat(getComputedStyle(el).paddingRight);
      const fsz = parseFloat(getComputedStyle(el).fontSize);
      const gap = box.right - pad - Math.max(...ls.map((l) => l.right));
      if (el.tagName === 'H2') {
        if (ls.length > 2) fail(el, `a Japanese h2 of ${ls.length} lines at 390 px, over 2`);
        if (gap >= 6 * fsz) fail(el, `the longest line of a Japanese h2 ends ${gap.toFixed(1)} px from the right edge, 6 em or more`);
      } else if (gap >= 2 * fsz) fail(el, `the longest line ends ${gap.toFixed(1)} px from the right edge, 2 em (${2 * fsz} px) or more`);
    }
  }
  return fails;
}

function shadowsOnly() {
  const fails = [];
  const els = [document.documentElement, document.body, ...document.querySelectorAll('body *')];
  for (const el of els) {
    for (const where of ['', '::before', '::after', '::backdrop']) {
      if (where === '::backdrop' && el.tagName !== 'DIALOG') continue;
      const s = getComputedStyle(el, where || null);
      const bf = s.backdropFilter ?? s.webkitBackdropFilter;
      const tag = `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${el.classList[0] ? '.' + el.classList[0] : ''}${where}`;
      if (s.boxShadow !== 'none') fails.push(`${tag}: box-shadow ${s.boxShadow}`);
      if (s.textShadow !== 'none') fails.push(`${tag}: text-shadow ${s.textShadow}`);
      if (bf && bf !== 'none') fails.push(`${tag}: backdrop-filter ${bf}`);
      if (/gradient/.test(s.backgroundImage)) fails.push(`${tag}: background-image holds a gradient`);
    }
  }
  return fails;
}

async function main() {
  const opt = args();
  if (!fs.existsSync(path.join(opt.dist, 'specimens/home/index.html'))) throw new Error(`${opt.dist} has no specimen pages: run SITE_SPECIMENS=1 npm run build first`);
  const server = await serve(opt.dist);
  const failures = [];
  let loads = 0;
  let menus = 0;
  let searches = 0;
  const transitions = ['color', 'background-color', 'border-color', 'border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color', 'outline-color', 'text-decoration-color', 'opacity', 'transform'];
  for (const engineName of opt.engines) {
    const engine = { chromium, webkit }[engineName];
    const browser = await engine.launch();
    const monoFace = (await (async () => {
      const css = fs.readFileSync(path.join(SITE, 'src/styles/tokens.css'), 'utf8');
      return css.match(/--font-mono-face:\s*"([^"]+)"/)[1];
    })());
    for (const page of PAGES) {
      for (const theme of ['light', 'dark']) {
        const colors = themeColors(theme);
        const tokens = Object.values(colors);
        for (const size of SIZES) {
          for (const reduced of [false, true]) {
            if (reduced && size.width !== 1440) continue;
            const context = await browser.newContext({ viewport: size, colorScheme: theme, reducedMotion: reduced ? 'reduce' : 'no-preference' });
            const tab = await context.newPage();
            await tab.goto(server.url + page, { waitUntil: 'load' });
            await tab.evaluate(() => document.fonts.ready);
            loads++;
            const tag = `${page} ${engineName} ${theme} ${size.width}x${size.height}${reduced ? ' reduced-motion' : ''}`;
            const running = await tab.evaluate(() => document.getAnimations().filter((a) => a.playState === 'running').length);
            if (running) failures.push(`${tag}: ${running} animation(s) running after the load`);
            const lang = await tab.evaluate(() => document.documentElement.lang);
            const cfg = {
              scale: SCALE,
              home: homeSize(lang === 'ja' ? 'ja' : 'en', size.width),
              tokens,
              spans: [...allowedSpanColors()],
              theme,
              spaces: SPACES,
              gutterNarrow: GUTTER_NARROW,
              radii: RADII,
              width: size.width,
              reduced,
              transitions,
              mono: monoFace,
              layoutOffsets: [
                ['.main-frame', 'padding-top'],
                ['.main-frame', 'padding-left'],
                ['.main-frame', 'padding-right'],
                ['.right-sidebar', 'padding-top'],
              ],
            };
            for (const f of await tab.evaluate(inspect, cfg)) failures.push(`${tag}: ${f}`);
            if (!reduced) {
              // The search dialog open, and on narrow screens the menu
              const search = tab.locator('button[data-open-modal]');
              if (await search.isVisible()) {
                try {
                  await search.click({ timeout: 5000 });
                } catch {
                  failures.push(`${tag}: the search button cannot be clicked (another element covers it)`);
                  await context.close();
                  continue;
                }
                // Pagefind shows each result first as a placeholder, while
                // the result's fragment loads, and then as the result. The
                // fragments are held until the placeholders have been
                // checked, so that both states are checked on every run,
                // whatever the timing of the requests.
                let release;
                let heldRequests = 0;
                const held = new Promise((resolve) => (release = resolve));
                await tab.route('**/pagefind/fragment/**', async (route) => {
                  heldRequests++;
                  await held;
                  await route.continue();
                });
                await tab.locator('dialog[open] input').fill('filter');
                const states = [];
                const placeholders = tab.locator('#starlight__search .pagefind-ui__loading');
                // Only a timeout means that a state did not come; any other
                // error is a fault of this check and stops it.
                const timedOut = (e) => {
                  if (e?.name !== 'TimeoutError') throw e;
                };
                try {
                  await placeholders.first().waitFor({ timeout: 10000 });
                  for (const f of await tab.evaluate(shadowsOnly)) failures.push(`${tag} search open, loading: ${f}`);
                  for (const f of await tab.evaluate(inspect, { ...cfg, width: 0 })) if (!/scrolls sideways/.test(f)) failures.push(`${tag} search open, loading: ${f}`);
                  // The loading state was checked only if the fragments were
                  // held and the placeholders were still there afterwards.
                  if (heldRequests === 0 || (await placeholders.count()) === 0) failures.push(`${tag}: the fragments of the search results were not held (${heldRequests} held), so the placeholders may not have been checked`);
                  else states.push('loading');
                } catch (e) {
                  timedOut(e);
                  failures.push(`${tag}: the search for "filter" showed no result placeholder within 10 s`);
                }
                release();
                try {
                  await tab.waitForFunction(() => !document.querySelector('#starlight__search .pagefind-ui__loading') && document.querySelector('#starlight__search .pagefind-ui__result-link'), null, { timeout: 10000 });
                  states.push('settled');
                  for (const f of await tab.evaluate(shadowsOnly)) failures.push(`${tag} search open: ${f}`);
                  for (const f of await tab.evaluate(inspect, { ...cfg, width: 0 })) if (!/scrolls sideways/.test(f)) failures.push(`${tag} search open: ${f}`);
                } catch (e) {
                  timedOut(e);
                  failures.push(`${tag}: the results of the search for "filter" did not finish loading within 10 s`);
                }
                await tab.unroute('**/pagefind/fragment/**');
                if (states.length === 2) searches++;
                await tab.keyboard.press('Escape');
              }
              const menu = tab.locator('button.sl-menu-button');
              if (await menu.isVisible()) {
                try {
                  await menu.click({ timeout: 5000 });
                } catch {
                  failures.push(`${tag}: the menu button cannot be clicked`);
                }
                await tab.waitForTimeout(100);
                if (!(await tab.locator('#starlight__sidebar:popover-open').count())) failures.push(`${tag}: the menu did not open`);
                menus++;
                for (const f of await tab.evaluate(shadowsOnly)) failures.push(`${tag} menu open: ${f}`);
                for (const f of await tab.evaluate(inspect, { ...cfg, width: 0 })) if (!/scrolls sideways/.test(f)) failures.push(`${tag} menu open: ${f}`);
              }
            }
            await context.close();
          }
        }
        // 4.7: without JavaScript the OS setting chooses the theme
        const context = await browser.newContext({ viewport: SIZES[1], colorScheme: theme, javaScriptEnabled: false });
        const tab = await context.newPage();
        await tab.goto(server.url + page, { waitUntil: 'load' });
        const bg = await tab.evaluate(() => getComputedStyle(document.body).backgroundColor);
        const want = colors['--color-bg-primary'];
        const got = '#' + bg.match(/\d+/g).slice(0, 3).map((x) => Number(x).toString(16).padStart(2, '0')).join('');
        if (got !== want) failures.push(`${page} ${engineName} ${theme} without JavaScript: the page background is ${got}, not bg ${want}`);
        await context.close();
        loads++;
      }
    }
    await browser.close();
  }
  await server.close();
  // One line per distinct failure; the same element fails on many pages.
  const counted = new Map();
  for (const f of failures) {
    const key = f.replace(/^\S+ \S+ \S+ \S+( reduced-motion)?( search open(, loading)?| menu open)?: /, '');
    const e = counted.get(key) ?? { n: 0, first: f };
    e.n++;
    counted.set(key, e);
  }
  for (const { n, first } of counted.values()) console.log(`${first}${n > 1 ? ` (and ${n - 1} more page, engine, theme or size)` : ''}`);
  if (failures.length) {
    console.log(`check-styles: ${failures.length} failure(s), ${counted.size} distinct; ${loads} page loads of ${PAGES.length} pages in ${opt.engines.join(' and ')}`);
    process.exit(1);
  }
  console.log(`check-styles: ok; ${loads} page loads of ${PAGES.length} pages in ${opt.engines.join(' and ')}, light and dark, ${SIZES.map((s) => `${s.width}x${s.height}`).join(' and ')}; ${searches} with the search dialog open (results loading and loaded), ${menus} with the menu open`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
