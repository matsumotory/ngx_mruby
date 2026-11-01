// Checks of step 6 (docs/proposals/site.md, 3.4 and section 6) on the
// built site with the 2.x pages of scripts/build-v2.mjs in dist/v2/:
//
// - every page of generated/pages-v2.json is built under /v2/, and every
//   HTML file under /v2/ is a page of the 2.x build (its canonical URL is
//   under https://ngx.mruby.org/v2/);
// - every 2.x page carries the 2.x banner of 3.4 (data-banner="v2"), in
//   the language of the page, with its link to the 3.x documentation; no
//   3.x page carries it;
// - the version link of the footer (4.10) leads from each 3.x page to /v2/
//   (/v2/ja/ from Japanese pages), and from each 2.x page to /docs/
//   (/ja/docs/); the language link of each 2.x page leads to the same
//   path under the other language's prefix within /v2/;
// - 2.x and 3.x search results do not mix: in Chromium, with the built site
//   served over HTTP, the search of a 3.x page and of a 2.x page, in English
//   and in Japanese, for a word that both versions document, shows results,
//   all of them pages of the same version, and the page loads the search
//   index of its own version only (/pagefind/ or /v2/pagefind/).
//
// The links of the 2.x pages are checked by check-built-links.mjs, which
// reads dist/v2/ too (no broken link under /v2/).
//
//   node scripts/check-v2.mjs [--dist DIR] [--manifest FILE] [--no-browser]
//
// --manifest names the list of the 2.x pages (default
// generated/pages-v2.json); --no-browser leaves out the search check.
//
// Exit status: 0 when every check passes, 1 otherwise (each problem is
// printed with its page), 2 on a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent } from './lib/html.mjs';
import { distDir, fileOfRoute, finish, htmlFiles, SITE_URL, V2_DIR, v2ManifestFile } from './lib/site.mjs';
import { serve } from './lib/serve.mjs';

function usage(message) {
  console.error(`check-v2: ${message}`);
  console.error('usage: node scripts/check-v2.mjs [--dist DIR] [--manifest FILE] [--no-browser]');
  process.exit(2);
}
const opt = { dist: distDir, manifest: v2ManifestFile, browser: true };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--no-browser') opt.browser = false;
  else if ((argv[i] === '--dist' || argv[i] === '--manifest') && i + 1 < argv.length) opt[argv[i].slice(2)] = path.resolve(argv[++i]);
  else usage(`unknown argument ${argv[i]}`);
}
const v2 = path.join(opt.dist, V2_DIR);
if (!fs.existsSync(path.join(v2, 'index.html'))) usage(`${v2} has no index.html: run node scripts/build-v2.mjs --tree DIR first`);
if (!fs.existsSync(opt.manifest)) usage(`${opt.manifest} is missing: run node scripts/build-v2.mjs --tree DIR first`);
const { commit, pages } = JSON.parse(fs.readFileSync(opt.manifest, 'utf8'));

const problems = [];
const prefix = `${V2_DIR}/`;
const all = htmlFiles(opt.dist, { v2: true });
const files2 = all.filter((f) => f.startsWith(prefix));
const files3 = htmlFiles(opt.dist);
const urlPath = (file) => `/${file.replace(/index\.html$/, '')}`;

for (const page of pages) {
  const file = `${prefix}${fileOfRoute(page.route)}`;
  if (!files2.includes(file)) problems.push(`${page.source}: its page /${file.replace(/index\.html$/, '')} is not built`);
}

function langOf(tree) {
  const html = elements(tree).find((e) => e.tagName === 'html');
  return String(html?.properties?.lang ?? '');
}
function attr(e, name) {
  return e.properties?.[name] === undefined ? undefined : String(e.properties[name]);
}

let banners = 0;
for (const file of files2) {
  const tree = readHtml(path.join(opt.dist, file));
  const where = urlPath(file);
  const ja = langOf(tree) === 'ja';
  const all = elements(tree);
  const canonical = all.find((e) => e.tagName === 'link' && [].concat(e.properties?.rel ?? []).includes('canonical'));
  if (!canonical || !attr(canonical, 'href').startsWith(`${SITE_URL}/${prefix}`)) {
    problems.push(`${where}: its canonical URL ${canonical ? attr(canonical, 'href') : '(none)'} is not under ${SITE_URL}/${prefix}`);
  }
  const found = all.filter((e) => attr(e, 'dataBanner') === 'v2');
  if (found.length !== 1) {
    problems.push(`${where}: ${found.length} 2.x banners (data-banner="v2"), not 1`);
  } else {
    const banner = found[0];
    const link = elements(banner).find((e) => e.tagName === 'a');
    const want = ja ? '/ja/docs/' : '/docs/';
    if (!link || attr(link, 'href') !== want) problems.push(`${where}: the 2.x banner has no link to ${want}`);
    const text = textContent(banner);
    if (!/2\.x/.test(text) || !/3\.x/.test(text)) problems.push(`${where}: the 2.x banner does not name 2.x and 3.x: "${text.trim()}"`);
    if (ja && !/[ぁ-んァ-ン]/.test(text)) problems.push(`${where}: the 2.x banner of a Japanese page is not in Japanese`);
    if (!ja && /[ぁ-んァ-ン]/.test(text)) problems.push(`${where}: the 2.x banner of an English page is not in English`);
    banners++;
  }
  const version = all.filter((e) => e.tagName === 'a' && hasClass(e, 'version-link'));
  const want = ja ? '/ja/docs/' : '/docs/';
  if (version.length === 0 || version.some((e) => attr(e, 'href') !== want)) {
    problems.push(`${where}: the version link of the footer does not lead to ${want} (${version.map((e) => attr(e, 'href')).join(', ') || 'none'})`);
  }
  const rest = where.slice(`/${V2_DIR}`.length);
  const other = `/${V2_DIR}${ja ? rest.replace(/^\/ja(\/|$)/, '/') : `/ja${rest}`}`;
  for (const e of all.filter((x) => x.tagName === 'a' && hasClass(x, 'language-link'))) {
    if (attr(e, 'href') !== other) problems.push(`${where}: a language link leads to ${attr(e, 'href')}, not ${other}`);
  }
}

for (const file of files3) {
  const tree = readHtml(path.join(opt.dist, file));
  const where = urlPath(file);
  const all = elements(tree);
  if (all.some((e) => attr(e, 'dataBanner') === 'v2')) problems.push(`${where}: a 3.x page carries the 2.x banner`);
  const ja = langOf(tree) === 'ja';
  const want = ja ? '/v2/ja/' : '/v2/';
  const version = all.filter((e) => e.tagName === 'a' && hasClass(e, 'version-link'));
  if (version.length === 0 || version.some((e) => attr(e, 'href') !== want)) {
    problems.push(`${where}: the version link of the footer does not lead to ${want} (${version.map((e) => attr(e, 'href')).join(', ') || 'none'})`);
  }
}

// The search check: a word of the directive reference of both versions.
const WORD = 'mruby_content_handler';
const SEARCHES = [
  { page: '/reference/directives/', version: 3 },
  { page: '/ja/reference/directives/', version: 3 },
  { page: '/v2/reference/directives/', version: 2 },
  { page: '/v2/ja/reference/directives/', version: 2 },
];
let searched = 0;
if (opt.browser) {
  const { chromium } = await import('playwright');
  const server = await serve(opt.dist);
  const browser = await chromium.launch();
  try {
    for (const s of SEARCHES) {
      const tab = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      const loaded = [];
      tab.on('request', (r) => {
        const p = new URL(r.url()).pathname;
        if (p.includes('/pagefind/')) loaded.push(p);
      });
      const where = `${s.page} (search for ${WORD})`;
      try {
        await tab.goto(`${server.url}${s.page}`, { waitUntil: 'load' });
        await tab.locator('button[data-open-modal]').click({ timeout: 5000 });
        await tab.locator('#site__search input').fill(WORD);
        await tab.waitForFunction(() => !document.querySelector('#site__search .pagefind-ui__loading') && document.querySelector('#site__search .pagefind-ui__result-link'), null, { timeout: 15000 });
        const hrefs = await tab.$$eval('#site__search .pagefind-ui__result-link', (links) => links.map((a) => new URL(a.href).pathname));
        const own = (p) => (s.version === 2 ? p.startsWith('/v2/') : !p.startsWith('/v2/'));
        const strays = hrefs.filter((p) => !own(p));
        if (strays.length) problems.push(`${where}: ${strays.length} of ${hrefs.length} results are pages of the other version: ${[...new Set(strays)].join(', ')}`);
        const index = s.version === 2 ? '/v2/pagefind/' : '/pagefind/';
        const other = loaded.filter((p) => !p.startsWith(index));
        if (!loaded.length) problems.push(`${where}: the page loaded no search index`);
        if (other.length) problems.push(`${where}: the page loaded files outside ${index}: ${[...new Set(other)].join(', ')}`);
        searched++;
      } catch (e) {
        problems.push(`${where}: no search result within 15 s (${e.message.split('\n')[0]})`);
      } finally {
        await tab.close();
      }
    }
  } finally {
    await browser.close();
    await server.close();
  }
}

finish(
  'check-v2',
  problems,
  `${pages.length} 2.x pages of ${String(commit).slice(0, 12)}, ${files2.length} HTML files under /v2/ with ${banners} banners and version links to /docs/, ${files3.length} 3.x pages without it and with version links to /v2/; ${opt.browser ? `${searched} of ${SEARCHES.length} searches in Chromium showed results` : 'search not checked (--no-browser)'}`,
);
