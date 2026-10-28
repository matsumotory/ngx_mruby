// The language checks of step 3 (docs/proposals/site.md, 4.10 and
// section 6), on the built site served over HTTP:
//
// - every language link of every page (header, menu and footer) leads to
//   the same path under the other language's prefix, and that URL answers
//   200 (the 404 page leads to the other language's home page);
// - / requested with Accept-Language: ja, and opened in a browser whose
//   language is Japanese, answers 200 with the English page, without a
//   redirect in HTTP, a meta refresh or a script that moves to /ja/.
//
//   node scripts/check-language-links.mjs [--dist DIR]
import path from 'node:path';
import { chromium } from 'playwright';
import { elements, hasClass, readHtml } from './lib/html.mjs';
import { htmlFiles } from './lib/site.mjs';
import { serve } from './lib/serve.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist') };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

// /x/index.html -> /x/, 404.html -> /404/ (GitHub Pages serves it there)
const pathOf = (file) => (file === '404.html' ? '/404/' : file === 'ja/404.html' ? '/ja/404/' : `/${file.replace(/index\.html$/, '')}`);
const other = (p) => (p === '/ja/' || p.startsWith('/ja/') ? p.slice(3) || '/' : `/ja${p}`);

async function main() {
  const opt = args();
  const server = await serve(opt.dist);
  const problems = [];
  let links = 0;
  const answered = new Map();
  const status = async (url) => {
    if (!answered.has(url)) answered.set(url, (await fetch(server.url + url, { redirect: 'manual' })).status);
    return answered.get(url);
  };
  try {
    for (const file of htmlFiles(opt.dist)) {
      const here = pathOf(file);
      const found = elements(readHtml(path.join(opt.dist, file))).filter((e) => e.tagName === 'a' && hasClass(e, 'language-link'));
      if (!found.length) problems.push(`${here}: no language link (4.10)`);
      for (const a of found) {
        links++;
        const href = String(a.properties?.href ?? '');
        // The 404 page leads to the other language's home page
        const want = file.endsWith('404.html') ? other(here.replace(/404\/$/, '')) : other(here);
        if (href !== want) problems.push(`${here}: a language link to ${href}, expected ${want}`);
        else {
          const s = await status(href);
          if (s !== 200) problems.push(`${here}: the language link ${href} answers ${s}`);
        }
      }
    }
    const res = await fetch(`${server.url}/`, { redirect: 'manual', headers: { 'Accept-Language': 'ja,en;q=0.5' } });
    const body = await res.text();
    if (res.status !== 200) problems.push(`/ with Accept-Language: ja answers ${res.status}${res.headers.get('location') ? ` to ${res.headers.get('location')}` : ''}`);
    if (!/<html[^>]*\blang="en"/.test(body)) problems.push('/ with Accept-Language: ja is not the English page');
    if (/<meta[^>]+http-equiv=["']?refresh/i.test(body)) problems.push('/ has a meta refresh');
    const browser = await chromium.launch();
    const context = await browser.newContext({ locale: 'ja-JP', extraHTTPHeaders: { 'Accept-Language': 'ja,en;q=0.5' } });
    const tab = await context.newPage();
    await tab.goto(`${server.url}/`, { waitUntil: 'load' });
    await tab.waitForTimeout(500);
    const final = new URL(tab.url()).pathname;
    const lang = await tab.evaluate(() => document.documentElement.lang);
    if (final !== '/' || lang !== 'en') problems.push(`/ opened in a browser in Japanese ends at ${final} with lang="${lang}", not at / in English`);
    await browser.close();
  } finally {
    await server.close();
  }
  for (const p of problems) console.log(p);
  const summary = `${links} language links of ${htmlFiles(opt.dist).length} pages, ${answered.size} target URLs`;
  if (problems.length) {
    console.log(`check-language-links: ${problems.length} problem(s); ${summary}`);
    process.exit(1);
  }
  console.log(`check-language-links: ok; ${summary} answer 200; / with Accept-Language: ja answers 200 in English without a redirect`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
