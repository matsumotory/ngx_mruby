// The Lighthouse check of step 3 (docs/proposals/site.md, section 6):
// Lighthouse's accessibility category with no failed audit on three page
// types, the home page, a page with a diagram and a reference page, in
// English and Japanese. Lighthouse runs in Playwright's Chromium, which it
// reaches through the remote debugging port, at Lighthouse's default
// mobile emulation, and in the light theme.
//
//   node scripts/check-lighthouse.mjs [--dist DIR] [--page PATH ...]
//
// It exits 1 and lists every audit of the category whose score is below 1,
// by page, with the elements that Lighthouse names.
import path from 'node:path';
import lighthouse from 'lighthouse';
import { chromium } from 'playwright';
import { serve } from './lib/serve.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
export const PAGES = ['/', '/ja/', '/concepts/request-phases/', '/ja/concepts/request-phases/', '/reference/directives/', '/ja/reference/directives/'];

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist'), pages: [] };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--page') out.pages.push(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  if (!out.pages.length) out.pages = PAGES;
  return out;
}

async function main() {
  const opt = args();
  const server = await serve(opt.dist);
  const port = 9300 + Math.floor(Math.random() * 500);
  const browser = await chromium.launch({ args: [`--remote-debugging-port=${port}`] });
  const failures = [];
  const summary = [];
  try {
    for (const page of opt.pages) {
      const result = await lighthouse(server.url + page, { port, output: 'json', logLevel: 'error', onlyCategories: ['accessibility'] });
      const lhr = result.lhr;
      if (lhr.runtimeError) {
        failures.push(`${page}: Lighthouse could not run: ${lhr.runtimeError.message}`);
        continue;
      }
      const category = lhr.categories.accessibility;
      let failed = 0;
      for (const ref of category.auditRefs) {
        const audit = lhr.audits[ref.id];
        if (audit.score === null || audit.score >= 1) continue;
        failed++;
        const items = (audit.details?.items ?? []).slice(0, 5).map((item) => item.node?.selector ?? item.node?.snippet ?? JSON.stringify(item).slice(0, 80));
        failures.push(`${page}: ${audit.id} (${audit.title}), score ${audit.score}${items.length ? `: ${items.join('; ')}` : ''}`);
      }
      summary.push(`${page} ${Math.round(category.score * 100)}`);
      if (!failed && category.score < 1) failures.push(`${page}: the accessibility score is ${category.score} with no failed audit listed`);
    }
  } finally {
    await browser.close();
    await server.close();
  }
  for (const f of failures) console.log(f);
  if (failures.length) {
    console.log(`check-lighthouse: ${failures.length} failed audit(s) on ${opt.pages.length} pages (accessibility scores: ${summary.join(', ')})`);
    process.exit(1);
  }
  console.log(`check-lighthouse: ok; no failed accessibility audit on ${opt.pages.length} pages (scores: ${summary.join(', ')})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
