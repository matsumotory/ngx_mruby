import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { compareBuilds, snapshotHtml } from './check-parity.mjs';
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-parity-'));
const base = path.join(tmp, 'base'), head = path.join(tmp, 'head');
fs.mkdirSync(base); fs.mkdirSync(head);
const page = `<!DOCTYPE html><html lang="ja" dir="ltr" data-theme="dark" data-has-sidebar data-has-toc><head><title>Guide</title><meta name="description" content="Description"><meta property="og:title" content="Guide"><meta name="twitter:card" content="summary"><link rel="canonical" href="https://example.com/ja/"><link rel="alternate" hreflang="en" href="https://example.com/"><link rel="alternate" hreflang="ja" href="https://example.com/ja/"><meta data-pagefind-meta="identifiers[content]" content="Method"></head><body><main><h1 id="_top">Guide</h1><aside data-notice="untranslated">English source</aside><div lang="en" data-pagefind-body class="sl-markdown-content"><div class="sl-heading-wrapper"><h2 id="topic">Topic</h2><a class="sl-anchor-link" href="#topic"><span class="sr-only">Section titled Topic</span></a></div><p>Hello <a href="/start/">start</a>.</p></div></main></body></html>`;
const xml = `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml"><url><loc>https://example.com/ja/</loc><xhtml:link rel="alternate" hreflang="en" href="https://example.com/"/></url></urlset>`;
const write = (dir, name, text) => { fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true }); fs.writeFileSync(path.join(dir, name), text); };
let count = 0;
try {
  for (const dir of [base, head]) { write(dir, 'index.html', page); write(dir, 'sitemap-0.xml', xml); }
  assert.deepEqual(compareBuilds(base, head).failures, []); count++;
  const snap = snapshotHtml(page);
  assert.equal(snap.html.dataTheme, 'dark');
  assert.equal(snap.alternates.length, 2);
  assert.equal(snap.pagefind.length, 2); count++;
  for (const [from, to, expected] of [
    ['lang="ja"', 'lang="en"', 'html'],
    ['data-theme="dark"', 'data-theme="light"', 'html'],
    ['data-has-toc', '', 'html'],
    ['<title>Guide', '<title>Other', 'title'],
    ['content="Description"', 'content="Changed"', 'meta'],
    ['property="og:title" content="Guide"', 'property="og:title" content="Other"', 'meta'],
    ['name="twitter:card" content="summary"', 'name="twitter:card" content="other"', 'meta'],
    ['rel="canonical" href="https://example.com/ja/"', 'rel="canonical" href="https://example.com/no/"', 'canonical'],
    ['hreflang="ja" href="https://example.com/ja/"', 'hreflang="ja" href="https://example.com/no/"', 'alternates'],
    ['id="topic"', 'id="different"', 'headings'],
    ['<h2 id="topic">Topic</h2>', '<h3 id="topic">Topic</h3>', 'headings'],
    ['Hello', 'Goodbye', 'content'],
    ['href="/start/"', 'href="/wrong/"', 'content'],
    ['<p>Hello', '<section>Hello', 'content'],
    ['lang="en" data-pagefind-body', 'lang="ja" data-pagefind-body', 'fallback'],
    ['English source', 'Missing translation', 'notices'],
    ['data-pagefind-body', 'data-pagefind-ignore', 'pagefind'],
    ['content="Method"', 'content="DifferentMethod"', 'pagefind'],
  ]) {
    write(head, 'index.html', page.replace(from, to));
    assert(compareBuilds(base, head).failures.some((s) => s.includes(`${expected} differs`)), `missed ${expected}: ${from}`); count++;
  }
  write(head, 'index.html', page.replace('sl-markdown-content', 'doc-content').replace('sl-heading-wrapper', 'heading-wrapper').replace('sl-anchor-link', 'heading-anchor'));
  assert.deepEqual(compareBuilds(base, head).failures, []); count++;
  for (const [from, to] of [['href="/nav/"', 'href="/wrong/"'], ['Navigation', 'Wrong label'], ['aria-current="page"', 'aria-current="false"']]) {
    const navPage = page.replace('<main>', '<header><a href="/nav/" aria-current="page">Navigation</a></header><main>');
    write(base, 'index.html', navPage);
    write(head, 'index.html', navPage.replace(from, to));
    assert(compareBuilds(base, head).failures.includes('index.html: navigation differs')); count++;
  }
  write(base, 'index.html', page);
  write(head, 'index.html', page.replace('</main>', '<nav>Unexpected pagination</nav></main>'));
  assert(compareBuilds(base, head).failures.includes('index.html: mainText differs')); count++;
  write(head, 'index.html', page);
  write(head, 'sitemap-0.xml', xml.replace('href="https://example.com/"', 'href="https://example.com/wrong/"'));
  assert(compareBuilds(base, head).failures.some((s) => s.startsWith('sitemap-0.xml:'))); count++;
  write(head, 'sitemap-0.xml', xml.replace('<loc>https://example.com/ja/', '<loc>https://example.com/no/'));
  assert(compareBuilds(base, head).failures.some((s) => s.startsWith('sitemap-0.xml:'))); count++;
  write(head, 'sitemap-0.xml', xml);
  write(head, 'extra.html', page);
  assert(compareBuilds(base, head).failures.some((s) => s.startsWith('built file set'))); count++;
  fs.unlinkSync(path.join(head, 'extra.html'));
  write(base, '_astro/index.ABCDEFGH.js', 'old bundle');
  write(head, '_astro/index.IJKLMNOP.js', 'new bundle');
  assert.deepEqual(compareBuilds(base, head).failures, []); count++;
  write(head, '_astro/extra.QRSTUVWX.js', 'unexpected bundle');
  assert(compareBuilds(base, head).failures.includes('hashed asset inventory differs')); count++;
  fs.unlinkSync(path.join(head, '_astro/extra.QRSTUVWX.js'));
  for (const dir of [base, head]) write(dir, 'googleabc123.html', 'google-site-verification: googleabc123.html');
  assert.deepEqual(compareBuilds(base, head).failures, []); count++;
  write(head, 'googleabc123.html', 'changed');
  assert(compareBuilds(base, head).failures.some((s) => s.includes('ownership verification differs'))); count++;
  write(head, 'googleabc123.html', 'google-site-verification: googleabc123.html');
  write(head, 'extra.svg', '<svg/>');
  assert(compareBuilds(base, head).failures.some((s) => s.startsWith('built file set'))); count++;
  console.log(`test-parity: ${count} positive/negative fixtures passed`);
} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
