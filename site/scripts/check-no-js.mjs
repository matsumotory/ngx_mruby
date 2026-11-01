// Check of step 1 (docs/proposals/site.md, section 6): pages read with
// JavaScript off.
//
//   node scripts/check-no-js.mjs [--dist DIR] [--repo DIR] [--manifest FILE]
//
// How it is measured. A page reads with JavaScript off when the HTML that
// the server sends, read without running any script, shows the whole text
// of the page's source in <main>. The check parses each built page (it
// runs no script and applies no CSS) and takes the text of <main> that a
// reader sees: it leaves out script, style, template and svg elements,
// elements with the hidden attribute, and the site's sr-only text. It
// splits that text and the source's text into words (runs of letters,
// marks and digits), and checks, for every page with a source in
// generated/pages.json (a route under /ja/ without a Japanese source is
// the English fallback of 3.4):
//
// - the h1 in <main> has the words of the title, the first heading of the
//   source;
// - the words of the title and then of the whole source (text, inline code
//   and code blocks; not URLs, image alternative text or raw HTML) appear
//   in <main> in the same order. Other words may come between them, such
//   as the frame titles of code blocks or the fallback notice;
// - every heading of the source is a heading element of the same level in
//   the content of the page, with the same words, in the same order.
//
// The text of a diagram block is the text of its labels and its caption
// (the generator draws the rest); a sample block is left out, since its
// files are code blocks that check-home.mjs compares on the home pages; and
// the home pages, MDX with components, are left to check-home.mjs.
//
// What it does not measure: CSS that hides content (the screenshots of
// step 3 run in browsers), and what needs scripts besides reading: the
// search, the language picker and the theme switch (5.1, 4.7).
//
// Exit status: 0 when every page passes, 1 otherwise (each problem is
// printed with its page and the line of the source), 2 on a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, findElement, hasClass, readHtml, textContent, visibleText } from './lib/html.mjs';
import { headings, isFirstBlock, parseMarkdown, plainText, textPieces, titleHeading, words } from './lib/markdown.mjs';
import { checkOptions, finish, htmlFiles, loadManifest, pageOfRoute, routeOfFile } from './lib/site.mjs';

const { dist, repo, manifest } = checkOptions();
const pages = loadManifest(manifest);
const problems = [];
const sources = new Map();

function expectedOf(source) {
  if (!sources.has(source)) {
    const text = fs.readFileSync(path.join(repo, source), 'utf8');
    const tree = parseMarkdown(text);
    const title = titleHeading(tree);
    const removed = title && isFirstBlock(tree, title) ? title : undefined;
    const sequence = [];
    for (const word of words(title ? plainText(title, text) : '')) sequence.push({ word, line: title.position.start.line });
    for (const piece of textPieces(tree, text, removed)) {
      for (const word of words(piece.text)) sequence.push({ word, line: piece.line });
    }
    sources.set(source, {
      lines: text.split('\n'),
      title: title ? words(plainText(title, text)) : [],
      sequence,
      headings: headings(tree, removed).map((h) => ({ depth: h.depth, words: words(plainText(h, text)), line: h.position.start.line })),
    });
  }
  return sources.get(source);
}

const same = (a, b) => a.length === b.length && a.every((w, i) => w === b[i]);
let checked = 0;
let wordsChecked = 0;
for (const file of htmlFiles(dist)) {
  const route = routeOfFile(file);
  if (route === null) continue;
  const { page } = pageOfRoute(pages, route);
  if (!page) {
    problems.push(`${file}: no source in docs/ for the route /${route}/`);
    continue;
  }
  // The home pages are MDX with components; check-home.mjs reads them.
  if (page.home) continue;
  checked++;
  const expected = expectedOf(page.source);
  const tree = readHtml(path.join(dist, file));
  const main = findElement(tree, (e) => e.tagName === 'main');
  if (!main) {
    problems.push(`${file}: no <main>`);
    continue;
  }
  const h1 = findElement(main, (e) => e.tagName === 'h1');
  const h1Words = h1 ? words(visibleText(h1)) : [];
  if (!same(h1Words, expected.title)) {
    problems.push(`${file}: the h1 reads "${h1Words.join(' ')}", but the title of ${page.source} is "${expected.title.join(' ')}"`);
  }

  const seen = words(visibleText(main));
  let at = 0;
  for (const { word, line } of expected.sequence) {
    while (at < seen.length && seen[at] !== word) at++;
    if (at === seen.length) {
      problems.push(`${file}: the word "${word}" of ${page.source}:${line} is not in the text of <main> that a reader sees after the words before it (the line: ${expected.lines[line - 1].trim().slice(0, 100)})`);
      break;
    }
    at++;
  }
  wordsChecked += expected.sequence.length;

  const content = findElement(main, (e) => hasClass(e, 'site-markdown-content'));
  const built = content
    ? elements(content)
        .filter((e) => /^h[1-6]$/.test(e.tagName))
        .map((e) => ({ depth: Number(e.tagName[1]), words: words(textContent(e)) }))
    : [];
  let next = 0;
  for (const heading of expected.headings) {
    while (next < built.length && !(built[next].depth === heading.depth && same(built[next].words, heading.words))) next++;
    if (next === built.length) {
      problems.push(`${file}: no h${heading.depth} "${heading.words.join(' ')}" (${page.source}:${heading.line}) in the content after the headings before it`);
      break;
    }
    next++;
  }
}

finish('check-no-js', problems, `${checked} pages and ${wordsChecked} words of their sources checked in the HTML without running scripts, 404.html left out`);
