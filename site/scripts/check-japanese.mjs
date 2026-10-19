// Check of step 1 (docs/proposals/site.md, section 6): a test page from
// docs/ja/ is served under /ja/ with lang="ja", and the <wbr> in its h2 is
// an element of the built h2 (4.4).
//
//   node scripts/check-japanese.mjs [--dist DIR] [--repo DIR] [--manifest FILE]
//
// For every page of generated/pages.json whose source is Japanese
// (docs/ja/<path>.md, or docs/<path>.ja.md):
//
// - the route is /ja/ or under it, and the built page exists;
// - <html> and <main> have lang="ja";
// - each h2 of the source that holds <wbr> has a built h2 with the same
//   text, which holds as many wbr elements and no text "wbr" (an escaped
//   or stripped <wbr> fails).
//
// It fails as well when no page comes from docs/ja/, or when no h2 of
// those pages holds <wbr>: docs/ja/README.md is the test page.
//
// Exit status: 0 when every check passes, 1 otherwise, 2 on a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, findElement, hasClass, readHtml, textContent } from './lib/html.mjs';
import { headings, parseMarkdown, plainText, titleHeading } from './lib/markdown.mjs';
import { checkOptions, fileOfRoute, finish, loadManifest } from './lib/site.mjs';

const { dist, repo, manifest } = checkOptions();
const pages = loadManifest(manifest).filter((p) => p.lang === 'ja');
const problems = [];
const isWbr = (node) => node.type === 'html' && /^<wbr\s*\/?>$/i.test(node.value.trim());
const countWbr = (node) => (isWbr(node) ? 1 : 0) + (node.children ?? []).reduce((n, c) => n + countWbr(c), 0);

let fromDocsJa = 0;
let wbrHeadings = 0;
for (const page of pages) {
  const file = fileOfRoute(page.route);
  if (page.source.startsWith('docs/ja/')) fromDocsJa++;
  if (!(page.route === 'ja' || page.route.startsWith('ja/'))) {
    problems.push(`${page.source}: Japanese, but its route /${page.route}/ is not under /ja/`);
  }
  if (!fs.existsSync(path.join(dist, file))) {
    problems.push(`${file}: missing (source ${page.source})`);
    continue;
  }
  const tree = readHtml(path.join(dist, file));
  const html = findElement(tree, (e) => e.tagName === 'html');
  const main = findElement(tree, (e) => e.tagName === 'main');
  if (html?.properties?.lang !== 'ja') problems.push(`${file}: <html lang="${html?.properties?.lang ?? ''}">, expected "ja"`);
  if (!main) {
    problems.push(`${file}: no <main>`);
    continue;
  }
  if (main.properties?.lang !== 'ja') problems.push(`${file}: <main lang="${main.properties?.lang ?? ''}">, expected "ja"`);

  const content = findElement(main, (e) => hasClass(e, 'sl-markdown-content')) ?? main;
  const built = elements(content).filter((e) => e.tagName === 'h2');
  const text = fs.readFileSync(path.join(repo, page.source), 'utf8');
  const source = parseMarkdown(text);
  const title = titleHeading(source);
  for (const heading of headings(source).filter((h) => h.depth === 2 && h !== title)) {
    const expected = countWbr(heading);
    if (expected === 0) continue;
    wbrHeadings++;
    const label = plainText(heading, text);
    // The built h2 with the same text, a <wbr> shown as text left out.
    const match = built.find((h2) => textContent(h2).replace(/<wbr\s*\/?>/gi, '').replace(/\s+/g, ' ').trim() === label);
    if (!match) {
      problems.push(`${file}: no h2 with the text "${label}" of ${page.source}:${heading.position.start.line}`);
      continue;
    }
    const found = elements(match).filter((e) => e.tagName === 'wbr').length;
    if (found !== expected) {
      problems.push(`${file}: the h2 "${label}" holds ${found} wbr element(s), but ${page.source}:${heading.position.start.line} has ${expected} <wbr>`);
    }
    if (/wbr/i.test(textContent(match))) {
      problems.push(`${file}: the h2 "${label}" shows "wbr" as text`);
    }
  }
}
if (fromDocsJa === 0) problems.push('no page comes from docs/ja/: the test page docs/ja/README.md is missing');
if (wbrHeadings === 0) problems.push('no h2 of the Japanese pages holds <wbr>: the h2 of the test page docs/ja/README.md need it');

finish('check-japanese', problems, `${pages.length} Japanese pages (${fromDocsJa} from docs/ja/), ${wbrHeadings} h2 with <wbr> checked`);
