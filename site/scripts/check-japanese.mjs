// The checks of the Japanese pages that need no browser: step 1 and step 5
// of docs/proposals/site.md, section 6 (3.4, 4.4, Q2 of section 7).
//
//   node scripts/check-japanese.mjs [--dist DIR] [--repo DIR] [--manifest FILE]
//
// - Translations. Every English page of generated/pages.json written by hand
//   has a Japanese page (docs/ja/, or docs/<path>.ja.md), except the pages
//   of the lists of scripts/lib/site.mjs. The pages of GENERATED_REFERENCE
//   and REWRITTEN_OFTEN have no Japanese page: under /ja/, a page of the
//   generated reference shows the notice that says why it stays in English
//   (data-notice="generated-reference"), and a page of REWRITTEN_OFTEN the
//   notice that almost every pull request rewrites it
//   (data-notice="rewritten-often"). A page of NOT_TRANSLATED_YET, which
//   step 5 emptied, shows the notice that its translation is not there yet
//   (data-notice="untranslated"). A translated page shows none of them.
//   Each notice holds Japanese text. The lists name only English routes,
//   and none of them a page that has a Japanese page.
// - Languages. Every page of the built site (404.html left out: it has no
//   route, and Starlight gives it no language links) has <html lang="en"> or, under
//   /ja/, lang="ja", and links with hreflang en, ja and x-default (English)
//   to absolute URLs of the site: the page itself and the same page in the
//   other language, which exists and links back.
// - The pages from docs/ja/ (and docs/<path>.ja.md) are under /ja/ with
//   lang="ja" on <html> and <main>, and each h2 of the source that holds
//   <wbr> has a built h2 with the same text and as many wbr elements, plus
//   those that the generator gives a long name of its text (breakNames of
//   scripts/lib/markdown.mjs) (step 1). It fails as well when no page comes from docs/ja/, or when no h2 of
//   those pages holds <wbr>.
// - Spaces. In the sources of the Japanese pages, outside code, URLs and
//   HTML, no space between a Japanese character and a Latin letter or digit
//   (or inline code), in either order (3.4); the labels and captions of
//   diagram blocks included.
// - Code. The code blocks of a Japanese page are those of its English page,
//   in the same order, with the same language, meta and text (sample blocks
//   included, so that the samples of 3.5 find the same case and files);
//   diagram blocks are compared by the generator (scripts/sync-docs.mjs).
// - wbr. On every page under /ja/, no <title>, h1, sidebar entry,
//   table-of-contents entry or heading id contains the text "wbr" (4.4).
// - Diagrams. Every diagram on a page under /ja/ is on a page from docs/ja/
//   (not on the English page shown in its place), and each of its labels
//   shows the text of the same key in the diagram block of the Japanese
//   source.
//
// Exit status: 0 when every check passes, 1 otherwise, 2 on a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, findElement, hasClass, readHtml, textContent } from './lib/html.mjs';
import { addedWbr, headings, parseMarkdown, plainText, titleHeading } from './lib/markdown.mjs';
import { parseDiagramBlock, plainLabel } from './lib/diagrams.mjs';
import { checkOptions, fileOfRoute, finish, GENERATED_REFERENCE, htmlFiles, loadManifest, NOT_TRANSLATED_YET, REWRITTEN_OFTEN, routeOfFile, SITE_URL } from './lib/site.mjs';

const { dist, repo, manifest } = checkOptions();
const all = loadManifest(manifest);
const pages = all.filter((p) => p.lang === 'ja');
const english = all.filter((p) => p.lang === 'en');
const problems = [];
const jaRoute = (route) => (route ? `ja/${route}` : 'ja');
const enRoute = (route) => (route === 'ja' ? '' : route.slice(3));
const isJa = (route) => route === 'ja' || route.startsWith('ja/');
const url = (route) => `${SITE_URL}${route === '' ? '/' : `/${route}/`}`;
const byRoute = new Map(all.map((p) => [p.route, p]));
const html = new Map();
const load = (file) => {
  if (!html.has(file)) html.set(file, fs.existsSync(path.join(dist, file)) ? readHtml(path.join(dist, file)) : null);
  return html.get(file);
};
const notices = (tree) => elements(tree).filter((e) => e.properties?.dataNotice !== undefined).map((e) => ({ kind: String(e.properties.dataNotice), lang: e.properties.lang, text: textContent(e).trim() }));

// Translations
const englishRoutes = new Set(english.map((p) => p.route));
for (const [name, list] of [['GENERATED_REFERENCE', GENERATED_REFERENCE], ['REWRITTEN_OFTEN', REWRITTEN_OFTEN], ['NOT_TRANSLATED_YET', NOT_TRANSLATED_YET]]) {
  for (const route of list) if (!englishRoutes.has(route)) problems.push(`${name} in scripts/lib/site.mjs names /${route}/, which is not an English page`);
}
let translated = 0;
let generatedNotices = 0;
let rewrittenNotices = 0;
let pendingNotices = 0;
for (const page of english) {
  const ja = jaRoute(page.route);
  const hasJa = byRoute.has(ja);
  const tree = load(fileOfRoute(ja));
  if (!tree) {
    problems.push(`${fileOfRoute(ja)}: missing (the page /${ja}/ for ${page.source})`);
    continue;
  }
  const shown = notices(tree);
  const want = GENERATED_REFERENCE.includes(page.route) ? 'generated-reference' : REWRITTEN_OFTEN.includes(page.route) ? 'rewritten-often' : NOT_TRANSLATED_YET.includes(page.route) ? 'untranslated' : null;
  if (want === 'generated-reference' && hasJa) problems.push(`${byRoute.get(ja).source}: a translation of the generated reference page /${page.route}/, which stays in English under /ja/ (Q2)`);
  if (want === 'rewritten-often' && hasJa) problems.push(`${byRoute.get(ja).source}: a translation of /${page.route}/, which almost every pull request rewrites and which stays in English under /ja/ (Q2)`);
  if (want === 'untranslated' && hasJa) problems.push(`${byRoute.get(ja).source} translates /${page.route}/: remove the route from NOT_TRANSLATED_YET in scripts/lib/site.mjs`);
  if (want === null && !hasJa) problems.push(`${page.source}: a page written by hand without a Japanese page (docs/ja/, or the .ja.md beside it) for /${ja}/`);
  if (hasJa) {
    translated++;
    if (shown.length) problems.push(`${fileOfRoute(ja)}: a translated page that shows the notice ${shown.map((n) => n.kind).join(', ')}`);
    continue;
  }
  if (!want) continue;
  const found = shown.filter((n) => n.kind === want);
  if (found.length !== 1 || shown.length !== 1) problems.push(`${fileOfRoute(ja)}: shows the notices [${shown.map((n) => n.kind).join(', ')}], expected one ${want}`);
  else if (!/[\u3040-\u30ff\u3400-\u9fff]/.test(found[0].text)) problems.push(`${fileOfRoute(ja)}: the notice ${want} holds no Japanese text`);
  else if (found[0].lang !== 'ja') problems.push(`${fileOfRoute(ja)}: the notice ${want} has lang="${found[0].lang ?? ''}", expected "ja" inside the English <main>`);
  else if (want === 'generated-reference') generatedNotices++;
  else if (want === 'rewritten-often') rewrittenNotices++;
  else pendingNotices++;
}

// Languages: lang and reciprocal absolute hreflang on every page
let hreflangPages = 0;
for (const file of htmlFiles(dist)) {
  const route = routeOfFile(file);
  if (route === null) continue;
  const tree = load(file);
  const lang = findElement(tree, (e) => e.tagName === 'html')?.properties?.lang;
  const want = isJa(route) ? 'ja' : 'en';
  if (lang !== want) problems.push(`${file}: <html lang="${lang ?? ''}">, expected "${want}"`);
  const en = isJa(route) ? enRoute(route) : route;
  const ja = isJa(route) ? route : jaRoute(route);
  const links = elements(tree).filter((e) => e.tagName === 'link' && [].concat(e.properties?.rel ?? []).includes('alternate') && e.properties?.hrefLang);
  const got = new Map(links.map((e) => [String(e.properties.hrefLang), String(e.properties.href)]));
  const expected = { en: url(en), ja: url(ja), 'x-default': url(en) };
  for (const [hl, href] of Object.entries(expected)) {
    if (got.get(hl) !== href) problems.push(`${file}: hreflang="${hl}" links to ${got.get(hl) ?? 'nothing'}, expected the absolute URL ${href}`);
  }
  if (links.length !== 3) problems.push(`${file}: ${links.length} hreflang links, expected 3 (en, ja, x-default)`);
  const other = fileOfRoute(isJa(route) ? en : ja);
  if (!load(other)) problems.push(`${file}: the page in the other language, ${other}, is missing, so its hreflang link has no page that links back`);
  hreflangPages++;
}

// The pages from docs/ja/: lang, and the <wbr> of their h2 (step 1)
const isWbr = (node) => node.type === 'html' && /^<wbr\s*\/?>$/i.test(node.value.trim());
const countWbr = (node) => (isWbr(node) ? 1 : 0) + (node.children ?? []).reduce((n, c) => n + countWbr(c), 0);
let fromDocsJa = 0;
let wbrHeadings = 0;
for (const page of pages) {
  const file = fileOfRoute(page.route);
  if (page.source.startsWith('docs/ja/')) fromDocsJa++;
  if (!isJa(page.route)) problems.push(`${page.source}: Japanese, but its route /${page.route}/ is not under /ja/`);
  const tree = load(file);
  if (!tree) {
    problems.push(`${file}: missing (source ${page.source})`);
    continue;
  }
  const main = findElement(tree, (e) => e.tagName === 'main');
  if (!main) {
    problems.push(`${file}: no <main>`);
    continue;
  }
  if (main.properties?.lang !== 'ja') problems.push(`${file}: <main lang="${main.properties?.lang ?? ''}">, expected "ja"`);
  if (page.home) continue;
  const content = findElement(main, (e) => hasClass(e, 'sl-markdown-content')) ?? main;
  const built = elements(content).filter((e) => e.tagName === 'h2');
  const text = fs.readFileSync(path.join(repo, page.source), 'utf8');
  const source = parseMarkdown(text);
  const title = titleHeading(source);
  for (const heading of headings(source).filter((h) => h.depth === 2 && h !== title)) {
    const own = countWbr(heading);
    if (own === 0) continue;
    // sync-docs.mjs also breaks a long name of the heading's text
    // (breakNames of scripts/lib/markdown.mjs): ngx_devel_kit gets one <wbr>
    const added = addedWbr(heading, text);
    const expected = own + added;
    wbrHeadings++;
    const label = plainText(heading, text);
    const match = built.find((h2) => textContent(h2).replace(/<wbr\s*\/?>/gi, '').replace(/\s+/g, ' ').trim() === label);
    if (!match) {
      problems.push(`${file}: no h2 with the text "${label}" of ${page.source}:${heading.position.start.line}`);
      continue;
    }
    const found = elements(match).filter((e) => e.tagName === 'wbr').length;
    if (found !== expected) problems.push(`${file}: the h2 "${label}" holds ${found} wbr element(s), but ${page.source}:${heading.position.start.line} has ${own} <wbr>${added ? ` and the generator adds ${added} to its long names` : ''}`);
    if (/wbr/i.test(textContent(match))) problems.push(`${file}: the h2 "${label}" shows "wbr" as text`);
  }
}
if (fromDocsJa === 0) problems.push('no page comes from docs/ja/: the test page docs/ja/README.md is missing');
if (wbrHeadings === 0) problems.push('no h2 of the Japanese pages holds <wbr>: the h2 of the test page docs/ja/README.md need it');

// Spaces between Japanese and Latin characters, and the code blocks
const JA = '\\u3000-\\u303f\\u3040-\\u30ff\\u3400-\\u9fff\\uf900-\\ufaff\\uff00-\\uffef';
const CODE = '';
const URLMARK = '';
// A line break in the source renders as a space, as a typed space does.
const SPACE = new RegExp(`[${JA}][ \\t\\n\\r\\u00a0]+[A-Za-z0-9${CODE}]|[A-Za-z0-9${CODE}][ \\t\\n\\r\\u00a0]+[${JA}]`, 'g');
// The text of inline content as a reader sees it: inline code as one
// placeholder character, the text of a link written as its URL as another
// one (spaces around a URL are allowed), HTML left out.
const inline = (node, src) => {
  switch (node.type) {
    case 'text':
      return node.value;
    case 'inlineCode':
      return CODE;
    case 'html':
      return '';
    case 'break':
      return '\u0002';
    case 'link':
      if (src[node.position.start.offset] !== '[') return URLMARK;
      return (node.children ?? []).map((c) => inline(c, src)).join('');
    default:
      return (node.children ?? []).map((c) => inline(c, src)).join('');
  }
};
const show = (s) => s.replaceAll(CODE, '`code`').replaceAll(URLMARK, 'URL');
let spaceBlocks = 0;
let codePages = 0;
const codeBlocks = (tree) => {
  const out = [];
  const walk = (n) => {
    if (n.type === 'code' && n.lang !== 'diagram') out.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  walk(tree);
  return out;
};
for (const page of pages) {
  if (page.home) continue;
  const src = fs.readFileSync(path.join(repo, page.source), 'utf8');
  const tree = parseMarkdown(src);
  const check = (text, line) => {
    spaceBlocks++;
    for (const m of text.matchAll(SPACE)) problems.push(`${page.source}:${line}: a space between Japanese and Latin text: "${show(text.slice(Math.max(0, m.index - 12), m.index + m[0].length + 12))}"`);
  };
  const walk = (node) => {
    if (['paragraph', 'heading', 'tableCell'].includes(node.type)) return check(inline(node, src), node.position.start.line);
    if (node.type === 'code') {
      if (node.lang !== 'diagram') return;
      for (const [i, l] of node.value.split('\n').entries()) {
        const m = /^([a-z0-9-]+):\s*(.*)$/.exec(l);
        if (m && !['source', 'nginx', 'at', 'label'].includes(m[1])) check(m[2].replace(/<wbr>/g, '').replace(/`[^`]*`/g, CODE), node.position.start.line + i);
      }
      return;
    }
    for (const c of node.children ?? []) walk(c);
  };
  walk(tree);
  // The code blocks, against those of the English page
  const enPage = byRoute.get(enRoute(page.route));
  if (!enPage) {
    problems.push(`${page.source}: no English page /${enRoute(page.route)}/`);
    continue;
  }
  const enSrc = fs.readFileSync(path.join(repo, enPage.source), 'utf8');
  const a = codeBlocks(tree);
  const b = codeBlocks(parseMarkdown(enSrc));
  const sig = (n) => `${n.lang ?? ''} ${n.meta ?? ''}\n${n.value}`;
  const first = a.findIndex((n, i) => !b[i] || sig(n) !== sig(b[i]));
  if (first !== -1 || a.length !== b.length) {
    const i = first === -1 ? a.length : first;
    const at = a[i] ? `${page.source}:${a[i].position.start.line}` : `${page.source} (end)`;
    const there = b[i] ? `${enPage.source}:${b[i].position.start.line}` : `${enPage.source} (end)`;
    problems.push(`${at}: code block ${i + 1} differs from code block ${i + 1} of ${there}: the code blocks of a Japanese page are those of its English page (${a.length} and ${b.length} blocks)`);
  }
  codePages++;
}

// wbr in titles, h1, the sidebar, the table of contents and heading ids
let wbrPages = 0;
for (const file of htmlFiles(dist).filter((f) => f.startsWith('ja/'))) {
  const tree = load(file);
  const places = [];
  for (const e of elements(tree)) {
    if (e.tagName === 'title' || e.tagName === 'h1') places.push([`<${e.tagName}>`, textContent(e)]);
    if (/^h[1-6]$/.test(e.tagName) && e.properties?.id) places.push([`the id of an ${e.tagName}`, String(e.properties.id)]);
  }
  const sidebar = findElement(tree, (e) => hasClass(e, 'sidebar-content'));
  for (const a of sidebar ? elements(sidebar).filter((e) => e.tagName === 'a') : []) places.push(['a sidebar entry', textContent(a)]);
  for (const toc of elements(tree).filter((e) => e.tagName === 'starlight-toc' || e.tagName === 'mobile-starlight-toc')) {
    for (const a of elements(toc).filter((e) => e.tagName === 'a')) places.push(['a table-of-contents entry', textContent(a)]);
  }
  for (const [where, text] of places) if (/wbr/i.test(text)) problems.push(`${file}: ${where} contains "wbr": ${text.trim().slice(0, 60)}`);
  wbrPages++;
}

// Diagrams on /ja/: labels from docs/ja/
let jaDiagrams = 0;
for (const file of htmlFiles(dist).filter((f) => f.startsWith('ja/'))) {
  const tree = load(file);
  const figures = elements(tree).filter((e) => e.tagName === 'figure' && hasClass(e, 'diagram'));
  if (!figures.length) continue;
  const page = byRoute.get(routeOfFile(file));
  // A page still to be translated shows the English labels until then
  if (!page && NOT_TRANSLATED_YET.includes(enRoute(routeOfFile(file)))) continue;
  if (!page || page.lang !== 'ja') {
    problems.push(`${file}: ${figures.length} diagram(s) on a page under /ja/ that shows an English page, so their labels are English: translate the page with its diagram blocks`);
    continue;
  }
  const blocks = parseMarkdown(fs.readFileSync(path.join(repo, page.source), 'utf8'))
    .children.filter((n) => n.type === 'code' && n.lang === 'diagram')
    .map((n) => parseDiagramBlock(n.value, page.source));
  for (const [i, fig] of figures.entries()) {
    jaDiagrams++;
    const block = blocks[i];
    if (!block) {
      problems.push(`${file}: diagram ${i + 1} has no diagram block in ${page.source}`);
      continue;
    }
    for (const label of elements(fig).filter((e) => hasClass(e, 'diagram-label'))) {
      const key = String(label.properties?.dataKey ?? '');
      const want = block.labels.has(key) ? plainLabel(block.labels.get(key)) : null;
      const got = textContent(label);
      if (want === null) problems.push(`${file}: the label ${key} of the diagram ${block.name} is not in the block of ${page.source}`);
      else if (got !== want) problems.push(`${file}: the label ${key} of the diagram ${block.name} shows "${got}", not "${want}" of ${page.source}`);
    }
  }
}

finish(
  'check-japanese',
  problems,
  `${english.length} English pages: ${translated} translated, ${generatedNotices} generated reference page(s) with their notice, ${rewrittenNotices} page(s) rewritten by almost every pull request with theirs, ${pendingNotices} not translated yet with theirs; hreflang on ${hreflangPages} pages; ${pages.length} Japanese pages (${fromDocsJa} from docs/ja/), ${wbrHeadings} h2 with <wbr>, ${spaceBlocks} text blocks checked for spaces, the code blocks of ${codePages} pages, wbr on ${wbrPages} pages under /ja/, ${jaDiagrams} diagram(s) under /ja/`,
);
