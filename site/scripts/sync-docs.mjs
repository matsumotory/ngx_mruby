// Writes the Markdown files of docs/ as Starlight pages: the generator of
// docs/proposals/site.md, 5.2. `npm run build` runs it before `astro
// build`; `npm run sync-docs` runs it alone.
//
// For each Markdown file under docs/ except docs/proposals/, it writes a
// page under src/content/docs/ (gitignored, beside the committed home pages;
// removed and written again on every run):
//
// - Language and route. docs/<path>.md is an English page at /<path>/.
//   docs/ja/<path>.md, and docs/<path>.ja.md (the Japanese release notes of
//   docs/releases/README.md), are Japanese pages at /ja/<path>/. README.md
//   is the index of its folder, except docs/README.md, which is /docs/
//   (and docs/ja/README.md /ja/docs/), since / and /ja/ are the committed
//   home pages (5.2); in the 2.x build (NGX_MRUBY_SITE_VERSION=2, step 6),
//   which has no home pages, docs/README.md is the index /v2/. Routes are
//   lowercase, and the pages of the 2.x build are under /v2/ (BASE of
//   scripts/lib/site.mjs). The pages of SOURCE_ROUTES
//   (scripts/lib/site.mjs) take the route given there instead, so that
//   the site shows the four kinds of page of 3.1 while the files stay
//   where they are; the README of examples/start/ is the one page from
//   outside docs/. A page whose route SIDEBAR_ORDER lists gets that place
//   in its group of the sidebar (sidebar.order).
// - title: the text of the first heading of the file. The build stops when
//   the file has no heading at the top level, or when that heading contains
//   HTML (4.4). The heading is removed from the body when it is the first
//   block of the file, since Starlight shows the title as the h1; a first
//   heading further down (docs/test/README.md starts with paragraphs) stays
//   where it is.
// - lastUpdated: `git log -1 --format=%cs -- <file>`. The build stops in a
//   shallow clone, where these dates would be wrong; a file that no commit
//   changed yet gets no date, with a warning.
// - Links. A relative link, or one from the top of the repository
//   (/path), to a file that the site renders becomes the route of its page,
//   with the anchor kept; from a Japanese page, a link to an English page
//   becomes the route of that page under /ja/. A link to any other file or folder of the
//   repository becomes its URL on GitHub at the branch next, and an image
//   its raw URL there. A link to a path that the repository does not track
//   stops the build. Absolute URLs and anchors within the page stay as they
//   are. The href and src attributes of raw HTML are rewritten in the same
//   way. Only the destinations change, and a long name in text outside
//   code (a directive, a constant, a Ruby method with its class) gets
//   <wbr> where it may break on a narrow screen (breakName): the rest of
//   the Markdown is copied as it is.
//
// - Samples and diagrams (3.5). A fenced block with the language `sample`
//   becomes the code blocks of the files that a case of test/t/cases/
//   compares, with a line that names the case and the date of the last
//   commit to the files (scripts/lib/samples.mjs). A fenced block with the
//   language `diagram` becomes a figure with the drawing of
//   site/src/diagrams/ and the labels of the block as HTML text
//   (scripts/lib/diagrams.mjs). The build stops on a sample whose file or
//   case is missing, on a diagram block whose keys differ from those of its
//   drawing, and on a diagram block of a Japanese page whose keys or
//   sources differ from the block of the English page. Both blocks must be
//   at the top level of the file.
//
// It also writes generated/pages.json, the list of the pages with their
// source, language, route, title and date, which the checks read.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { containsHtml, isFirstBlock, parseMarkdown, plainText, titleHeading } from './lib/markdown.mjs';
import { BASE, contentDir, contentRoot, GITHUB_REF, GITHUB_URL, HOME_PAGES, isShallow, lastCommitDate, manifestFile, repoDir, SIDEBAR_ORDER, siteDir, SITE_VERSION, SOURCE_ROUTES } from './lib/site.mjs';
import { checkKeys, diagramHtml, diagramMarkdown, loadDrawings, parseDiagramBlock } from './lib/diagrams.mjs';
import { loadSample, parseSampleBlock, sampleMarkdown } from './lib/samples.mjs';

const posix = path.posix;

function fail(message) {
  console.error(`sync-docs: ${message}`);
  process.exit(1);
}

if (isShallow(repoDir)) {
  fail('the repository is a shallow clone, so the last-updated dates of the pages would be wrong; fetch the whole history (git fetch --unshallow) and run the build again');
}

// The paths that the repository tracks, and the folders that hold them.
const tracked = new Set();
for (const file of execFileSync('git', ['-C', repoDir, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0')) {
  if (!file) continue;
  tracked.add(file);
  for (let dir = posix.dirname(file); dir !== '.'; dir = posix.dirname(dir)) tracked.add(`${dir}/`);
}

function markdownFiles(dir) {
  const files = [];
  for (const entry of fs.readdirSync(path.join(repoDir, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (rel !== 'docs/proposals') files.push(...markdownFiles(rel));
    } else if (entry.name.endsWith('.md')) {
      files.push(rel);
    }
  }
  return files;
}

function pageOf(source) {
  if (!source.startsWith('docs/')) return { source, lang: 'en', route: SOURCE_ROUTES[source] };
  let rel = source.slice('docs/'.length);
  let lang = 'en';
  if (rel.startsWith('ja/')) {
    lang = 'ja';
    rel = rel.slice('ja/'.length);
  } else if (rel.endsWith('.ja.md')) {
    lang = 'ja';
    rel = `${rel.slice(0, -'.ja.md'.length)}.md`;
  }
  const parts = rel.slice(0, -'.md'.length).split('/');
  if (parts.at(-1) === 'README') parts.pop();
  // docs/README.md, the index of the documentation, is /docs/: the home
  // pages of the site are / and /ja/ (5.2). The 2.x build has no home
  // pages, and docs/README.md is its index, /v2/.
  const index = SITE_VERSION === 2 ? '' : 'docs';
  let route = SOURCE_ROUTES[`docs/${rel}`] ?? (parts.length ? parts.join('/').toLowerCase() : index);
  if (lang === 'ja') route = route ? `ja/${route}` : 'ja';
  if (!/^[a-z0-9._-]+(\/[a-z0-9._-]+)*$|^$/.test(route)) {
    fail(`${source}: the route ${route} would need characters other than a-z, 0-9, ".", "_" and "-"`);
  }
  return { source, lang, route };
}

// A page from outside docs/ that the branch does not have (docs/ of master
// for /v2/, step 6) is left out with a warning; a link to it still stops
// the build.
const outside = Object.keys(SOURCE_ROUTES).filter((source) => {
  if (source.startsWith('docs/')) return false;
  if (tracked.has(source)) return true;
  console.warn(`sync-docs: warning: ${source}, a page of SOURCE_ROUTES in scripts/lib/site.mjs, is not tracked by git; no page /${SOURCE_ROUTES[source]}/`);
  return false;
});
const pages = [...markdownFiles('docs').sort(), ...outside].map(pageOf);
const bySource = new Map(pages.map((page) => [page.source, page]));
for (const page of pages) {
  const other = pages.find((p) => p !== page && p.route === page.route);
  if (other) fail(`${page.source} and ${other.source} would both be the page /${page.route}/`);
}

const routeUrl = (route) => (route === '' ? `${BASE}/` : `${BASE}/${route}/`);

// The new destination of a link or image of `source`, or null to keep it.
function resolve(url, source, image, where) {
  if (url === '' || url.startsWith('#') || url.startsWith('//') || /^[a-z][a-z0-9+.-]*:/i.test(url)) return null;
  const [, rawPath, query = '', fragment = ''] = /^([^?#]*)(\?[^#]*)?(#.*)?$/.exec(url);
  let decoded;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    fail(`${where}: the link ${url} is not a valid URL`);
  }
  const joined = decoded.startsWith('/') ? decoded.slice(1) : posix.join(posix.dirname(source), decoded);
  const target = posix.normalize(joined).replace(/\/$/, '');
  if (target === '..' || target.startsWith('../')) fail(`${where}: the link ${url} points outside the repository`);
  if (!image) {
    const page = bySource.get(target) ?? bySource.get(`${target}/README.md`);
    // From a Japanese page, a link to an English page goes to that page
    // under /ja/: its translation, or the English page with the notice of
    // 3.4 (a generated reference page, or one not translated yet), so that
    // the reader stays on the Japanese pages.
    const fromJapanese = bySource.get(source)?.lang === 'ja';
    if (page) return routeUrl(fromJapanese && page.lang === 'en' ? (page.route ? `ja/${page.route}` : 'ja') : page.route) + query + fragment;
  }
  const isDir = target === '.' || tracked.has(`${target}/`);
  if (!isDir && !tracked.has(target)) {
    fail(`${where}: the link ${url} points to ${target}, which the repository does not track`);
  }
  const kind = image ? 'raw' : isDir ? 'tree' : 'blob';
  const encoded = target === '.' ? '' : target.split('/').map(encodeURIComponent).join('/');
  return `${GITHUB_URL}/${kind}/${GITHUB_REF}/${encoded}${query}${fragment}`;
}

// The index of the "]" that closes the "[" at `open`, skipping backslash
// escapes and code spans, or -1.
function closingBracket(src, open, end) {
  let depth = 0;
  for (let i = open; i < end; i++) {
    const c = src[i];
    if (c === '\\') {
      i++;
    } else if (c === '`') {
      let n = 1;
      while (src[i + n] === '`') n++;
      const close = src.indexOf('`'.repeat(n), i + n);
      if (close !== -1 && close < end && src[close + n] !== '`') i = close + n - 1;
      else i += n - 1;
    } else if (c === '[') {
      depth++;
    } else if (c === ']' && --depth === 0) {
      return i;
    }
  }
  return -1;
}

// The range [start, end) of the destination of an inline link, an inline
// image or a link definition in the source, without the angle brackets of
// <dest>, or null for an autolink or a reference.
function destinationRange(src, node) {
  const start = node.position.start.offset;
  const end = node.position.end.offset;
  const open = node.type === 'image' ? start + 1 : start;
  if (src[open] !== '[') return null;
  const close = closingBracket(src, open, end);
  if (close === -1) return null;
  let i = close + 1;
  if (node.type === 'definition') {
    if (src[i] !== ':') return null;
    i++;
  } else {
    if (src[i] !== '(') return null;
    i++;
  }
  while (i < end && /[ \t\r\n]/.test(src[i])) i++;
  if (src[i] === '<') {
    let j = i + 1;
    while (j < end && src[j] !== '>' && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
    return [i + 1, j];
  }
  let j = i;
  let parens = 0;
  while (j < end && !/[\s\x00-\x1f]/.test(src[j])) {
    if (src[j] === '\\') j++;
    else if (src[j] === '(') parens++;
    else if (src[j] === ')' && --parens < 0) break;
    j++;
  }
  return [i, j];
}

// The raw text of a destination as the parser reads it: backslash escapes
// and character references resolved.
function unescapeDestination(raw) {
  return raw
    .replace(/\\([!-/:-@[-`{-~])/g, '$1')
    .replace(/&(amp|lt|gt|quot|#39|#x27);/g, (_, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'" })[e]);
}

// An href or src attribute with a quoted value in raw HTML.
const HTML_URL_ATTRIBUTE = /\b(href|src)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const attributeValue = (m) => m[2] ?? m[3];

// Long names in text outside code: a directive or constant of three or
// more parts joined by underscores (mruby_ssl_handshake_handler_code,
// Nginx::HTTP_MOVED_TEMPORARILY), and a Ruby method with its class
// (Nginx::Stream::Connection#remote_port, Nginx::Headers_in#delete(string)).
// breakName gives such a name a <wbr> after each "::" and before each "#",
// "." and "(" between names, and after an underscore that is followed by
// four or more characters of the name, so that no line ends with one or two
// characters of it.
const SNAKE = /[A-Za-z0-9]+(?:_[A-Za-z0-9]+){2,}|[A-Z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)+(?:[#.][a-z_][A-Za-z0-9_?!=]*(?:\([^)\s]*\))?)?/;
const SNAKE_ALL = new RegExp(SNAKE.source, 'g');
function breakName(name) {
  let out = '';
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    const rest = name.length - i - 1;
    if ((c === '#' || c === '.' || c === '(') && i > 0) out += '<wbr>';
    out += c;
    if (c === ':' && name[i - 1] === ':' && rest > 0) out += '<wbr>';
    else if (c === '_' && rest >= 4 && !/[#.(]/.test(name.slice(i + 1, i + 5))) out += '<wbr>';
  }
  return out;
}

function lineOf(node) {
  return node.position.start.line;
}

// The diagram blocks of the English page of a Japanese page, by name.
function englishDiagramBlocks(page) {
  const rel = page.source.startsWith('docs/ja/') ? `docs/${page.source.slice('docs/ja/'.length)}` : page.source.replace(/\.ja\.md$/, '.md');
  const blocks = new Map();
  if (!fs.existsSync(path.join(repoDir, rel))) return blocks;
  const tree = parseMarkdown(fs.readFileSync(path.join(repoDir, rel), 'utf8'));
  for (const node of tree.children) {
    if (node.type === 'code' && node.lang === 'diagram') {
      try {
        const block = parseDiagramBlock(node.value, `${rel}:${node.position.start.line}`);
        blocks.set(block.name, block);
      } catch (e) {
        fail(e.message);
      }
    }
  }
  return blocks;
}

function render(page) {
  const file = path.join(repoDir, page.source);
  const src = fs.readFileSync(file, 'utf8');
  const tree = parseMarkdown(src);
  if (tree.children.some((node) => node.type === 'yaml' || node.type === 'toml')) {
    fail(`${page.source}: front matter in docs/ is not supported (the generator writes it)`);
  }
  const heading = titleHeading(tree);
  if (!heading) fail(`${page.source}: no heading at the top level to take the title from`);
  if (containsHtml(heading)) {
    fail(`${page.source}:${lineOf(heading)}: the first heading gives the page title and must not contain HTML (docs/proposals/site.md, 4.4)`);
  }
  const title = plainText(heading, src);
  if (!title) fail(`${page.source}:${lineOf(heading)}: the first heading has no text to take the title from`);

  // Replacements of [start, end) by text, applied from the end.
  const edits = [];
  let removed = null;
  if (isFirstBlock(tree, heading)) {
    let end = heading.position.end.offset;
    while (src[end] === '\n' || src[end] === '\r') end++;
    removed = [0, end];
    edits.push([0, end, '', src.slice(0, end)]);
  }
  // A node inside the removed heading needs no edit.
  const inRemoved = (node) =>
    removed !== null && node.position.start.offset >= removed[0] && node.position.end.offset <= removed[1];
  // Samples and diagrams (3.5), at the top level of the file.
  const englishBlocks = page.lang === 'ja' ? englishDiagramBlocks(page) : null;
  const generated = (node) => node.type === 'code' && (node.lang === 'sample' || node.lang === 'diagram');
  const nested = (node, top) => {
    if (!top && generated(node)) fail(`${page.source}:${lineOf(node)}: a ${node.lang} block must be at the top level of the file, not inside a list or a quote`);
    for (const child of node.children ?? []) nested(child, false);
  };
  for (const child of tree.children) nested(child, true);
  const diagrams = [];
  for (const node of tree.children) {
    if (!generated(node)) continue;
    const where = `${page.source}:${lineOf(node)}`;
    let text;
    let machineText;
    try {
      if (node.lang === 'sample') {
        text = sampleMarkdown(loadSample(parseSampleBlock(node.value, where), repoDir, where), page.lang);
      } else {
        const block = parseDiagramBlock(node.value, where);
        const drawings = loadDrawings(siteDir, block.name, where);
        checkKeys(block, drawings[0].keys, where, `the drawing site/src/diagrams/${block.name}.svg`);
        if (englishBlocks) {
          const en = englishBlocks.get(block.name);
          if (!en) fail(`${where}: the English page of ${page.source} has no diagram block ${block.name}`);
          checkKeys(block, [...en.labels.keys()], where, 'the diagram block of the English page');
          const lines = (b) => JSON.stringify([b.sources, b.nginx, b.at]);
          if (lines(block) !== lines(en)) fail(`${where}: the source, nginx and at lines of the diagram block ${block.name} differ from those of the English page`);
        }
        diagrams.push({ name: block.name, sources: block.sources, nginx: block.nginx, at: block.at });
        text = diagramHtml(block, drawings, page.lang);
        machineText = diagramMarkdown(block, page.lang);
      }
    } catch (e) {
      fail(e.message);
    }
    edits.push([node.position.start.offset, node.position.end.offset, text, machineText]);
  }
  // A definition that an image refers to (![alt][id]) gets the raw URL.
  const imageIds = new Set();
  const collect = (node) => {
    if (node.type === 'imageReference') imageIds.add(node.identifier);
    for (const child of node.children ?? []) collect(child);
  };
  collect(tree);
  const inUrl = new Set();
  const visit = (node) => {
    if (inRemoved(node)) return;
    const where = `${page.source}:${node.position?.start.line}`;
    // The text of a link written as its URL (an autolink, or a bare URL
    // that GFM makes a link) is the URL: it gets no <wbr>
    if (node.type === 'link' && src[node.position.start.offset] !== '[') {
      for (const child of node.children ?? []) inUrl.add(child);
    }
    if (node.type === 'link' || node.type === 'image' || node.type === 'definition') {
      const range = destinationRange(src, node);
      if (range) {
        const raw = src.slice(range[0], range[1]);
        if (unescapeDestination(raw) !== node.url) {
          fail(`${where}: could not find the destination ${node.url} of this ${node.type} in the source`);
        }
        const image = node.type === 'image' || (node.type === 'definition' && imageIds.has(node.identifier));
        const next = resolve(node.url, page.source, image, where);
        if (next !== null) edits.push([range[0], range[1], next.replace(/[ ()<>\\]/g, (c) => encodeURIComponent(c))]);
      } else if (node.type !== 'link') {
        fail(`${where}: could not find the destination ${node.url} of this ${node.type} in the source`);
      }
    } else if (node.type === 'text' && SNAKE.test(node.value) && !inUrl.has(node)) {
      // Long identifiers such as mruby_ssl_handshake_handler_code break
      // after their underscores, not at any character, so that no line of a
      // heading or list item ends with one or two characters of a name
      // (the owner's rule for text); the source in docs/ is unchanged
      const start = node.position.start.offset;
      const end = node.position.end.offset;
      if (src.slice(start, end) === node.value) {
        // Not inside a URL of the text (http://host/YOUR_MRUBY_SCRIPT.rb)
        edits.push([start, end, node.value.replace(SNAKE_ALL, (w, at, all) => (/\S*:\/\/\S*$/.test(all.slice(0, at)) ? w : breakName(w))), node.value]);
      }
    } else if (node.type === 'html') {
      // The attributes are found in the source text of the node, not in
      // node.value: inside a blockquote or a list item, node.value lacks the
      // "> " or the indentation that starts each line after the first, so
      // an index into it is not an offset into the source. The attributes
      // found in node.value, which is what the page renders, must be the
      // same ones in the same order, or the build stops.
      const base = node.position.start.offset;
      const text = src.slice(base, node.position.end.offset);
      if (/^<wbr\s*\/?\s*>$/i.test(text)) edits.push([base, node.position.end.offset, text, '']);
      const inSource = [...text.matchAll(HTML_URL_ATTRIBUTE)];
      const inValue = [...node.value.matchAll(HTML_URL_ATTRIBUTE)].map(attributeValue);
      if (inSource.length !== inValue.length || inSource.some((m, i) => attributeValue(m) !== inValue[i])) {
        fail(`${where}: the href and src attributes of this HTML differ between its source and the HTML that the page renders (an attribute value over more than one line inside a blockquote or a list item?)`);
      }
      for (const m of inSource) {
        const value = attributeValue(m);
        const url = value.replace(/&amp;/g, '&');
        const next = resolve(url, page.source, m[1].toLowerCase() === 'src', where);
        if (next === null) continue;
        const valueStart = base + m.index + m[0].length - value.length - 1;
        if (src.slice(valueStart, valueStart + value.length) !== value) {
          fail(`${where}: could not find the value ${value} of this ${m[1]} attribute in the source`);
        }
        edits.push([valueStart, valueStart + value.length, next.replace(/&/g, '&amp;').replace(/"/g, '&quot;')]);
      }
    }
    for (const child of node.children ?? []) visit(child);
  };
  visit(tree);

  edits.sort((a, b) => b[0] - a[0]);
  let body = src;
  let machineBody = src;
  let previousStart = Infinity;
  for (const [start, end, text, machineText = text] of edits) {
    if (end > previousStart) fail(`${page.source}: overlapping edits at offset ${start}`);
    body = body.slice(0, start) + text + body.slice(end);
    machineBody = machineBody.slice(0, start) + machineText + machineBody.slice(end);
    previousStart = start;
  }

  const lastUpdated = lastCommitDate(repoDir, page.source);
  if (!lastUpdated) console.warn(`sync-docs: warning: ${page.source} has no commit yet, so its page has no last-updated date`);
  const front = ['---', `title: ${JSON.stringify(title)}`, `slug: ${JSON.stringify(page.route)}`];
  if (lastUpdated) front.push(`lastUpdated: ${lastUpdated}`);
  // Pagefind's Japanese body segmentation and browser Intl.Segmenter can
  // split API names differently. Its searchable metadata keeps these names
  // whole. Derive them from the same canonical body; never add query-specific
  // keywords or alter visible code/Markdown to make search work.
  const identifiers = [...new Set(`${title}\n${machineBody}`.match(SNAKE_ALL) ?? [])].sort();
  if (identifiers.length) front.push('head:', '  - tag: meta', '    attrs:',
    '      data-pagefind-meta: "identifiers[content]"',
    `      content: ${JSON.stringify(identifiers.join(' '))}`);

  const order = SIDEBAR_ORDER[page.route.replace(/^ja\//, '')];
  if (order !== undefined) front.push('sidebar:', `  order: ${order}`);
  front.push('---', '');
  // A page of two or more route segments is the file <route>.md, so that
  // the autogenerated groups of the sidebar list it as a page of its
  // folder; as <route>/index.md, Starlight made a group of each such page
  // (step 3). A page of one segment, the index of a group such as
  // releases/, stays <route>/index.md.
  const out = path.join(contentDir, page.route.includes('/') ? `${page.route}.md` : `${page.route}/index.md`);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${front.join('\n')}\n${body}`);
  const machine = path.join(path.dirname(manifestFile), 'markdown', `${page.route || 'index'}.md`);
  fs.mkdirSync(path.dirname(machine), { recursive: true });
  fs.writeFileSync(machine, machineBody);
  return { ...page, title, lastUpdated, titleRemoved: removed !== null, diagrams };
}

// Remove what the last run wrote: everything in the content folder except
// the committed home pages.
for (const entry of fs.readdirSync(contentRoot, { withFileTypes: true })) {
  if (entry.name === 'index.mdx') continue;
  const full = path.join(contentRoot, entry.name);
  if (entry.name === 'ja' && entry.isDirectory()) {
    for (const sub of fs.readdirSync(full)) if (sub !== 'index.mdx') fs.rmSync(path.join(full, sub), { recursive: true, force: true });
  } else {
    fs.rmSync(full, { recursive: true, force: true });
  }
}
fs.rmSync(path.dirname(manifestFile), { recursive: true, force: true });
const manifest = pages.map(render);
// The home pages are committed MDX files (5.2): the checks read them from
// the list too.
for (const [lang, rel, route] of [['en', HOME_PAGES[0], ''], ['ja', HOME_PAGES[1], 'ja']].filter(([, rel]) => rel)) {
  const file = path.join(contentRoot, rel);
  if (!fs.existsSync(file)) fail(`site/src/content/docs/${rel}, the home page of 5.2, is missing`);
  const title = /^title:\s*(.+)$/m.exec(fs.readFileSync(file, 'utf8'))?.[1]?.replace(/^["']|["']$/g, '');
  if (!title) fail(`site/src/content/docs/${rel} has no title in its front matter`);
  const source = path.relative(repoDir, file).split(path.sep).join('/');
  manifest.push({ source, lang, route, title, lastUpdated: lastCommitDate(repoDir, source), home: true, diagrams: [] });
}
fs.mkdirSync(path.dirname(manifestFile), { recursive: true });
fs.writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`sync-docs: wrote ${manifest.length} pages from docs/ to ${path.relative(repoDir, contentDir)}/`);
