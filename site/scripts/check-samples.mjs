// The sample checks of step 4 (docs/proposals/site.md, 3.5 "Samples" and
// section 6): "every sample on a page names a case that exists, and every
// use case of docs/use_case/ is either a sample or marked untested with the
// reason of 3.5".
//
// - Every ```sample block of the pages (the Markdown files of docs/ outside
//   docs/proposals/, and the pages of SOURCE_ROUTES outside docs/) names a
//   case of test/t/cases/ and files that exist and that git tracks, and the
//   case names the request, the response and the port in its code
//   (scripts/lib/samples.mjs, which the generator uses too).
// - Every second-level section of docs/use_case/README.md, except
//   "Articles and other examples", has a sample block; or a paragraph that
//   starts with "**Untested.**" and gives the reason; or a link to a page
//   that has a sample block, or to the README of an example of examples/,
//   which the examples workflow runs.
// - "every v3 diagram and sample carries the development label": every
//   sample and diagram block of the pages of V3_PAGES (the agent proxy page
//   of 3.2) has `label: development`, and the built page shows the label
//   once for each of them (scripts/lib/samples.mjs and diagrams.mjs write
//   it as <p class="caption development-label">).
//
//   node scripts/check-samples.mjs [--repo DIR] [--dist DIR]
//
// Without a built site (dist/ of npm run build, or --dist) it skips the
// count of the labels in the built pages. It exits 1 and lists each
// problem by file and line.
import fs from 'node:fs';
import path from 'node:path';
import { parseMarkdown } from './lib/markdown.mjs';
import { distDir, finish, repoDir, SOURCE_ROUTES } from './lib/site.mjs';
import { parseDiagramBlock } from './lib/diagrams.mjs';
import { loadSample, parseSampleBlock } from './lib/samples.mjs';

const argv = process.argv.slice(2);
let repo = repoDir;
let dist = distDir;
for (let i = 0; i < argv.length; i += 2) {
  if (argv[i] === '--repo' && argv[i + 1]) repo = path.resolve(argv[i + 1]);
  else if (argv[i] === '--dist' && argv[i + 1]) dist = path.resolve(argv[i + 1]);
  else {
    console.error('usage: node scripts/check-samples.mjs [--repo DIR] [--dist DIR]');
    process.exit(2);
  }
}
// The pages of features of v3 that are not released (3.4, 3.5), with the
// route of their built page.
const V3_PAGES = { 'docs/guides/agent-proxy.md': 'guides/agent-proxy' };

const USE_CASES = 'docs/use_case/README.md';
const NOT_A_USE_CASE = new Set(['Articles and other examples']);

function markdownFiles(dir, out = []) {
  for (const entry of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (rel !== 'docs/proposals') markdownFiles(rel, out);
    } else if (entry.name.endsWith('.md')) out.push(rel);
  }
  return out;
}

const v3Blocks = new Map();
const sources = [...markdownFiles('docs'), ...Object.keys(SOURCE_ROUTES).filter((s) => !s.startsWith('docs/') && fs.existsSync(path.join(repo, s)))];
const problems = [];
const withSample = new Set();
let samples = 0;
for (const source of sources) {
  const tree = parseMarkdown(fs.readFileSync(path.join(repo, source), 'utf8'));
  const visit = (node) => {
    if (V3_PAGES[source] && node.type === 'code' && (node.lang === 'sample' || node.lang === 'diagram')) {
      const where = `${source}:${node.position.start.line}`;
      v3Blocks.set(source, (v3Blocks.get(source) ?? 0) + 1);
      let label = null;
      try {
        label = node.lang === 'sample' ? parseSampleBlock(node.value, where).label : parseDiagramBlock(node.value, where).label;
      } catch (e) {
        problems.push(e.message);
      }
      if (label !== 'development') problems.push(`${where}: a ${node.lang} of a feature of v3 without "label: development" (3.5: until v3.0.0, each carries the label "Development version")`);
    }
    if (node.type === 'code' && node.lang === 'sample') {
      const where = `${source}:${node.position.start.line}`;
      samples++;
      withSample.add(source);
      try {
        loadSample(parseSampleBlock(node.value, where), repo, where);
      } catch (e) {
        problems.push(e.message);
      }
    }
    for (const child of node.children ?? []) visit(child);
  };
  visit(tree);
}

// The use cases: sections of the second level
const text = (node) => (node.value ?? '') + (node.children ?? []).map(text).join('');
let useCases = 0;
const kinds = { sample: 0, linked: 0, untested: 0 };
if (!fs.existsSync(path.join(repo, USE_CASES))) {
  problems.push(`${USE_CASES} is missing`);
} else {
  const tree = parseMarkdown(fs.readFileSync(path.join(repo, USE_CASES), 'utf8'));
  const sections = [];
  for (const node of tree.children) {
    if (node.type === 'heading' && node.depth <= 2) {
      sections.push({ title: text(node).trim(), line: node.position.start.line, depth: node.depth, nodes: [] });
    } else if (sections.length) sections.at(-1).nodes.push(node);
  }
  for (const section of sections) {
    if (section.depth !== 2 || NOT_A_USE_CASE.has(section.title)) continue;
    useCases++;
    const where = `${USE_CASES}:${section.line}`;
    const hasSample = section.nodes.some((n) => n.type === 'code' && n.lang === 'sample');
    const links = [];
    const collect = (n) => {
      if (n.type === 'link' && !/^[a-z]+:/i.test(n.url) && !n.url.startsWith('#')) {
        links.push(path.posix.normalize(path.posix.join(path.posix.dirname(USE_CASES), n.url.split('#')[0])));
      }
      for (const c of n.children ?? []) collect(c);
    };
    section.nodes.forEach(collect);
    const linked = links.find((l) => withSample.has(l) || /^examples\/[^/]+\/README\.md$/.test(l));
    const untested = section.nodes.find((n) => n.type === 'paragraph' && n.children?.[0]?.type === 'strong' && text(n.children[0]) === 'Untested.');
    if (untested && text(untested).replace('Untested.', '').trim().length < 20) {
      problems.push(`${where}: the use case "${section.title}" is marked untested without a reason`);
    }
    if (hasSample) kinds.sample++;
    else if (linked) kinds.linked++;
    else if (untested) kinds.untested++;
    else problems.push(`${where}: the use case "${section.title}" has no sample, no link to a page with a sample, and no "**Untested.**" paragraph with the reason (3.5)`);
  }
  if (useCases === 0) problems.push(`${USE_CASES} has no use case (no section of the second level)`);
}

// The labels in the built pages
let labelsChecked = 0;
for (const [source, route] of Object.entries(V3_PAGES)) {
  if (!fs.existsSync(path.join(repo, source))) continue;
  if (!v3Blocks.get(source)) problems.push(`${source}: a page of V3_PAGES without a sample or a diagram block`);
  const file = path.join(dist, route, 'index.html');
  if (!fs.existsSync(path.join(dist, 'index.html'))) continue;
  if (!fs.existsSync(file)) {
    problems.push(`${route}/index.html is missing from the built site`);
    continue;
  }
  const shown = (fs.readFileSync(file, 'utf8').match(/<p class="caption development-label">/g) ?? []).length;
  labelsChecked += shown;
  if (shown !== (v3Blocks.get(source) ?? 0)) problems.push(`${route}/index.html shows the development label ${shown} time(s), for ${v3Blocks.get(source) ?? 0} sample and diagram block(s) of ${source}`);
}

finish(
  'check-samples',
  problems,
  `${samples} sample block(s) on ${withSample.size} page(s) name cases and files that exist; ${[...v3Blocks.values()].reduce((a, b) => a + b, 0)} sample and diagram block(s) of v3 carry the development label, ${labelsChecked} shown in the built pages; ${useCases} use case(s) of ${USE_CASES}: ${kinds.sample} with a sample, ${kinds.linked} linked to a page with one, ${kinds.untested} marked untested with the reason`,
);
