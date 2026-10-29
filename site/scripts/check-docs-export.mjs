// Check version isolation and source fidelity of the machine-readable output.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { elements, readHtml } from './lib/html.mjs';
import { distDir, GITHUB_URL, htmlFiles, manifestFile, pageOfRoute, repoDir, SITE_URL, v2ManifestFile } from './lib/site.mjs';
import { loadSample, parseSampleBlock } from './lib/samples.mjs';
import { parseMarkdown } from './lib/markdown.mjs';

const problems = [];
const v2 = JSON.parse(fs.readFileSync(v2ManifestFile, 'utf8'));
let checked = 0;
for (const spec of [
  { version: '3.x', channel: 'development', prefix: '', repo: repoDir, revision: execFileSync('git', ['-C', repoDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), manifest: JSON.parse(fs.readFileSync(manifestFile, 'utf8')) },
  { version: '2.x', channel: 'stable', prefix: '/v2', repo: v2.tree, revision: v2.commit, manifest: v2.pages },
]) {
  const root = path.join(distDir, spec.prefix);
  const index = JSON.parse(fs.readFileSync(path.join(root, 'docs-index.json'), 'utf8'));
  const where = `${spec.version} export`;
  if (index.schema_version !== 1 || index.documentation_version !== spec.version || index.channel !== spec.channel || index.source_revision !== spec.revision) problems.push(`${where}: index version/revision mismatch`);
  const clean = execFileSync('git', ['-C', spec.repo, 'status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' }).trim() === '';
  if (index.working_tree_clean !== clean) problems.push(`${where}: index clean state mismatch`);
  const expected = spec.manifest.filter((p) => !p.home);
  if (index.pages.length !== expected.length) problems.push(`${where}: incomplete page index`);
  const seen = new Set();
  for (const page of expected) {
    const html = `${SITE_URL}${spec.prefix}/${page.route ? `${page.route}/` : ''}`;
    const matches = index.pages.filter((p) => p.html_url === html);
    if (matches.length !== 1) { problems.push(`${where}: expected one entry for ${html}`); continue; }
    const entry = matches[0];
    if (seen.has(entry.markdown_url)) problems.push(`${where}: duplicate Markdown URL`);
    seen.add(entry.markdown_url);
    if (entry.language !== page.lang || entry.source_path !== page.source || entry.source_revision !== spec.revision || entry.documentation_version !== spec.version || entry.channel !== spec.channel || entry.working_tree_clean !== clean || entry.title !== page.title || entry.last_updated !== (page.lastUpdated ?? null)) problems.push(`${where}: metadata mismatch for ${page.source}`);
    const expectedPath = `${spec.prefix}/markdown/${page.route || 'index'}.md`;
    if (entry.markdown_url !== SITE_URL + expectedPath) problems.push(`${where}: wrong version/path for ${page.source}`);
    const text = fs.readFileSync(path.join(distDir, expectedPath), 'utf8');
    const front = /^---\n([\s\S]*?)\n---\n\n/.exec(text);
    if (!front) { problems.push(`${where}: missing metadata for ${page.source}`); continue; }
    const meta = Object.fromEntries(front[1].split('\n').map((line) => { const at = line.indexOf(': '); return [line.slice(0, at), JSON.parse(line.slice(at + 2))]; }));
    for (const [key, value] of Object.entries(entry)) if (meta[key] !== value) problems.push(`${where}: index/Markdown differ for ${page.source} ${key}`);
    const source = fs.readFileSync(path.join(spec.repo, page.source), 'utf8');
    if (createHash('sha256').update(source).digest('hex') !== entry.source_sha256) problems.push(`${where}: wrong source hash for ${page.source}`);
    const committed = execFileSync('git', ['-C', spec.repo, 'show', `${spec.revision}:${page.source}`], { encoding: 'utf8' });
    const atRevision = source === committed;
    const sourceUrl = atRevision ? `${GITHUB_URL}/blob/${spec.revision}/${page.source}` : null;
    if (entry.source_at_revision !== atRevision || entry.source_url !== sourceUrl) problems.push(`${where}: source revision state mismatch for ${page.source}`);
    const canonical = path.join(path.dirname(manifestFile), spec.prefix ? 'markdown-v2' : 'markdown', `${page.route || 'index'}.md`);
    if (text.slice(front[0].length) !== fs.readFileSync(canonical, 'utf8')) problems.push(`${where}: incomplete or changed body for ${page.source}`);
    const tree = parseMarkdown(source);
    for (const node of tree.children) {
      if (node.type !== 'code' || node.lang !== 'sample') continue;
      const sample = loadSample(parseSampleBlock(node.value, page.source), spec.repo, page.source);
      for (const item of sample.shown) if (!text.includes(item.text.replace(/\n$/, ''))) problems.push(`${where}: missing tested fixture ${item.file}`);
      if (!text.includes(sample.commit) || !text.includes(sample.date) || !text.includes(sample.spec.case)) problems.push(`${where}: missing sample provenance for ${page.source}`);
    }
    checked++;
  }
  for (const file of htmlFiles(root)) {
    if (file === '404.html') continue;
    const route = file === 'index.html' ? '' : file.slice(0, -'/index.html'.length);
    const { page, fallback } = pageOfRoute(spec.manifest, route);
    const links = elements(readHtml(path.join(root, file))).filter((e) => e.tagName === 'a');
    const md = links.find((e) => String(e.properties?.className ?? '').includes('doc-markdown'));
    if (page && !page.home) {
      const want = `${spec.prefix}/markdown/${page.route || 'index'}.md`;
      if (md?.properties?.href !== want) problems.push(`${where}: ${file} does not link to its ${fallback ? 'English fallback' : 'own'} Markdown`);
    }
    if (!links.some((e) => e.properties?.href === `${spec.prefix}/docs-index.json`)) problems.push(`${where}: ${file} lacks its version's index link`);
  }
}
for (const problem of problems) console.error(problem);
if (problems.length) process.exit(1);
console.log(`check-docs-export: ${checked} pages; versions, revisions, languages, source hashes, complete bodies, tested sample bytes/provenance and fallback links pass`);
