// Export the already-expanded Markdown used by HTML. No second document source.
// Run after Astro: outputs live only in ignored dist/, separately for each version.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { BASE, distDir, GITHUB_URL, manifestFile, repoDir, SITE_URL, SITE_VERSION } from './lib/site.mjs';

import { releaseState } from './lib/release-state.mjs';
const release = SITE_VERSION === 2 ? releaseState(repoDir, 2) : null;
const git = (...args) => execFileSync('git', ['-C', repoDir, ...args], { encoding: 'utf8' }).trim();
const revision = git('rev-parse', 'HEAD');
const clean = git('status', '--porcelain', '--untracked-files=all') === '';
const version = `${SITE_VERSION}.x`;
const channel = SITE_VERSION === 2 ? 'maintenance' : 'development';
const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
const pages = [];
for (const page of manifest.filter((p) => !p.home)) {
  const body = fs.readFileSync(path.join(path.dirname(manifestFile), 'markdown', `${page.route || 'index'}.md`), 'utf8');
  const original = fs.readFileSync(path.join(repoDir, page.source));
  // Never advertise an uncommitted new source as a file at HEAD. Edited tracked
  // pages remain useful in previews, with a null source URL and explicit state.
  let committed;
  try { committed = execFileSync('git', ['-C', repoDir, 'show', `${revision}:${page.source}`]); }
  catch { throw new Error(`source must exist at HEAD before export: ${page.source}`); }
  const sourceAtRevision = original.equals(committed);
  const relative = `markdown/${page.route || 'index'}.md`;
  const entry = {
    title: page.title,
    language: page.lang,
    documentation_version: version,
    channel,
    release_context: release,
    source_revision: revision,
    working_tree_clean: clean,
    source_path: page.source,
    source_sha256: createHash('sha256').update(original).digest('hex'),
    source_at_revision: sourceAtRevision,
    source_url: sourceAtRevision ? `${GITHUB_URL}/blob/${revision}/${page.source}` : null,
    html_url: `${SITE_URL}${BASE}/${page.route ? `${page.route}/` : ''}`,
    markdown_url: `${SITE_URL}${BASE}/${relative}`,
    last_updated: page.lastUpdated ?? null,
  };
  const metadata = Object.entries(entry).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join('\n');
  const output = `---\n${metadata}\n---\n\n${body}`;
  const file = path.join(distDir, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, output);
  pages.push(entry);
}
const index = {
  schema_version: 1,
  documentation_version: version,
  channel,
  release_context: release,
  source_revision: revision,
  working_tree_clean: clean,
  note: 'Select the documentation version before implementing. Maintenance documents a branch snapshot and can include unreleased changes; consult release_context and each example target. Development is not a stable release. Check prerequisites, execution phase, lifetime and sample provenance in the linked pages. Version identifies a release line, not a release tag. source_at_revision compares the original source file with HEAD; source_sha256 hashes that original file, not the transformed Markdown. A dirty working-tree preview can differ from its source revision. An untranslated Japanese HTML page links to its English Markdown source; no translation is fabricated.',
  status_vocabulary: { implemented: 'Present in the documented source revision; development is not a stable release.', planned: 'Named in the agreed plan; not an available API or executable proof.', 'under-design': 'Unresolved design; no settled API contract.' },
  pages,
};
fs.writeFileSync(path.join(distDir, 'docs-index.json'), `${JSON.stringify(index, null, 2)}\n`);
console.log(`export-docs: ${pages.length} Markdown pages; ${version} ${channel}; revision ${revision}; working tree ${clean ? 'clean' : 'dirty'}`);
