// Builds the 2.x pages under /v2/ (docs/proposals/site.md, 3.4, 5.2 and
// step 6 of section 6) from docs/ of another git work tree, and puts them
// beside the 3.x build in dist/v2/.
//
//   node scripts/build-v2.mjs --tree DIR
//
// DIR is a work tree of the 2.x branch (master until the promotion of 5.2,
// then v2.x) with its whole history, since the last-updated date of a page
// is the date of the last commit to its source there. The workflow site.yml
// on next checks out master for it; site-v2.yml on master checks out the
// pull request's merge commit, with next for the 3.x pages and site/.
// DIR is only read.
//
// The 2.x build runs the build of this site/ (npm run build: the generator,
// astro build and mark-num-cells) in a copy of it, generated/v2-site/, with
// node_modules linked to this one and without the home pages, and with
// NGX_MRUBY_SITE_VERSION=2 and NGX_MRUBY_SITE_REPO=DIR, which
// scripts/lib/site.mjs reads: the pages of DIR/docs/ (and SECURITY.md and
// CONTRIBUTING.md of SOURCE_ROUTES), with docs/README.md as the index /v2/,
// links to files that the site does not render going to GitHub at master,
// the base /v2/, the sidebar of the 2.x pages (astro.config.mjs) and the
// banner of 3.4 on every page (src/components/Banner.astro). Pagefind
// writes the search index of the 2.x pages into their own build, so 2.x
// pages search /v2/pagefind/ and 3.x pages /pagefind/, which was written
// before the 2.x pages were added (3.4: one index per version).
//
// Afterwards dist/v2/ holds the 2.x pages, without the 404 page (GitHub
// Pages serves /404.html for every path without a file, /v2/ paths
// included) and without the copies of VERBATIM_FILES, which the site
// serves at its top only, and generated/pages-v2.json the list of them,
// which
// scripts/check-v2.mjs reads. Run npm run build first: the 3.x build
// removes generated/ and dist/. The previous dist/v2/ and the list are
// removed first, and the copy of site/ also when the build fails, so that
// a failed build leaves no 2.x pages for the checks to read.
//
// Exit status: 0 when the build succeeds, 1 when it fails, 2 on a usage
// error.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { distDir, manifestFile, siteDir, V2_DIR, v2ManifestFile, VERBATIM_FILES } from './lib/site.mjs';

const me = 'build-v2';
function usage(message) {
  console.error(`${me}: ${message}`);
  console.error('usage: node scripts/build-v2.mjs --tree DIR');
  process.exit(2);
}
const stage = path.join(siteDir, 'generated', 'v2-site');
function fail(message) {
  fs.rmSync(stage, { recursive: true, force: true });
  console.error(`${me}: ${message}`);
  process.exit(1);
}

const argv = process.argv.slice(2);
if (argv.length !== 2 || argv[0] !== '--tree') usage('expected --tree DIR');
const tree = path.resolve(argv[1]);
let top;
try {
  top = execFileSync('git', ['-C', tree, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
} catch {
  usage(`${tree} is not a git work tree`);
}
if (fs.realpathSync(top) !== fs.realpathSync(tree)) usage(`${tree} is not the top of its git work tree (${top} is)`);
if (!fs.existsSync(path.join(tree, 'docs', 'README.md'))) usage(`${tree} has no docs/README.md`);
if (!fs.existsSync(path.join(distDir, 'index.html')) || !fs.existsSync(manifestFile)) {
  usage('the 3.x build is missing (dist/index.html, generated/pages.json): run npm run build first');
}

// The copy of site/: what the build reads, without what npm ci, the 3.x
// build and the checks wrote, and without the home pages and the pages
// that the generator wrote for 3.x.
const target = path.join(distDir, V2_DIR);
fs.rmSync(target, { recursive: true, force: true });
fs.rmSync(v2ManifestFile, { force: true });
fs.rmSync(path.join(siteDir, 'generated', 'markdown-v2'), { recursive: true, force: true });
fs.rmSync(stage, { recursive: true, force: true });
const skip = new Set(['node_modules', 'dist', 'generated', '.astro', 'build-screenshots', 'offline-build.log']);
const content = path.join(siteDir, 'src', 'content', 'docs');
for (const name of fs.readdirSync(siteDir)) {
  if (skip.has(name)) continue;
  fs.cpSync(path.join(siteDir, name), path.join(stage, name), {
    recursive: true,
    filter: (src) => !src.startsWith(`${content}${path.sep}`),
  });
}
fs.mkdirSync(path.join(stage, 'src', 'content', 'docs'), { recursive: true });
fs.symlinkSync(path.join(siteDir, 'node_modules'), path.join(stage, 'node_modules'), 'dir');

const commit = execFileSync('git', ['-C', tree, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
console.log(`${me}: building /v2/ from docs/ of ${tree} at ${commit}`);
const run = spawnSync('npm', ['run', 'build'], {
  cwd: stage,
  stdio: 'inherit',
  env: { ...process.env, NGX_MRUBY_SITE_VERSION: '2', NGX_MRUBY_SITE_REPO: tree },
});
if (run.status !== 0) fail(`npm run build of the 2.x pages failed (exit status ${run.status ?? run.signal})`);

const built = path.join(stage, 'dist');
if (!fs.existsSync(path.join(built, 'index.html'))) fail('the 2.x build wrote no index.html');
if (!fs.existsSync(path.join(built, 'pagefind'))) fail('the 2.x build wrote no search index (pagefind/)');
fs.rmSync(path.join(built, '404.html'), { force: true });
for (const { file } of VERBATIM_FILES) fs.rmSync(path.join(built, file), { force: true });
fs.cpSync(built, target, { recursive: true });
const pages = JSON.parse(fs.readFileSync(path.join(stage, 'generated', 'pages.json'), 'utf8'));
fs.cpSync(path.join(stage, 'generated', 'markdown'), path.join(siteDir, 'generated', 'markdown-v2'), { recursive: true });
fs.writeFileSync(v2ManifestFile, `${JSON.stringify({ tree, commit, pages }, null, 2)}\n`);
fs.rmSync(stage, { recursive: true, force: true });
console.log(`${me}: ok; ${pages.length} pages of ${commit} in ${path.relative(siteDir, target)}/, the list in ${path.relative(siteDir, v2ManifestFile)}`);
