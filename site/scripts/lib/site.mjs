// Paths, constants and helpers shared by the generator and the checks of
// site/scripts (docs/proposals/site.md, 5.2 and step 1 of section 6).
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The address of the site. astro.config.mjs imports it as `site`, and the
// link check treats URLs on this origin as links into the built site.
export const SITE_URL = 'https://ngx.mruby.org';

// Links to files of the repository that the site does not render go to
// GitHub, on the branch that the site is built from.
export const GITHUB_URL = 'https://github.com/matsumotory/ngx_mruby';
export const GITHUB_REF = 'next';

export const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const repoDir = path.resolve(siteDir, '..');
// Where scripts/sync-docs.mjs writes the pages and the list of them. The
// pages go into Starlight's content folder beside the committed home pages
// index.mdx and ja/index.mdx (docs/proposals/site.md, 5.2), each at the
// folder of its route; .gitignore ignores everything else there.
export const contentRoot = path.join(siteDir, 'src', 'content', 'docs');
export const contentDir = contentRoot;
export const HOME_PAGES = ['index.mdx', 'ja/index.mdx'];
export const manifestFile = path.join(siteDir, 'generated', 'pages.json');
export const distDir = path.join(siteDir, 'dist');

// The pages whose route is not the path of their source (the site map of
// docs/proposals/site.md, 3.2, and the four kinds of page of 3.1). The
// files stay where GitHub and the 2.x branch have them, and the page moves
// on the site. A source outside docs/ is rendered only when it is listed
// here: the README of examples/start/, which readers on GitHub read beside
// the files of the example. A Japanese page (docs/ja/<path>) takes the
// route of its English page under /ja/.
export const SOURCE_ROUTES = {
  'examples/start/README.md': 'start',
  'docs/install/README.md': 'guides/install',
  'docs/use_case/README.md': 'guides/use-cases',
  'docs/directives/README.md': 'reference/directives',
  'docs/class_and_method/README.md': 'reference/ruby',
  'docs/migration/README.md': 'releases/migration',
  'docs/test/README.md': 'contributing/test',
  'docs/DEVELOPMENT.md': 'contributing/development',
  'docs/HANDOFF.md': 'contributing/handoff',
};

// The place of a page in its group of the sidebar (astro.config.mjs), by
// route without the /ja/ prefix. The other pages of a group follow, in the
// order of their routes.
export const SIDEBAR_ORDER = {
  'guides/install': 1,
  'guides/use-cases': 99,
  'reference/directives': 1,
  'reference/ruby': 2,
  releases: 1,
  'releases/migration': 2,
  concepts: 1,
  'concepts/request-phases': 2,
  'concepts/filters': 3,
  'concepts/async': 4,
  'concepts/lifetimes': 5,
};

// Options of the checks: --dist DIR (the built site, default site/dist),
// --repo DIR (the git repository of the sources, default the parent of
// site/) and --manifest FILE (default site/generated/pages.json). They let a
// check run on a copy of the built site, such as one with a planted fault.
export function checkOptions(argv = process.argv.slice(2)) {
  const options = { dist: distDir, repo: repoDir, manifest: manifestFile };
  for (let i = 0; i < argv.length; i++) {
    const name = argv[i].replace(/^--/, '');
    if (!argv[i].startsWith('--') || !(name in options) || i + 1 >= argv.length) {
      usage(`unknown argument ${argv[i]}`);
    }
    options[name] = path.resolve(argv[++i]);
  }
  if (!fs.existsSync(path.join(options.dist, 'index.html'))) {
    usage(`${options.dist} has no index.html: run npm run build first`);
  }
  if (!fs.existsSync(options.manifest)) {
    usage(`${options.manifest} is missing: run npm run build first`);
  }
  return options;
}

function usage(message) {
  const me = path.basename(process.argv[1]);
  console.error(`${me}: ${message}`);
  console.error(`usage: node scripts/${me} [--dist DIR] [--repo DIR] [--manifest FILE]`);
  process.exit(2);
}

// The pages that scripts/sync-docs.mjs wrote: [{ source, lang, route, title,
// lastUpdated }], with routes like '' (the home page), 'install' and
// 'ja/releases/v3.0.0'.
export function loadManifest(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// The HTML files of the built site, as paths relative to it.
export function htmlFiles(dist) {
  const files = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.html')) files.push(path.relative(dist, full).split(path.sep).join('/'));
    }
  };
  walk(dist);
  return files.sort();
}

// The route of a built page ('install/index.html' -> 'install'), or null for
// a file that is not the index of a route (404.html).
export function routeOfFile(file) {
  if (file === 'index.html') return '';
  return file.endsWith('/index.html') ? file.slice(0, -'/index.html'.length) : null;
}

export function fileOfRoute(route) {
  return route === '' ? 'index.html' : `${route}/index.html`;
}

// The page of the manifest that a built route shows. A route under ja/ that
// has no Japanese source is Starlight's fallback: the English page shown
// under /ja/ with a notice (docs/proposals/site.md, 3.4).
export function pageOfRoute(pages, route) {
  const page = pages.find((p) => p.route === route);
  if (page) return { page, fallback: false };
  if (route === 'ja' || route.startsWith('ja/')) {
    const english = pages.find((p) => p.lang === 'en' && p.route === route.slice(3));
    if (english) return { page: english, fallback: true };
  }
  return { page: undefined, fallback: false };
}

// The date of the last commit that changed a file, as YYYY-MM-DD (the
// committer date), or '' when no commit changed it.
export function lastCommitDate(repo, file) {
  return execFileSync('git', ['-C', repo, 'log', '-1', '--format=%cs', '--', file], { encoding: 'utf8' }).trim();
}

export function isShallow(repo) {
  return execFileSync('git', ['-C', repo, 'rev-parse', '--is-shallow-repository'], { encoding: 'utf8' }).trim() !== 'false';
}

// Prints the problems and the summary of a check, and exits with 1 when
// there is a problem.
export function finish(name, problems, summary) {
  for (const problem of problems) console.log(problem);
  if (problems.length > 0) {
    console.log(`${name}: ${problems.length} problem(s); ${summary}`);
    process.exit(1);
  }
  console.log(`${name}: ok; ${summary}`);
}
