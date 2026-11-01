// Check of step 1 (docs/proposals/site.md, section 6): every page has a
// title and the last-updated date of its source.
//
//   node scripts/check-pages.mjs [--dist DIR] [--repo DIR] [--manifest FILE]
//
// For every HTML file of the built site that is the page of a route
// (every file but the site's not-found page, 404.html, which has no
// source):
//
// - the page has a source: a file of docs/ that generated/pages.json lists
//   for the route, or, for a route under /ja/ without a Japanese source,
//   the English page that the site shows there as its fallback (3.4);
// - <title> is "<h1> | ngx_mruby", and the h1 in <main> has text;
// - the <time datetime> in the footer of <main> has the date of the last
//   commit that changed the source, which the check reads from git itself
//   (git log -1 --format=%cs -- <source>), not from the generator.
//
// It also checks that every page of generated/pages.json was built.
//
// Exit status: 0 when every page passes, 1 otherwise (each problem is
// printed with its page), 2 on a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, findElement, readHtml, textContent } from './lib/html.mjs';
import { checkOptions, fileOfRoute, finish, htmlFiles, lastCommitDate, loadManifest, pageOfRoute, routeOfFile } from './lib/site.mjs';

const { dist, repo, manifest } = checkOptions();
const pages = loadManifest(manifest);
const problems = [];
const dates = new Map();
const dateOf = (source) => {
  if (!dates.has(source)) dates.set(source, lastCommitDate(repo, source));
  return dates.get(source);
};

let checked = 0;
let fallbacks = 0;
for (const file of htmlFiles(dist)) {
  if (file === '404.html') continue;
  const route = routeOfFile(file);
  if (route === null) {
    problems.push(`${file}: not the index.html of a route, and not 404.html`);
    continue;
  }
  checked++;
  const { page, fallback } = pageOfRoute(pages, route);
  if (!page) {
    problems.push(`${file}: no source in docs/ for the route /${route}/`);
    continue;
  }
  if (fallback) fallbacks++;
  const tree = readHtml(path.join(dist, file));
  const title = textContent(findElement(tree, (e) => e.tagName === 'title') ?? { children: [] }).trim();
  const main = findElement(tree, (e) => e.tagName === 'main');
  const h1 = main && findElement(main, (e) => e.tagName === 'h1');
  const heading = h1 ? textContent(h1).trim() : '';
  if (!heading) problems.push(`${file}: no h1 with text in <main> (source ${page.source})`);
  if (!title) problems.push(`${file}: no <title> (source ${page.source})`);
  else if (heading && title !== `${heading} | ngx_mruby`) {
    problems.push(`${file}: <title> is "${title}", expected "${heading} | ngx_mruby"`);
  }

  const expected = dateOf(page.source);
  const footer = main && findElement(main, (e) => e.tagName === 'footer');
  const times = footer ? elements(footer).filter((e) => e.tagName === 'time' && e.properties?.dateTime) : [];
  if (!expected) {
    problems.push(`${file}: no commit changed the source ${page.source}, so it has no last-updated date`);
  } else if (times.length !== 1) {
    problems.push(`${file}: ${times.length} <time datetime> elements in the footer of <main>, expected 1 with ${expected} (source ${page.source})`);
  } else {
    const shown = String(times[0].properties.dateTime).slice(0, 10);
    if (shown !== expected) {
      problems.push(`${file}: last updated ${shown}, but the last commit to ${page.source} is of ${expected}`);
    }
  }
}

for (const page of pages) {
  if (!fs.existsSync(path.join(dist, fileOfRoute(page.route)))) {
    problems.push(`${fileOfRoute(page.route)}: missing, but generated/pages.json lists it for ${page.source}`);
  }
}

finish('check-pages', problems, `${checked} pages checked (${checked - fallbacks} from their own source, ${fallbacks} English fallbacks under /ja/), 404.html left out`);
