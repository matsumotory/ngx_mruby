// Check of step 1 (docs/proposals/site.md, section 6): every internal link
// of the built HTML resolves.
//
//   node scripts/check-built-links.mjs [--dist DIR]
//
// It reads every HTML file of the built site, the 2.x pages of dist/v2/
// included (step 6: no broken link under /v2/) and every URL in the
// attributes that make a browser load or open something: a and area
// (href), link (href), script, img, source, iframe, embed, audio, video and
// track (src, srcset, poster), object (data), form (action), and the
// og:url and og:image meta tags (content). A URL is internal when it is
// relative, starts with "/", or is on the origin of the site
// (https://ngx.mruby.org, scripts/lib/site.mjs). An internal URL resolves
// when its path is a file of the built site, with "/" read as
// "/index.html", and its fragment, if any, is the id of an element of that
// page (or the name of an a element). Other URLs (other origins, mailto:,
// data:) are counted and not fetched. check-project-badges.mjs separately
// validates the one external footer image and its real browser loading.
//
// A URL attribute without a value (<a href>, href="") is a problem too, and
// so is an attribute name with a quote, "<" or "=" in it on any element:
// both are what a broken tag of a page's source turns into, such as
// <a href/install/md"> for an href whose value the generator wrote over the
// wrong characters, and a browser would show such a link with no
// destination.
//
// One exception: Starlight's not-found page, 404.html, names its own
// address as /404/ (and /ja/404/) in its canonical and alternate links and
// in og:url. GitHub Pages serves 404.html for that address, as for every
// path that has no file, so these tags of 404.html are not checked. Its
// other links are.
//
// Exit status: 0 when every internal URL resolves and no attribute has the
// problems above, 1 otherwise (each problem is printed with its page), 2 on
// a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { elements, readHtml } from './lib/html.mjs';
import { checkOptions, finish, htmlFiles, SITE_URL } from './lib/site.mjs';

const { dist } = checkOptions();
const site = new URL(SITE_URL);

const URL_ATTRIBUTES = {
  a: ['href'],
  area: ['href'],
  link: ['href'],
  script: ['src'],
  img: ['src', 'srcSet'],
  source: ['src', 'srcSet'],
  iframe: ['src'],
  embed: ['src'],
  audio: ['src'],
  video: ['src', 'poster'],
  track: ['src'],
  object: ['data'],
  form: ['action'],
};

// The tags in which a page names its own address.
function isSelfReference(element) {
  const props = element.properties ?? {};
  const rel = [].concat(props.rel ?? []).join(' ').split(/\s+/);
  if (element.tagName === 'link') return rel.includes('canonical') || rel.includes('alternate');
  return element.tagName === 'meta' && props.property === 'og:url';
}

// The problems of the attributes of an element: a URL attribute without a
// value, and an attribute name that a well-formed tag does not produce.
function attributeProblems(element) {
  const props = element.properties ?? {};
  const problems = [];
  for (const name of URL_ATTRIBUTES[element.tagName] ?? []) {
    const value = props[name] ?? props[name.toLowerCase()];
    if (value === '' || (Array.isArray(value) && value.length === 0)) {
      problems.push(`<${element.tagName}> has an empty ${name.toLowerCase()} attribute`);
    }
  }
  for (const name of Object.keys(props)) {
    if (/["'<=]/.test(name)) problems.push(`<${element.tagName}> has an attribute named ${name}, which a well-formed tag does not have`);
  }
  return problems;
}

function urlsOf(element) {
  const props = element.properties ?? {};
  const urls = [];
  for (const name of URL_ATTRIBUTES[element.tagName] ?? []) {
    const value = props[name] ?? props[name.toLowerCase()];
    if (value === undefined || value === null || value === '') continue;
    if (name === 'srcSet') {
      for (const candidate of String(Array.isArray(value) ? value.join(',') : value).split(',')) {
        const url = candidate.trim().split(/\s+/)[0];
        if (url) urls.push(url);
      }
    } else {
      urls.push(String(value));
    }
  }
  if (element.tagName === 'meta' && ['og:url', 'og:image'].includes(props.property) && props.content) {
    urls.push(String(props.content));
  }
  return urls;
}

const idsCache = new Map();
function idsOf(file) {
  if (!idsCache.has(file)) {
    const ids = new Set();
    for (const element of elements(readHtml(file))) {
      const props = element.properties ?? {};
      if (props.id) ids.add(String(props.id));
      if (element.tagName === 'a' && props.name) ids.add(String(props.name));
    }
    idsCache.set(file, ids);
  }
  return idsCache.get(file);
}

// The file of the built site that an internal path names, or null.
function fileOf(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  const rel = decoded.replace(/^\/+/, '');
  const candidates = decoded.endsWith('/') ? [path.join(rel, 'index.html')] : [rel, path.join(rel, 'index.html')];
  for (const candidate of candidates) {
    const full = path.join(dist, candidate);
    if (!full.startsWith(dist + path.sep) && full !== dist) continue;
    if (fs.existsSync(full) && fs.statSync(full).isFile()) return full;
  }
  return null;
}

const problems = [];
let internal = 0;
let external = 0;
const pages = htmlFiles(dist, { v2: true });
for (const page of pages) {
  const pageUrl = new URL(page.replace(/(^|\/)index\.html$/, '$1'), `${site.origin}/`);
  for (const element of elements(readHtml(path.join(dist, page)))) {
    if (page === '404.html' && isSelfReference(element)) continue;
    for (const problem of attributeProblems(element)) problems.push(`${page}: ${problem}`);
    for (const raw of urlsOf(element)) {
      let url;
      try {
        url = new URL(raw, pageUrl);
      } catch {
        problems.push(`${page}: <${element.tagName}> ${raw}: not a valid URL`);
        continue;
      }
      if (url.origin !== site.origin) {
        external++;
        continue;
      }
      internal++;
      const target = fileOf(url.pathname);
      if (!target) {
        problems.push(`${page}: <${element.tagName}> ${raw}: ${url.pathname} is not a file of the built site`);
        continue;
      }
      const fragment = url.hash.slice(1);
      if (!fragment || !target.endsWith('.html')) continue;
      let id;
      try {
        id = decodeURIComponent(fragment);
      } catch {
        id = fragment;
      }
      if (!idsOf(target).has(id)) {
        problems.push(`${page}: <${element.tagName}> ${raw}: ${path.relative(dist, target)} has no element with id "${id}"`);
      }
    }
  }
}

finish('check-built-links', problems, `${pages.length} HTML files, ${internal} internal URLs checked, ${external} other URLs not checked`);
