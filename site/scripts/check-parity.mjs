// Semantic HTML parity for the two shells, site proposal 5.4.
// node scripts/check-parity.mjs --base DIR --head DIR
// This does not replace browser layout, interaction or search checks.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { htmlToHast } from 'satteri';
import { elements, hasClass, textContent, visibleText } from './lib/html.mjs';

const compact = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();
const prop = (el, key) => el?.properties?.[key];
const tag = (el) => el.tagName.includes('-') ? '#custom-element' : el.tagName;
const sorted = (values) => values.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
const attr = (el, keys) => Object.fromEntries(keys.filter((k) => prop(el, k) !== undefined).map((k) => [k, prop(el, k)]));
const isHeadingWrapper = (el) => hasClass(el, 'site-heading-wrapper') || hasClass(el, 'sl-heading-wrapper') || hasClass(el, 'heading-wrapper');
const isHeadingAnchor = (el) => hasClass(el, 'site-anchor-link') || hasClass(el, 'sl-anchor-link') || hasClass(el, 'heading-anchor');
const isThemeTemplate = (el) => el.tagName === 'template' && prop(el, 'id') === 'theme-icons';
const isContent = (el) => hasClass(el, 'site-markdown-content') || hasClass(el, 'sl-markdown-content') || hasClass(el, 'doc-content') || hasClass(el, 'markdown-content');

// File names emitted for bundles are not stable across shells. Only
// explicitly hashed assets are exempt; ordinary files must still match.
export function isHashedAsset(file) {
  return /(?:^|\/)_(?:astro)\/[^/]+\.[A-Za-z0-9_-]{5,}\.(?:css|js|mjs|woff2?|png|svg|webp)$/.test(file)
    || /(?:^|\/)pagefind\/(?:fragment|index)\/[^/]+\.(?:pf_fragment|pf_index)$/.test(file)
    || /(?:^|\/)pagefind\/pagefind\.[a-z-]+_[a-f0-9]+\.pf_meta$/.test(file);
}

// Exact inline programs replaced by the sidebar scroll behavior permitted
// in proposal 5.4. Digests cover trimmed output from Starlight 0.42.6 and
// the own sidebar. A modified program is not exempted by a substring.
const SIDEBAR_SCRIPTS = new Map([
  ['46558470e9a702e76565bdcf62c954c14d93309f3e641774cdce5e428cd1a9e1', { ariaHidden: 'true' }],
  ['46c36b449fabfe2e694f59379fd7d0567453aeaa4cdfcbea8bc15a41df7e149f', { ariaHidden: 'true' }],
  ['560ae070a06f20cdd7a622c9e9f12fd55cba60707094a2e462d15d7c1328b93a', { type: 'module' }],
  ['1fcaddf14e0009c34c731c474291b62fd3f067c0454f1d5a0b54e2bd7695c5c4', { type: 'module' }],
]);
const allowedSidebarScript = (el) => {
  if (el.tagName !== 'script') return false;
  const hash = createHash('sha256').update(textContent(el).trim()).digest('hex');
  // The new initializer sets this marker itself.
  if (hash === '73452e5d846873a0f6f3e0f263b7bc24cfc8cad8b2f5b8797542bb22f18309e3' && Object.keys(el.properties ?? {}).length === 0) return true;
  const allowed = SIDEBAR_SCRIPTS.get(hash);
  return allowed && JSON.stringify(el.properties ?? {}) === JSON.stringify(allowed);
};

// Normalize only emitted _astro asset hashes, preserving path, extension,
// query and origin. Two known bundle stems name the same role in each shell.
export function normalizeAssetName(value) {
  return String(value).replace(/((?:^|\/)\_astro\/)([^/?#]+)\.([A-Za-z0-9_-]{5,})(\.(?:css|js|mjs|woff2?|png|svg|webp))(?=[?#]|$)/g,
    (_, prefix, name, hash, extension) => `${prefix}${name === 'routes' && extension === '.css' ? 'common' : name === 'toc' && extension === '.js' ? 'site-toc' : name === 'starlight-toc' && extension === '.js' ? 'site-toc' : name}.<hash>${extension}`);
}
const normalizedProperties = (el) => Object.fromEntries(Object.entries(el.properties ?? {})
  .filter(([key]) => key !== 'className' && key !== 'class')
  .sort(([a], [b]) => a.localeCompare(b))
  .map(([key, value]) => [key, ['src', 'href'].includes(key) ? normalizeAssetName(value) : value]));
// Identifier-only renames made by the removal of Starlight. The persisted
// theme key is deliberately not renamed; a changed key must fail parity.
export const normalizeShellIdentifiers = (value) => String(value)
  .replace(/sl-/g, 'site-').replace(/starlight__/g, 'site__')
  .replace(/starlight-(?!theme\b)/g, 'site-').replace(/starlight\./g, 'site.');
const THEME_PROGRAMS = new Set([
  '1f1a85ec67961936620d836a2e1a86a3fe1a39d724fe0f3b2b5625f544db18ee',
  'edf10bb716adea24105725e3f5d17f687f5a84d77b888c9e837d0886d4b7c5b5',
]);
const scriptBody = (el) => {
  const body = textContent(el).trim();
  const hash = createHash('sha256').update(body).digest('hex');
  // The exact old provider (including unused picker support) and the exact
  // new initializer preserve stored/OS theme behavior. This is not a wildcard.
  return THEME_PROGRAMS.has(hash) && Object.keys(el.properties ?? {}).length === 0
    ? '#saved-or-system-theme-initializer' : normalizeShellIdentifiers(body);
};
const scriptSnapshot = (el) => ({ properties: normalizedProperties(el), body: scriptBody(el) });
const starlightGenerator = (el) => el.tagName === 'meta' && prop(el, 'name') === 'generator' && /^Starlight v\d/.test(String(prop(el, 'content')));
function headSnapshot(node) {
  if (node.type === 'text') return node.value.trim() ? { text: node.value } : null;
  if (node.type !== 'element' || starlightGenerator(node) || isThemeTemplate(node) || allowedSidebarScript(node)) return null;
  if (node.tagName === 'script') return { tag: 'script', ...scriptSnapshot(node) };
  return { tag: tag(node), properties: normalizedProperties(node), children: (node.children ?? []).map(headSnapshot).filter(Boolean) };
}

export function snapshotHtml(source) {
  const root = htmlToHast(source);
  const all = elements(root);
  const html = all.find((e) => e.tagName === 'html');
  const content = all.filter(isContent);
  if (!html) throw new Error('missing html element');
  // 404 has no indexed body, but its main text is still compared.
  const bodies = content.length ? content : all.filter((e) => e.tagName === 'main');
  if (!bodies.length) throw new Error('missing content/main element');
  const sequence = (node) => {
    const out = [];
    for (const e of node.children ?? []) {
      if (e.type !== 'element' || ['script', 'style'].includes(e.tagName) || isThemeTemplate(e) || isHeadingAnchor(e)) continue;
      if (isHeadingWrapper(e)) out.push(...sequence(e));
      else out.push([tag(e), sequence(e)]);
    }
    return out;
  };
  const pagefind = all.filter((e) => Object.keys(e.properties ?? {}).some((k) => k.startsWith('dataPagefind') || k.startsWith('data-pagefind-'))).map((e) => ({
    tag: tag(e), attributes: Object.fromEntries(Object.entries(e.properties).filter(([k]) => k.startsWith('dataPagefind') || k.startsWith('data-pagefind-')).sort()),
    // Metadata can come from another attribute rather than inner text.
    content: prop(e, 'content') ?? null,
  }));
  const fallback = all.filter((e) => prop(e, 'lang') === 'en' && e !== html).map((e) => ({ tag: tag(e), text: compact(visibleText(e)) }));
  const notices = all.filter((e) => prop(e, 'dataNotice') !== undefined || prop(e, 'data-notice') !== undefined).map((e) => ({ kind: prop(e, 'dataNotice') ?? prop(e, 'data-notice'), text: compact(visibleText(e)) }));
  return {
    head: all.filter((e) => e.tagName === 'head').map(headSnapshot),
    scripts: all.filter((e) => e.tagName === 'script' && !allowedSidebarScript(e)).map(scriptSnapshot),
    styles: all.filter((e) => e.tagName === 'style').map((e) => ({ properties: normalizedProperties(e), body: textContent(e).trim() })),
    html: attr(html, ['lang', 'dir', 'dataTheme', 'dataHasSidebar', 'dataHasToc']),
    title: all.filter((e) => e.tagName === 'title').map((e) => compact(textContent(e))),
    meta: sorted(all.filter((e) => e.tagName === 'meta' && (prop(e, 'name') === 'description' || String(prop(e, 'property') ?? '').startsWith('og:') || String(prop(e, 'name') ?? '').startsWith('twitter:'))).map((e) => attr(e, ['name', 'property', 'content']))),
    canonical: all.filter((e) => e.tagName === 'link' && [].concat(prop(e, 'rel') ?? []).includes('canonical')).map((e) => prop(e, 'href')),
    alternates: sorted(all.filter((e) => e.tagName === 'link' && prop(e, 'hrefLang') !== undefined).map((e) => attr(e, ['hrefLang', 'href']))),
    headings: all.filter((e) => /^h[1-6]$/.test(e.tagName)).map((e) => [e.tagName, prop(e, 'id') === 'starlight__on-this-page' ? 'site__on-this-page' : prop(e, 'id') ?? null, compact(visibleText(e))]),
    navigation: all.filter((e) => e.tagName === 'a' && !isHeadingAnchor(e)).map((e) => ({ href: prop(e, 'href') ?? null, text: compact(visibleText(e)), current: prop(e, 'ariaCurrent') ?? null })),
    mainText: all.filter((e) => e.tagName === 'main').map((e) => compact(visibleText(e))),
    content: bodies.map((e) => ({ text: compact(visibleText(e)), links: elements(e).filter((n) => n.tagName === 'a' && !isHeadingAnchor(n)).map((n) => prop(n, 'href') ?? null), sequence: sequence(e) })),
    fallback, notices, pagefind,
  };
}

function files(dir, prefix = '') {
  return fs.readdirSync(path.join(dir, prefix), { withFileTypes: true }).flatMap((e) => e.isDirectory() ? files(dir, path.join(prefix, e.name)) : [path.join(prefix, e.name).split(path.sep).join('/')]).sort();
}

function sitemap(source) {
  // Sitemaps are XML. Extract the loc and alternate tags with the same
  // parser only after grouping each URL, so alternates cannot swap pages.
  const tree = htmlToHast(source);
  return sorted(elements(tree).filter((e) => ['url', 'sitemap'].includes(e.tagName)).map((e) => ({
    loc: elements(e).filter((n) => n.tagName === 'loc').map((n) => compact(textContent(n))),
    alternates: sorted(elements(e).filter((n) => n.tagName === 'xhtml:link').map((n) => ({ lang: prop(n, 'hrefLang') ?? prop(n, 'hreflang'), href: prop(n, 'href') }))),
  })));
}

export function compareBuilds(base, head) {
  const failures = [];
  const before = files(base), after = files(head);
  const same = (label, a, b) => { if (JSON.stringify(a) !== JSON.stringify(b)) failures.push(label); };
  same('built file set differs (excluding hashed bundle/index assets)', before.filter((f) => !isHashedAsset(f)), after.filter((f) => !isHashedAsset(f)));
  // Renaming a hash is allowed; silently dropping an asset is not.
  const hashedInventory = (list) => sorted(list.filter(isHashedAsset).map((f) => [path.dirname(f), path.extname(f)]));
  same('hashed asset inventory differs', hashedInventory(before), hashedInventory(after));
  for (const file of before.filter((f) => after.includes(f))) {
    if (file.endsWith('.html')) {
      try {
        const sourceA = fs.readFileSync(path.join(base, file), 'utf8');
        const sourceB = fs.readFileSync(path.join(head, file), 'utf8');
        // Google's ownership file is plain text with an .html suffix.
        if (/^google-site-verification: google[a-f0-9]+\.html\s*$/.test(sourceA)) {
          same(`${file}: ownership verification differs`, sourceA, sourceB);
          continue;
        }
        const a = snapshotHtml(sourceA);
        const b = snapshotHtml(sourceB);
        for (const key of Object.keys(a)) same(`${file}: ${key} differs`, a[key], b[key]);
      } catch (e) { failures.push(`${file}: ${e.message}`); }
    } else if (/(?:^|\/)sitemap[^/]*\.xml$/.test(file)) {
      same(`${file}: sitemap URLs/alternates differ`, sitemap(fs.readFileSync(path.join(base, file), 'utf8')), sitemap(fs.readFileSync(path.join(head, file), 'utf8')));
    }
  }
  return { failures, pages: before.filter((f) => f.endsWith('.html')).length };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--base' || args[2] !== '--head') {
    console.error('Usage: node scripts/check-parity.mjs --base DIR --head DIR');
    process.exitCode = 2;
  } else {
    try {
      const result = compareBuilds(path.resolve(args[1]), path.resolve(args[3]));
      for (const failure of result.failures) console.error(`check-parity: ${failure}`);
      console.log(`check-parity: ${result.failures.length ? 'FAIL' : 'ok'}; ${result.pages} HTML pages; ${result.failures.length} differences`);
      process.exitCode = result.failures.length ? 1 : 0;
    } catch (e) { console.error(`check-parity: ${e.message}`); process.exitCode = 2; }
  }
}
