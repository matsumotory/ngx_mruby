// An optional page set for a local run of a browser check: SITE_CI_PAGES
// holds a JSON array of routes. Missing means full coverage; malformed,
// empty or unavailable routes are errors, never an empty pass.
// SITE_CI_VERSION ('2' or '3') limits check-code-layout.mjs to one version.
import fs from 'node:fs';
import path from 'node:path';
export function scopedPages(dist, raw = process.env.SITE_CI_PAGES) {
  if (raw === undefined) return null;
  const pages = JSON.parse(raw);
  if (!Array.isArray(pages) || !pages.length || new Set(pages).size !== pages.length) throw new Error('invalid CI page set');
  for (const page of pages) {
    if (typeof page !== 'string' || (!/^\/(?:[a-zA-Z0-9_.-]+\/)*$/.test(page) || page.split('/').some(part => part === '.' || part === '..'))) throw new Error(`invalid CI route: ${page}`);
    if (!fs.existsSync(path.join(dist, page, 'index.html'))) throw new Error(`missing CI route: ${page}`);
  }
  return pages;
}

export function codePageScope(allPages, representatives, selected = null, version) {
  if (version !== undefined && !['2','3'].includes(version)) throw new Error('invalid code-layout version');
  const inVersion = route => !version || (route.startsWith('/v2/') ? '2' : '3') === version;
  const pages = (selected ?? allPages).filter(inVersion);
  const stressPages = (selected ?? representatives).filter(inVersion);
  if (!pages.length || stressPages.some(route => !pages.includes(route))) throw new Error('incomplete code-layout selection');
  return {pages,stressPages};
}
