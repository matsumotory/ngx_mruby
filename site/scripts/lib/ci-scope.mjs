import { sameDocumentContract } from './ci-markdown.mjs';

// Conservative browser selection. This module has no filesystem or browser effects.
// The caller must establish the comparison baseline and a complete, freshly built
// manifest before it may opt into targeted coverage. Static checks stay complete.
const RECORDS = new Set(['AGENTS.md', 'CLAUDE.md', 'README.md']);
const validPath = (value) => typeof value === 'string' && value.length > 0 &&
  !/[\\\x00-\x1f\x7f]/.test(value) && value.split('/').every((part) => part && part !== '.' && part !== '..');
const full = (reason) => ({ mode: 'full', pages: [], reason });

// Use precisely the parser/features used by the generator. Ambiguous or
// unavailable input fails closed rather than approximating Markdown nesting.
export function isLocalProseChange(oldText, newText) {
  if (typeof oldText !== 'string' || typeof newText !== 'string' ||
      oldText.includes('\0') || newText.includes('\0')) return false;
  try {
    return sameDocumentContract(oldText, newText);
  } catch {
    return false;
  }
}

/**
 * changes: [{path,status,oldMode,newMode,oldText,newText}]; status must be M.
 * manifest: complete generated/pages.json [{source,route,lang,...}]. Fallback
 * pages need not have rows: the paired language route is always included.
 * event: pull_request or push (branch only); callers reject tags/manual events.
 */
export function planBrowserScope({ changes, manifest, event, baselineKnown = false, manifestComplete = false } = {}) {
  if (!['pull_request', 'push'].includes(event) || baselineKnown !== true) return full('unknown-event-or-baseline');
  if (!Array.isArray(changes) || changes.length === 0) return full('empty-or-invalid-change-range');
  if (manifestComplete !== true || !Array.isArray(manifest) || manifest.length === 0) return full('incomplete-manifest');
  const bySource = new Map();
  const routes = new Set();
  for (const page of manifest) {
    if (!page || !validPath(page.source) || typeof page.route !== 'string' ||
        (page.route !== '' && (!validPath(page.route) || !/^[\p{L}\p{N}_./-]+$/u.test(page.route))) || !['en', 'ja'].includes(page.lang) ||
        (page.lang === 'ja') !== (page.route === 'ja' || page.route.startsWith('ja/')) ||
        routes.has(page.route)) return full('invalid-manifest');
    routes.add(page.route);
    if (!bySource.has(page.source)) bySource.set(page.source, []);
    bySource.get(page.source).push(page);
  }
  const selected = new Set();
  for (const change of changes) {
    if (!change || !validPath(change.path) || change.status !== 'M' ||
        change.oldMode !== '100644' || change.newMode !== '100644') return full('non-regular-or-structural-file-change');
    if (RECORDS.has(change.path)) {
      // The allowlist is valid only while these records are not rendered.
      if (bySource.has(change.path)) return full('record-is-rendered');
      continue;
    }
    if (!change.path.startsWith('docs/') || !change.path.endsWith('.md')) return full('shared-or-unknown-input');
    const pages = bySource.get(change.path);
    if (!pages || !isLocalProseChange(change.oldText, change.newText)) return full('unknown-source-or-structural-content');
    for (const page of pages) {
      const english = page.lang === 'ja' ? (page.route === 'ja' ? '' : page.route.slice(3)) : page.route;
      // A translated source without its English manifest row is partial data.
      if (!routes.has(english)) return full('missing-language-baseline');
      selected.add(english === '' ? '/' : `/${english}/`);
      selected.add(english === '' ? '/ja/' : `/ja/${english}/`);
    }
  }
  return selected.size ? { mode: 'targeted', pages: [...selected].sort(), reason: 'local-prose-or-links' } :
    { mode: 'none', pages: [], reason: 'non-rendered-records-only' };
}
