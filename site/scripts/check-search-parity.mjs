// Compare the actual generated Pagefind/WASM search with the UI's ranking.
// This is a Node runtime check, not a browser dialog/interaction check.
// node scripts/check-search-parity.mjs --base DIR --head DIR
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { pagefindOptions } from '../src/search-config.mjs';

// Proposal 5.4 acceptance 4: every query from check-search-identifiers,
// followed by the first content h2 of the specified Japanese pages.
// Keep these queries fixed across both versions and languages, including
// the v3 guide query when searching v2. The unknown identifier is deliberate.
export const identifierTerms = ['mruby_content_handler', 'Nginx::Request', '"zzqv_zzqw_74931"'];
export const japaneseHeadingTerms = [
  ['start', '始める前に用意するもの'],
  ['guides/install', 'ソースからインストールする'],
  ['reference/build', 'ビルドの組み立て'],
  ['guides/agent-proxy', '実装状況とv3の完成像'],
];
// The baseline request-phases page has no content h2. Its h1 is an
// additional query, not a claim that the first-h2 criterion was measured.
export const headingCoverageNotes = ['/ja/concepts/request-phases/: no content h2 in baseline; h1 query is supplemental'];
export const terms = [...new Set([...identifierTerms, ...japaneseHeadingTerms.map(([, term]) => term),
  'リクエストのフェーズ', 'ssl', 'request body', 'install', 'ビルド', 'async', 'header', 'proxy'])];
const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// The current UI must consume the options measured below. The base is
// verified from its compiled Search bundle, not its historical source shape.
export function assertUiWiring(own) {
  assert.match(own, /import\s*\{\s*pagefindOptions\s*\}\s*from\s*['"]\.\.\/search-config\.mjs['"]/);
  assert.match(own, /new PagefindUI\(\{\s*\.\.\.pagefindOptions\s*,/);
}

export function assertBundleRanking(source, label) {
  const objects = [...source.matchAll(/ranking\s*:\s*\{([^{}]+)\}/g)];
  assert.ok(objects.length, `${label}: built search UI is missing ranking`);
  const rankings = objects.map(([, body]) => Object.fromEntries(body.split(',').filter(Boolean).map((entry) => {
    const match = entry.trim().match(/^([a-zA-Z]+)\s*:\s*(\d*\.?\d+)$/);
    assert.ok(match, `${label}: unsupported ranking expression ${entry}`);
    return [match[1], Number(match[2])];
  })));
  assert.ok(rankings.some((ranking) => {
    try { assert.deepEqual(ranking, pagefindOptions.ranking); return true; } catch { return false; }
  }), `${label}: built ranking differs from the shared UI options`);
}

async function checkBuiltRanking(dist, prefix) {
  const assets = path.join(dist, prefix, '_astro');
  const scripts = (await fs.readdir(assets)).filter((name) => /^Search\..*\.js$/.test(name));
  assert.ok(scripts.length, `${assets}: missing Search bundle`);
  for (const name of scripts) assertBundleRanking(await fs.readFile(path.join(assets, name), 'utf8'), `${prefix}/${name}`);
}

async function query(dist, prefix, language) {
  const directory = path.join(dist, prefix, 'pagefind');
  const originalDocument = globalThis.document;
  const originalFetch = globalThis.fetch;
  // Pagefind detects the HTML language. No DOM layout is emulated here.
  globalThis.document = { currentScript: null, querySelector: () => ({ getAttribute: () => language }) };
  globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    assert.equal(url.protocol, 'file:', 'search parity must not fetch the network');
    const file = fileURLToPath(url);
    assert.ok(file.startsWith(directory + path.sep), `unexpected index path: ${file}`);
    return new Response(await fs.readFile(file));
  };
  let index;
  try {
    index = await import(pathToFileURL(path.join(directory, 'pagefind.js')).href + `?language=${language}`);
    await index.options({ ...pagefindOptions, baseUrl: prefix ? `/${prefix}/` : '/' });
    const rows = [];
    for (const term of terms) {
      const result = await index.search(term);
      if (term === identifierTerms[2]) assert.equal(result.results.length, 0, 'unknown identifier returned unrelated results');
      const urls = await Promise.all(result.results.slice(0, 5).map(async (item) => (await item.data()).url));
      assert.ok(urls.every((url) => prefix ? url.startsWith(`/${prefix}/`) : !url.startsWith('/v2/')), 'cross-version result');
      rows.push({ language, term, urls });
    }
    return rows;
  } finally {
    await index?.destroy();
    globalThis.document = originalDocument;
    globalThis.fetch = originalFetch;
  }
}

export async function compareSearch(base, head) {
  assertUiWiring(await fs.readFile(path.join(site, 'src/own/Search.astro'), 'utf8'));
  const rows = [];
  for (const prefix of ['', 'v2']) {
    await checkBuiltRanking(base, prefix);
    await checkBuiltRanking(head, prefix);
    for (const language of ['en', 'ja']) {
      const before = await query(base, prefix, language);
      const after = await query(head, prefix, language);
      assert.deepEqual(after, before, `${prefix || '/'} ${language}: ranked result order differs`);
      rows.push(...after.map((row) => ({ version: prefix || '3.x', ...row })));
    }
  }
  assert.ok(rows.some((row) => row.urls.length), 'all queries were empty');
  return rows;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const base = args.indexOf('--base'), head = args.indexOf('--head');
  assert.ok(base >= 0 && head >= 0 && args[base + 1] && args[head + 1], 'usage: --base DIR --head DIR');
  const rows = await compareSearch(path.resolve(args[base + 1]), path.resolve(args[head + 1]));
  console.log(JSON.stringify(rows, null, 2));
  for (const note of headingCoverageNotes) console.log(`check-search-parity: coverage note: ${note}`);
  console.log(`check-search-parity: ${rows.length} queries, UI ranking, top-five URL order equal; Node/WASM, not browser interaction`);
}
