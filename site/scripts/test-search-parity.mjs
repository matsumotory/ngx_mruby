import assert from 'node:assert/strict';
import { assertUiWiring, assertBundleRanking, identifierTerms, japaneseHeadingTerms, terms, headingCoverageNotes } from './check-search-parity.mjs';
const own = "import { pagefindOptions } from '../search-config.mjs'; new PagefindUI({ ...pagefindOptions, element: '#search' })";
assertUiWiring(own);
assert.throws(() => assertUiWiring(own.replace('...pagefindOptions,', '')));
const bundle = 'ranking:{pageLength:.1,termFrequency:.1,termSaturation:2,termSimilarity:9,diacriticSimilarity:.8}';
assertBundleRanking(bundle, 'fixture');
assert.throws(() => assertBundleRanking('new PagefindUI({})', 'missing ranking'));
assert.throws(() => assertBundleRanking(bundle.replace('pageLength:.1', 'pageLength:1'), 'wrong ranking'));
assert.deepEqual(identifierTerms, ['mruby_content_handler', 'Nginx::Request', '"zzqv_zzqw_74931"']);
assert.deepEqual(japaneseHeadingTerms, [
  ['start', '始める前に用意するもの'],
  ['guides/install', 'ソースからインストールする'],
  ['reference/build', 'ビルドの組み立て'],
  ['guides/agent-proxy', '実装状況とv3の完成像'],
]);
assert.ok([...identifierTerms, ...japaneseHeadingTerms.map(([, term]) => term)].every(term => terms.includes(term)));
assert.equal(new Set(terms).size, terms.length);
assert.match(headingCoverageNotes.join(' '), /request-phases.*no content h2/);
console.log('test-search-parity: 10 UI wiring, built ranking and required-query regression assertions passed');
