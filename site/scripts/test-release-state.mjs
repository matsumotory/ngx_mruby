import assert from 'node:assert/strict';
import { newestStableTag, summarizeReleases } from './lib/release-state.mjs';
import { githubStars, releaseBadge } from './lib/project-badges.mjs';
assert.deepEqual(summarizeReleases(['v2.9.0', 'v3.0.0', 'v2.11.0-rc.1', 'v2.10.0'], ['v2.9.0.md', 'v2.10.0.md', 'v2.10.1.md', 'v2.10.1.ja.md', 'v3.0.0.md', 'README.md'], 2), {latest_release_tag:'v2.10.0', unreleased_versions:['v2.10.1']});
assert.deepEqual(summarizeReleases(['v2.10.1', 'v2.10.0'], ['v2.10.1.md'], 2), {latest_release_tag:'v2.10.1', unreleased_versions:[]});
assert.throws(()=>summarizeReleases(['v2.11.0-rc.1'], [], 2), /No reachable stable/);
// The release badge of the home pages: the newest stable tag of any major.
assert.equal(newestStableTag(['v2.7.3', 'v2.10.0', 'v3.0.0-rc.1', 'v2.9.9', 'v1.20.2']), 'v2.10.0');
assert.equal(newestStableTag(['v2.7.3', 'v3.0.0', 'v3.0.0-rc.2']), 'v3.0.0');
assert.throws(() => newestStableTag(['v3.0.0-alpha.1', '']), /No stable release tag/);
const badge = releaseBadge('v2.7.3', 'en');
assert.equal(badge.width, 95);
assert.equal(badge.href, 'https://github.com/matsumotory/ngx_mruby/releases/tag/v2.7.3');
assert.match(badge.svg, /^<svg [^>]*width="95" height="20"/);
assert.equal(releaseBadge('v2.7.3', 'ja').alt, '最新のリリースはv2.7.3');
assert.equal(decodeURIComponent(badge.src.replace('data:image/svg+xml,', '')), badge.svg);
assert.throws(() => releaseBadge('v3.0.0-rc.1', 'en'), /not a stable release tag/);
// The star count of the header: none without the variables, a short count
// of at most four characters, and a failed build on a malformed value.
assert.equal(githubStars('en', {}), null);
for (const [count, short] of [['997', '997'], ['1000', '1K'], ['1234', '1.2K'], ['12345', '12K'], ['123456', '123K']]) assert.equal(githubStars('en', { NGX_MRUBY_SITE_STARS: count, NGX_MRUBY_SITE_STARS_DATE: '2026-11-01' }).short, short);
assert.equal(githubStars('ja', { NGX_MRUBY_SITE_STARS: '1234', NGX_MRUBY_SITE_STARS_DATE: '2026-11-01' }).label, '、2026年11月1日時点のスターは1,234件');
for (const env of [{ NGX_MRUBY_SITE_STARS: '997' }, { NGX_MRUBY_SITE_STARS: 'many', NGX_MRUBY_SITE_STARS_DATE: '2026-11-01' }, { NGX_MRUBY_SITE_STARS: '997', NGX_MRUBY_SITE_STARS_DATE: '11/01' }]) assert.throws(() => githubStars('en', env), /must be digits/);
console.log('test-release-state: numeric ordering, prerelease exclusion, localized-note exclusion, release advancement and missing-tag failure pass; the newest stable tag, the release badge and the star count pass');
