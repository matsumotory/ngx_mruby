import assert from 'node:assert/strict';
import { summarizeReleases } from './lib/release-state.mjs';
assert.deepEqual(summarizeReleases(['v2.9.0', 'v3.0.0', 'v2.11.0-rc.1', 'v2.10.0'], ['v2.9.0.md', 'v2.10.0.md', 'v2.10.1.md', 'v2.10.1.ja.md', 'v3.0.0.md', 'README.md'], 2), {latest_release_tag:'v2.10.0', unreleased_versions:['v2.10.1']});
assert.deepEqual(summarizeReleases(['v2.10.1', 'v2.10.0'], ['v2.10.1.md'], 2), {latest_release_tag:'v2.10.1', unreleased_versions:[]});
assert.throws(()=>summarizeReleases(['v2.11.0-rc.1'], [], 2), /No reachable stable/);
console.log('test-release-state: numeric ordering, prerelease exclusion, localized-note exclusion, release advancement and missing-tag failure pass');
