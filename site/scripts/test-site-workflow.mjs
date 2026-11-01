// The wiring of .github/workflows/site.yml and its local counterpart
// scripts/check-ci.sh (npm run check:ci), without a build or a browser.
// The owner decided on 2026-11-02 that pull requests do not run site.yml:
// it runs on a push to next and on a dispatch, builds, checks without a
// browser, deploys and checks the published site, and every check of its
// build job also runs in npm run check:ci, with the browser checks.
import assert from 'node:assert/strict';
import fs from 'node:fs';

const read = (file) => fs.readFileSync(new URL(file, import.meta.url), 'utf8');
const workflow = read('../../.github/workflows/site.yml');
// The lines of check-ci.sh without its comments, so that a check that is
// commented out counts as missing.
const local = read('./check-ci.sh').split('\n').filter((line) => !/^\s*#/.test(line)).join('\n') + '\n';
const localText = read('./check-ci.sh');
const pkg = JSON.parse(read('../package.json'));

// Triggers: a push to next and workflow_dispatch, no pull request.
const on = workflow.split('\non:\n')[1].split('\n\n')[0];
assert.ok(!/pull_request/.test(on), 'site.yml has no pull_request trigger');
assert.match(on, /^ {2}push:\n {4}branches:\n {6}- next\n {2}workflow_dispatch:/m);
console.log('site.yml runs on a push to next and on a dispatch, not on pull requests: PASS');

// Jobs: build, deploy and verify-live only.
const jobs = [...workflow.split('\njobs:\n')[1].matchAll(/^ {2}([a-z][a-z0-9-]*):\n/gm)].map((m) => m[1]);
assert.deepEqual(jobs, ['build', 'deploy', 'verify-live']);
const job = (name) => workflow.split(`\n  ${name}:\n`)[1].split(/\n {2}[a-z][a-z0-9-]*:\n/)[0];
assert.match(job('deploy'), /\n {4}needs: build\n/);
assert.match(job('verify-live'), /\n {4}needs: \[build, deploy\]\n/);
for (const name of ['deploy', 'verify-live']) {
  assert.ok(job(name).includes("github.ref == 'refs/heads/next'"), `${name} runs only on next`);
}
assert.ok(job('build').includes('uses: actions/upload-pages-artifact@'), 'build uploads the Pages artifact');
assert.ok(job('verify-live').includes('node scripts/check-public-deployment.mjs --sha'));
assert.ok(job('verify-live').includes('node scripts/check-live.mjs --no-gh'));
assert.ok(job('verify-live').includes('node scripts/screenshots-live.mjs --out live-screenshots'));
assert.ok(job('verify-live').includes('npx playwright install --with-deps chromium webkit'), 'verify-live installs Chromium and WebKit');
assert.ok(job('verify-live').includes('GITHUB_TOKEN: ${{ github.token }}'), 'verify-live passes the job token to the public API calls');
for (const word of ['site-ok', 'maintenance-lines', 'ci-plan', 'ci-browser', 'ci-artifact', 'site-validation', 'measure_scope']) {
  assert.ok(!workflow.includes(word), `no browser lane is left in site.yml (${word})`);
}
console.log('site.yml builds, deploys and checks the published site, with no browser lane: PASS');

// Every script that the build job runs is in check:ci, directly or through
// npm run check or npm test.
const covered = local + pkg.scripts.check + pkg.scripts.test + pkg.scripts.build;
const inBuild = new Set([...job('build').matchAll(/(?:node|python3|sh) (?:site\/)?(scripts\/[\w.-]+)/g)].map((m) => m[1]));
// The fresh-clone and offline builds stay in CI (the head of check-ci.sh).
for (const script of ['scripts/check-fresh-clone.sh', 'scripts/check-offline-build.sh']) {
  assert.ok(inBuild.delete(script), `site.yml runs ${script}`);
  assert.ok(localText.includes(script.replace('scripts/check-offline-build.sh', 'npm run check:offline')), `check-ci.sh names ${script}`);
}
assert.ok(inBuild.size >= 15, `the build job runs its checks (${[...inBuild].join(', ')})`);
for (const script of inBuild) {
  assert.ok(covered.includes(script.replace('scripts/', '')), `npm run check:ci runs ${script}, which the build job of site.yml runs`);
}
for (const step of ['npm run build', 'scripts/build-v2.mjs --tree', 'npm test', 'npm run check\n', 'check_links.py', 'check-v2.mjs --no-browser']) {
  assert.ok(local.includes(step), `check-ci.sh runs ${step.trim()}`);
}
console.log(`check:ci runs every check of the build job of site.yml (${inBuild.size} scripts): PASS`);

// The browser checks that the lanes of site.yml ran until 2026-11-02.
const browser = local.split('browser_checks() {')[1].split('\n}')[0];
for (const command of [
  'check-styles.mjs --ja-face noto',
  'check-japanese-lines.mjs --ja-face noto\n',
  'check-japanese-lines.mjs --ja-face noto --pages /v2/ja/',
  'check-copy-idle.mjs', 'check-home-interaction.mjs', 'check-code-layout.mjs',
  'check-focus.mjs', 'check-language-links.mjs', 'check-lighthouse.mjs',
  'check-project-badges.mjs --browser', 'check-search-identifiers.mjs', 'check-v2.mjs\n',
  'test-read-only-browser.mjs', 'screenshots.mjs --out build-screenshots',
  'screenshots-live.mjs --local --out build-screenshots/predeploy-smoke',
]) assert.ok(browser.includes(command), `check:browser runs ${command.trim()}`);
assert.ok(!/--engine|--pages \/[^v]|SITE_CI_PAGES|SITE_CI_VERSION/.test(browser), 'check:browser measures every page in both engines');
assert.equal(pkg.scripts['check:ci'], 'sh scripts/check-ci.sh');
assert.equal(pkg.scripts['check:browser'], 'sh scripts/check-ci.sh --browser');
console.log('check:browser runs every browser check on every page, in both engines: PASS');
