// Run independent browser lanes against one build, with no cross-run cache.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { scopedPages } from './lib/ci-pages.mjs';
export const LANES = ['styles-chromium', 'styles-webkit', 'interaction', 'japanese', 'accessibility', 'screenshots'];
export function commandsFor(plan, lane) {
  if (!LANES.includes(lane)) throw new Error(`unknown lane ${lane}`);
  if (!['full', 'targeted', 'none'].includes(plan.mode)) throw new Error('invalid mode');
  if (plan.mode === 'none') return [];
  const pages = plan.mode === 'targeted' ? plan.pages : null;
  if (pages && !pages.length) throw new Error('empty targeted scope');
  if (lane.startsWith('styles-')) return [['check-styles.mjs', '--engine', lane.slice(7)]];
  if (lane === 'interaction') return [
    ...(!pages || pages.some(p => p === '/' || p === '/ja/') ? [['check-copy-idle.mjs'], ['check-home-interaction.mjs']] : []),
    ['check-code-layout.mjs'],
  ];
  if (lane === 'japanese') {
    const ja = pages?.filter(p => p.startsWith('/ja/'));
    return ja ? (ja.length ? [['check-japanese-lines.mjs', '--pages', ja.join(',')]] : []) : [['check-japanese-lines.mjs']];
  }
  if (lane === 'accessibility') return [
    ['check-focus.mjs'], ['check-language-links.mjs'],
    ['check-lighthouse.mjs', ...(pages ? pages.flatMap(p => ['--page', p]) : [])],
  ];
  return [[pages ? 'ci-screenshots.mjs' : 'screenshots.mjs', '--out', 'build-screenshots']];
}
export function siteGate(results) {
  return results.build === 'success' && results.browser === 'success' && results.maintenance === 'success';
}
async function main() {
  if (process.argv[2] === '--gate') {
    const results = {build:process.env.BUILD_RESULT, browser:process.env.BROWSER_RESULT, maintenance:process.env.MAINTENANCE_RESULT};
    console.log(JSON.stringify(results));
    if (!siteGate(results)) process.exitCode = 1;
    return;
  }
  const plan = JSON.parse(fs.readFileSync('generated/ci-scope.json', 'utf8'));
  const lane = process.argv[2];
  if (plan.mode === 'targeted') scopedPages('dist', JSON.stringify(plan.pages));
  const commands = commandsFor(plan, lane);
  const timings = [];
  for (const [script, ...args] of commands) {
    const started = Date.now();
    const env = {...process.env};
    delete env.SITE_CI_PAGES;
    delete env.SITE_CI_VERSION;
    if (script === 'check-code-layout.mjs') env.SITE_CI_VERSION = '3';
    if (plan.mode === 'targeted') env.SITE_CI_PAGES = JSON.stringify(plan.pages);
    const result = spawnSync(process.execPath, ['scripts/' + script, ...args], {stdio:'inherit',env});
    timings.push({script,seconds:(Date.now()-started)/1000,status:result.status});
    if (result.error || result.status !== 0) {
      console.error(JSON.stringify({lane, timings}));
      process.exitCode = 1;
      return;
    }
  }
  if (process.env.MEASURE_SCOPE === 'true') {
    // An explicit manual or CI-policy-change diagnostic. The full lane already passed;
    // this cannot replace it or turn its failure into a success.
    if (plan.mode !== 'full' || lane !== 'styles-chromium') throw new Error('measurement requires the full Chromium style lane');
    const pages = ['/guides/install/', '/ja/guides/install/'];
    scopedPages('dist', JSON.stringify(pages));
    const started = Date.now();
    const result = spawnSync(process.execPath, ['scripts/check-styles.mjs','--engine','chromium'], {
      stdio:'inherit', env:{...process.env,SITE_CI_PAGES:JSON.stringify(pages)},
    });
    timings.push({script:'targeted-style-comparison',pages,seconds:(Date.now()-started)/1000,status:result.status});
    if(result.error || result.status !== 0) {console.error(JSON.stringify({lane,timings}));process.exitCode=1;return;}
  }
  console.log(JSON.stringify({lane, mode:plan.mode, pages:plan.pages, timings}));
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, '\n```json\n'+JSON.stringify({lane,mode:plan.mode,pages:plan.pages,timings},null,2)+'\n```\n');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
