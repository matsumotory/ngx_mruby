// The checks of step 7 (docs/proposals/site.md, section 6) on the live
// site, after the switch of ngx.mruby.org to the deployment from next.
// The post-deploy CI job runs it against that run's artifact, after the
// equivalent public GitHub policy/SHA check; a session can also run it by
// hand ("The site" in AGENTS.md).
//
//   node scripts/check-live.mjs [--dist DIR] [--url URL] [--no-gh] [--no-lighthouse]
//
// - https://ngx.mruby.org/ answers 200, and its body is the index.html of
//   the built site in --dist (default site/dist). Build the commit that the
//   deployment came from first (the last line of the output prints the
//   commit of the latest deployment), since the last-updated dates and the
//   example's commit differ between commits;
// - http://ngx.mruby.org/ answers with a redirect (301 or 308) to
//   https://ngx.mruby.org/ (Enforce HTTPS);
// - each file of VERBATIM_FILES (the Google verification file) answers 200
//   with its bytes and SHA-256 unchanged;
// - with gh (left out with --no-gh): the github-pages environment has custom
//   branch policies, which list only the branch next, and the latest
//   deployment to it came from next;
// - Lighthouse (left out with --no-lighthouse) on the live home page, in
//   Playwright's Chromium: the scores of its four categories are printed,
//   and a failed accessibility audit is a problem, as in
//   check-lighthouse.mjs.
//
// Exit status: 0 when every check passes, 1 otherwise, 2 on a usage error.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { distDir, finish, VERBATIM_FILES } from './lib/site.mjs';

const REPO = 'matsumotory/ngx_mruby';
const BRANCH = 'next';

function args() {
  const a = process.argv.slice(2);
  const out = { dist: distDir, url: 'https://ngx.mruby.org', gh: true, lighthouse: true };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist' && i + 1 < a.length) out.dist = path.resolve(a[++i]);
    else if (a[i] === '--url' && i + 1 < a.length) out.url = a[++i].replace(/\/$/, '');
    else if (a[i] === '--no-gh') out.gh = false;
    else if (a[i] === '--no-lighthouse') out.lighthouse = false;
    else {
      console.error(`check-live.mjs: unknown argument ${a[i]}`);
      console.error('usage: node scripts/check-live.mjs [--dist DIR] [--url URL] [--no-gh] [--no-lighthouse]');
      process.exit(2);
    }
  }
  return out;
}

const opt = args();
const problems = [];
const notes = [];
const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');
const get = async (url, redirect = 'follow') => {
  const response = await fetch(url, { redirect, headers: { 'cache-control': 'no-cache' } });
  return { response, body: Buffer.from(await response.arrayBuffer()) };
};

// The home page and the deployed index.html.
{
  const { response, body } = await get(`${opt.url}/`);
  if (response.status !== 200) problems.push(`${opt.url}/: status ${response.status}, not 200`);
  const local = path.join(opt.dist, 'index.html');
  if (!fs.existsSync(local)) problems.push(`${local} is missing: build the deployed commit first, or pass --dist`);
  else if (!body.equals(fs.readFileSync(local))) {
    problems.push(`${opt.url}/: the body (${body.length} bytes, SHA-256 ${sha256(body)}) differs from ${local} (${fs.statSync(local).size} bytes): is --dist the build of the deployed commit?`);
  }
  notes.push(`${opt.url}/ ${response.status}, ${body.length} bytes`);
}

// http:// redirects to https://.
{
  const plain = opt.url.replace(/^https:/, 'http:');
  const { response } = await get(`${plain}/`, 'manual');
  const location = response.headers.get('location');
  if (![301, 308].includes(response.status) || location !== `${opt.url}/`) {
    problems.push(`${plain}/: status ${response.status} with Location ${location}, not a 301 or 308 to ${opt.url}/`);
  }
  notes.push(`${plain}/ ${response.status} to ${location}`);
}

// The files kept from the old site.
for (const { file, bytes, sha256: want } of VERBATIM_FILES) {
  const { response, body } = await get(`${opt.url}/${file}`);
  if (response.status !== 200) problems.push(`/${file}: status ${response.status}, not 200`);
  if (body.length !== bytes || sha256(body) !== want) {
    problems.push(`/${file}: ${body.length} bytes with SHA-256 ${sha256(body)}, not the ${bytes} bytes of the gh-pages copy (${want})`);
  }
  notes.push(`/${file} ${response.status}, ${body.length} bytes`);
}

// The environment and the deployments, read back with gh api.
if (opt.gh) {
  const api = (route) => JSON.parse(execFileSync('gh', ['api', route], { encoding: 'utf8' }));
  const environment = api(`repos/${REPO}/environments/github-pages`);
  const policy = environment.deployment_branch_policy;
  if (!policy || policy.custom_branch_policies !== true || policy.protected_branches !== false) {
    problems.push(`environment github-pages: deployment_branch_policy is ${JSON.stringify(policy)}, not custom branch policies`);
  } else {
    const { branch_policies: list } = api(`repos/${REPO}/environments/github-pages/deployment-branch-policies`);
    const names = list.map((p) => `${p.type ?? 'branch'}:${p.name}`);
    if (names.length !== 1 || names[0] !== `branch:${BRANCH}`) {
      problems.push(`environment github-pages: the deployment branch policies are ${JSON.stringify(names)}, not only branch:${BRANCH}`);
    }
    notes.push(`environment github-pages: ${names.join(', ')}`);
  }
  const deployments = api(`repos/${REPO}/deployments?environment=github-pages&per_page=1`);
  if (deployments.length === 0) problems.push('environment github-pages: no deployment');
  else {
    const [latest] = deployments;
    if (latest.ref !== BRANCH) problems.push(`the latest deployment (${latest.id}, ${latest.created_at}) came from ${latest.ref}, not ${BRANCH}`);
    notes.push(`latest deployment ${latest.id} from ${latest.ref} at ${latest.sha} (${latest.created_at})`);
  }
}

// Lighthouse on the live home page.
if (opt.lighthouse) {
  const { default: lighthouse } = await import('lighthouse');
  const { chromium } = await import('playwright');
  const port = 9800 + Math.floor(Math.random() * 100);
  const browser = await chromium.launch({ args: [`--remote-debugging-port=${port}`] });
  try {
    const { lhr } = await lighthouse(`${opt.url}/`, { port, output: 'json', logLevel: 'error' });
    if (lhr.runtimeError) problems.push(`Lighthouse could not run: ${lhr.runtimeError.message}`);
    else {
      const scores = Object.values(lhr.categories).map((c) => `${c.title} ${Math.round(c.score * 100)}`);
      notes.push(`Lighthouse on ${opt.url}/: ${scores.join(', ')}`);
      for (const ref of lhr.categories.accessibility.auditRefs) {
        const audit = lhr.audits[ref.id];
        if (audit.score !== null && audit.score < 1) problems.push(`Lighthouse accessibility: ${audit.id} (${audit.title}), score ${audit.score}`);
      }
    }
  } finally {
    await browser.close();
  }
}

for (const note of notes) console.log(note);
finish('check-live', problems, `${opt.url}: ${notes.length} results above`);
