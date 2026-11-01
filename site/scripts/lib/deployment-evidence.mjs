// Public, read-only evidence. The deployment permissions are deliberately not
// part of this verifier. When GITHUB_TOKEN is set (the workflow passes the
// job's own token, which only reads this public repository), the requests
// carry it, so they count against the token's rate limit and not against the
// anonymous limit of the runner's IP address (60 requests per hour).
//
// A response is repeated only when it is a rate limit: HTTP 429, or HTTP 403
// with a Retry-After header or with X-RateLimit-Remaining at 0. GitHub sends
// X-RateLimit-Reset on every response, so a 403 for a missing permission is
// not repeated. The wait is Retry-After, else the time to X-RateLimit-Reset,
// else 60 s (the secondary limit asks for at least a minute), doubling, and
// at most 5 repeats per call. The waits of one process add up to at most
// 240 s, so that the job's 10 minutes (with the install steps before it) are
// never used up by waiting: a wait that does not fit fails with the reason.
const MAX_RETRIES = 5;
const FIRST_WAIT_MS = 60000;
const TOTAL_WAIT_MS = 240000;
const budget = { left: TOTAL_WAIT_MS };

function header(response, name) {
  const value = response.headers?.get?.(name);
  return value === null || value === undefined || String(value).trim() === '' ? null : String(value).trim();
}

function isRateLimit(response) {
  if (response.status === 429) return true;
  return response.status === 403 && (header(response, 'retry-after') !== null || header(response, 'x-ratelimit-remaining') === '0');
}

function waitMs(response, attempt, now) {
  const retryAfter = Number(header(response, 'retry-after'));
  if (header(response, 'retry-after') !== null && Number.isFinite(retryAfter) && retryAfter >= 0) return retryAfter * 1000;
  const reset = Number(header(response, 'x-ratelimit-reset'));
  if (header(response, 'x-ratelimit-reset') !== null && Number.isFinite(reset)) return Math.max(reset * 1000 - now(), 0) + 1000;
  return FIRST_WAIT_MS * 2 ** attempt;
}

async function reason(response) {
  try { return `: ${String((await response.json())?.message ?? '').slice(0, 200)}`; } catch { return ''; }
}

export async function publicJson(url, fetcher = fetch, { env = process.env, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), log = console.log, now = Date.now, waitBudget = budget } = {}) {
  const headers = { accept: 'application/vnd.github+json', 'cache-control': 'no-cache' };
  if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  for (let attempt = 0; ; attempt++) {
    const response = await fetcher(url, { headers, signal: AbortSignal.timeout(15000) });
    if (response.ok) return response.json();
    if (isRateLimit(response) && attempt < MAX_RETRIES) {
      const ms = waitMs(response, attempt, now);
      if (ms > waitBudget.left) throw new Error(`${url}: HTTP ${response.status}; rate limited, and the wait of ${Math.ceil(ms / 1000)} s does not fit in the ${Math.floor(waitBudget.left / 1000)} s left; deployment evidence is unavailable`);
      waitBudget.left -= ms;
      log(`${url}: HTTP ${response.status}; waiting ${Math.ceil(ms / 1000)} s before repeat ${attempt + 1} of ${MAX_RETRIES} (${env.GITHUB_TOKEN ? 'authenticated' : 'anonymous'})`);
      await sleep(ms);
      continue;
    }
    throw new Error(`${url}: HTTP ${response.status}${await reason(response)}; deployment evidence is unavailable`);
  }
}

export function deploymentProblems({ expectedSha, artifact, environment, policies, deployment, statuses }) {
  const problems = [];
  if (!/^[0-9a-f]{40}$/.test(expectedSha ?? '')) problems.push('expected SHA must be a full commit SHA');
  if (artifact?.source_revision !== expectedSha || artifact?.working_tree_clean !== true) problems.push('artifact source revision/clean state does not match the expected deployment');
  const policy = environment?.deployment_branch_policy;
  if (environment?.name !== 'github-pages' || policy?.custom_branch_policies !== true || policy?.protected_branches !== false) problems.push('github-pages must use custom deployment branch policies');
  const branches = policies?.branch_policies;
  if (policies?.total_count !== 1 || branches?.length !== 1 || branches[0].name !== 'next' || (branches[0].type ?? 'branch') !== 'branch') problems.push('github-pages must permit only branch:next');
  if (deployment?.environment !== 'github-pages' || deployment?.ref !== 'next' || deployment?.sha !== expectedSha) problems.push('latest github-pages deployment does not match next at the expected artifact SHA');
  if (statuses?.[0]?.state !== 'success') problems.push('latest deployment status is not success');
  return problems;
}
