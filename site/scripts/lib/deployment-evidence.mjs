// Public, read-only evidence. The deployment permissions are deliberately not
// part of this verifier. When GITHUB_TOKEN is set (the workflow passes the
// job's own token, which only reads this public repository), the requests
// carry it, so they count against the token's rate limit and not against the
// anonymous limit of the runner's IP address (60 requests per hour). Without
// it the requests stay anonymous. On 403 or 429 the request is repeated:
// after Retry-After or X-RateLimit-Reset when the response has them, else
// after 10 s, doubling, with at most 5 repeats.
const MAX_RETRIES = 5;
const FIRST_WAIT_MS = 10000;
const MAX_HEADER_WAIT_MS = 120000;

function waitMs(response, attempt, now) {
  const header = (name) => response.headers?.get?.(name) ?? null;
  const retryAfter = Number(header('retry-after'));
  if (header('retry-after') !== null && Number.isFinite(retryAfter) && retryAfter >= 0) return Math.min(retryAfter * 1000, MAX_HEADER_WAIT_MS);
  const reset = Number(header('x-ratelimit-reset'));
  if (header('x-ratelimit-reset') !== null && Number.isFinite(reset)) return Math.min(Math.max(reset * 1000 - now(), 0) + 1000, MAX_HEADER_WAIT_MS);
  return FIRST_WAIT_MS * 2 ** attempt;
}

export async function publicJson(url, fetcher = fetch, { env = process.env, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), log = console.log, now = Date.now } = {}) {
  const headers = { accept: 'application/vnd.github+json', 'cache-control': 'no-cache' };
  if (env.GITHUB_TOKEN) headers.authorization = `Bearer ${env.GITHUB_TOKEN}`;
  for (let attempt = 0; ; attempt++) {
    const response = await fetcher(url, { headers, signal: AbortSignal.timeout(15000) });
    if (response.ok) return response.json();
    if ((response.status === 403 || response.status === 429) && attempt < MAX_RETRIES) {
      const ms = waitMs(response, attempt, now);
      log(`${url}: HTTP ${response.status}; waiting ${Math.ceil(ms / 1000)} s before repeat ${attempt + 1} of ${MAX_RETRIES} (${env.GITHUB_TOKEN ? 'authenticated' : 'anonymous'})`);
      await sleep(ms);
      continue;
    }
    throw new Error(`${url}: HTTP ${response.status}; deployment evidence is unavailable`);
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
