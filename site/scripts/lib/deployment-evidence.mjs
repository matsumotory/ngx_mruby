// Public, read-only evidence. Authentication and deployment permissions are
// deliberately not part of this verifier.
export async function publicJson(url, fetcher = fetch) {
  const response = await fetcher(url, { headers: { accept: 'application/vnd.github+json', 'cache-control': 'no-cache' }, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}; deployment evidence is unavailable`);
  return response.json();
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
