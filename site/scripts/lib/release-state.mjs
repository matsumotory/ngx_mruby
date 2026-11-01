// Stable release tags and release-note filenames are the existing version sources.
// Read only tags reachable from this documentation tree; do not call the network.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
export function summarizeReleases(reachableTags, filenames, major) {
  const pattern = new RegExp(`^v${major}\\.\\d+\\.\\d+$`);
  const tags = reachableTags.filter(t => pattern.test(t));
  if (!tags.length) throw new Error(`No reachable stable v${major} release tag; fetch full history and tags before building`);
  const numbers = v => v.replace(/^v/, '').split('.').map(Number);
  const after = (a,b) => { const x=numbers(a), y=numbers(b); for(let i=0;i<3;i++) if(x[i]!==y[i]) return x[i]>y[i]; return false; };
  tags.sort((a,b) => after(a,b) ? -1 : after(b,a) ? 1 : 0);
  const latest = tags[0];
  const unreleased = filenames.filter(f => f.endsWith('.md')).map(f => f.slice(0,-3)).filter(v => pattern.test(v) && after(v, latest)).sort((a,b) => after(a,b) ? 1 : -1);
  return { latest_release_tag: latest, unreleased_versions: unreleased };
}

export function releaseState(repo, major) {
  const git = (...args) => execFileSync('git', ['-C', repo, ...args], {encoding:'utf8'}).trim();
  const state = summarizeReleases(git('tag', '--merged', 'HEAD', '--list', `v${major}.*`).split('\n'), fs.readdirSync(path.join(repo, 'docs/releases')), major);
  return { ...state, latest_release_revision: git('rev-parse', `${state.latest_release_tag}^{commit}`) };
}

// The newest stable release of the project (vX.Y.Z of any major), for the
// release badge of the home pages (docs/proposals/site.md, 4.10). It reads
// every tag of the repository, not only those merged into HEAD, because a
// 2.x release is tagged on master before master is merged into next.
export function newestStableTag(tags) {
  const stable = tags.filter(t => /^v\d+\.\d+\.\d+$/.test(t));
  if (!stable.length) throw new Error('No stable release tag; fetch the tags before building');
  const numbers = v => v.replace(/^v/, '').split('.').map(Number);
  return stable.reduce((best, t) => { const x = numbers(t), y = numbers(best); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i] ? t : best; return best; });
}
export function latestReleaseTag(repo) {
  return newestStableTag(execFileSync('git', ['-C', repo, 'tag', '--list', 'v*'], { encoding: 'utf8' }).trim().split('\n'));
}
