// Reads the test files that the specimen pages show (docs/proposals/site.md,
// 4.12), so that no line of them is copied by hand. The specimens show the
// design; the sample mechanism of 3.5 comes with step 3.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

// The build runs in site/ (npm run build); Astro bundles this module, so
// import.meta.url does not point to src/specimens/ when it runs.
export const REPO = path.resolve(process.cwd(), '..');
if (!fs.existsSync(path.join(REPO, 'test/t/cases'))) throw new Error(`${REPO} is not the repository root`);

export function read(file) {
  return fs.readFileSync(path.join(REPO, file), 'utf8');
}

/** The short commit and the date of the last commit to the files. */
export function lastChange(...files) {
  const out = execFileSync('git', ['log', '-1', '--format=%h %cs', '--', ...files], { cwd: REPO, encoding: 'utf8' }).trim();
  const [commit, date] = out.split(' ');
  if (!commit) throw new Error(`no commit for ${files.join(', ')}`);
  return { commit, date };
}

/** The block that starts with the line matching start, to its closing brace. */
export function block(text, start) {
  const lines = text.split('\n');
  const i = lines.findIndex((l) => start.test(l));
  if (i < 0) throw new Error(`no line matches ${start}`);
  const indent = lines[i].match(/^\s*/)[0];
  const end = lines.findIndex((l, j) => j > i && l === `${indent}}`);
  if (end < 0) throw new Error(`no end of the block at ${start}`);
  return lines.slice(i, end + 1).map((l) => l.slice(indent.length)).join('\n');
}

/** The first line matching re, without its indentation. */
export function line(text, re) {
  const l = text.split('\n').find((x) => re.test(x));
  if (!l) throw new Error(`no line matches ${re}`);
  return l.trim();
}

/** The value of a Ruby constant of single-quoted string. */
export function rubyConstant(text, name) {
  const m = text.match(new RegExp(`^${name} = '([^']*)'`, 'm'));
  if (!m) throw new Error(`no constant ${name}`);
  return m[1];
}

/** The nginx versions of the test matrix of .github/workflows/test.yml. */
export function testedNginxVersions() {
  const yml = read('.github/workflows/test.yml');
  const m = yml.match(/NGINX_VERSION:\n((?:\s+- [0-9.]+\n)+)/);
  if (!m) throw new Error('no NGINX_VERSION matrix in test.yml');
  return [...m[1].matchAll(/- ([0-9.]+)/g)].map((x) => x[1]);
}

/** The first and last line (1-based) of the C function whose definition matches re. */
export function functionLines(text, re) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => re.test(l));
  if (start < 0) throw new Error(`no function matches ${re}`);
  const end = lines.findIndex((l, j) => j > start && l === '}');
  return [start + 1, end + 1];
}
