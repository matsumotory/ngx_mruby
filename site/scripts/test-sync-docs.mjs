// Test of the generator scripts/sync-docs.mjs on fixtures: the href and src
// attributes of raw HTML are rewritten in place at the top level, inside a
// blockquote, inside a list item and inside a list item of a blockquote,
// where the parser's node.value lacks the "> " and the indentation of the
// lines after the first; and an attribute value that the source and the
// rendered HTML read differently stops the build.
//
//   node scripts/test-sync-docs.mjs
//
// For each fixture it makes a git repository in a new temporary directory,
// with a copy of site/scripts, site/node_modules linked to this one, and
// the fixture's files under docs/ committed, runs the copy of sync-docs.mjs
// there, and compares the page it wrote, or its error, with the expected
// one. It needs `npm ci` first, and no network.
//
// Exit status: 0 when every fixture gives the expected result, 1 otherwise.
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { siteDir } from './lib/site.mjs';

const RAW = 'https://github.com/matsumotory/ngx_mruby/raw/next';

const PAGES = {
  'docs/install/README.md': '# Install\n',
  'docs/directives/README.md': '# Directives\n\n## Anchor\n',
  'misc/logo.png': 'not an image, only a tracked file\n',
};

const fixtures = [
  {
    name: 'raw HTML links at the top level, in a blockquote and in list items',
    source: `# Raw HTML links

<div>
<a href="install/README.md">at the top level</a>
</div>

> <div>
> <a href="install/README.md">in a blockquote</a>
> <img src="../misc/logo.png" alt="">
> </div>

- An item

  <div>
  <a href='directives/README.md#anchor'>in a list item</a>
  </div>

> - A list item in a blockquote
>
>   <p>
>   <a href="directives/README.md">nested</a> and <a href="https://example.com/">absolute</a>
>   </p>

> One line,
> then <a href="install/README.md">an inline link</a> and [a Markdown link](directives/README.md).
`,
    page: `<div>
<a href="/install/">at the top level</a>
</div>

> <div>
> <a href="/install/">in a blockquote</a>
> <img src="${RAW}/misc/logo.png" alt="">
> </div>

- An item

  <div>
  <a href='/directives/#anchor'>in a list item</a>
  </div>

> - A list item in a blockquote
>
>   <p>
>   <a href="/directives/">nested</a> and <a href="https://example.com/">absolute</a>
>   </p>

> One line,
> then <a href="/install/">an inline link</a> and [a Markdown link](/directives/).
`,
  },
  {
    name: 'an attribute value over two lines of a blockquote',
    source: `# A value over two lines

> <div>
> <a href="install/
> README.md">in a blockquote</a>
> </div>
`,
    error: 'docs/README.md:3: the href and src attributes of this HTML differ between its source and the HTML that the page renders',
  },
];

function run(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx_mruby-sync-docs-'));
  try {
    fs.cpSync(path.join(siteDir, 'scripts'), path.join(dir, 'site', 'scripts'), { recursive: true });
    fs.symlinkSync(path.join(siteDir, 'node_modules'), path.join(dir, 'site', 'node_modules'), 'dir');
    for (const [file, text] of Object.entries({ ...PAGES, 'docs/README.md': fixture.source })) {
      fs.mkdirSync(path.join(dir, path.dirname(file)), { recursive: true });
      fs.writeFileSync(path.join(dir, file), text);
    }
    const git = (...args) =>
      execFileSync('git', ['-C', dir, '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { stdio: 'pipe' });
    git('init', '--quiet');
    git('add', 'docs', 'misc');
    git('commit', '--quiet', '-m', 'fixture');
    const result = spawnSync(process.execPath, [path.join(dir, 'site', 'scripts', 'sync-docs.mjs')], { cwd: dir, encoding: 'utf8' });
    if (fixture.error) {
      if (result.status === 1 && result.stderr.includes(fixture.error)) return [];
      return [`expected exit 1 with "${fixture.error}", got exit ${result.status}: ${result.stderr.trim() || result.stdout.trim()}`];
    }
    if (result.status !== 0) return [`sync-docs.mjs exited ${result.status}: ${result.stderr.trim()}`];
    const written = fs.readFileSync(path.join(dir, 'site', 'src', 'content', 'docs', 'index.md'), 'utf8');
    const body = written.replace(/^---\n[\s\S]*?\n---\n\n/, '');
    if (body === fixture.page) return [];
    const expected = fixture.page.split('\n');
    const actual = body.split('\n');
    const line = expected.findIndex((text, i) => text !== actual[i]);
    return [`the page differs from the expected one at line ${line + 1} of its body:\n  expected: ${expected[line]}\n  actual:   ${actual[line]}`];
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

let failed = 0;
for (const fixture of fixtures) {
  const problems = run(fixture);
  if (problems.length > 0) {
    failed++;
    console.log(`not ok: ${fixture.name}`);
    for (const problem of problems) console.log(`  ${problem}`);
  } else {
    console.log(`ok: ${fixture.name}`);
  }
}
if (failed > 0) {
  console.log(`test-sync-docs: ${failed} of ${fixtures.length} fixture(s) failed`);
  process.exit(1);
}
console.log(`test-sync-docs: ok; ${fixtures.length} fixtures`);
