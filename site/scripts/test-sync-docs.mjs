// Test of the generator scripts/sync-docs.mjs on fixtures: the href and src
// attributes of raw HTML are rewritten in place at the top level, inside a
// blockquote, inside a list item and inside a list item of a blockquote,
// where the parser's node.value lacks the "> " and the indentation of the
// lines after the first; an attribute value that the source and the
// rendered HTML read differently stops the build. The samples and diagrams
// of 3.5 (step 3): a sample block becomes code blocks and a caption, and
// the build stops on a sample whose file is missing or whose case does not
// name what the page shows; a diagram block becomes a figure, and the build
// stops on a block whose keys differ from those of its drawing (the
// English and the Japanese block both have the drawing's keys), and on a
// Japanese block whose source lines differ from those of the English block.
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
import { markCells } from './mark-num-cells.mjs';

const RAW = 'https://github.com/matsumotory/ngx_mruby/raw/next';

const PAGES = {
  'docs/install/README.md': '# Install\n',
  'docs/directives/README.md': '# Directives\n\n## Anchor\n',
  'misc/logo.png': 'not an image, only a tracked file\n',
  // The committed home pages beside the generated ones (5.2)
  'site/src/content/docs/index.mdx': '---\ntitle: Home\n---\n',
  'site/src/content/docs/ja/index.mdx': '---\ntitle: ホーム\n---\n',
  // A sample: a case that names the request, the response and the port
  'test/t/cases/demo.rb': "# Config: test/conf/conf.d/99-demo.conf (port 18999)\nrequest = html_path('demo.request')\nresponse = html_path('demo.response')\nport = 18999\n",
  'test/conf/conf.d/99-demo.conf': '# Port 18999.\nserver {\n    listen 18999;\n}\n',
  'test/html/demo.rb': 'Nginx.rputs "demo"\n',
  'test/html/demo.request': 'GET / HTTP/1.1\n',
  'test/html/demo.response': 'HTTP/1.1 200 OK\n\ndemo\n',
  // A drawing with the keys a and b
  'site/src/diagrams/demo.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" data-labels="a b"><path class="d-line" d="M0 0 H10" /></svg>\n',
};

const SAMPLE = (script = 'test/html/demo.rb', response = 'test/html/demo.response') =>
  `\`\`\`sample\ncase: test/t/cases/demo.rb\nconf: test/conf/conf.d/99-demo.conf\nscript: ${script}\nrequest: test/html/demo.request\nresponse: ${response}\n\`\`\`\n`;
const DIAGRAM = (labels) =>
  `\`\`\`diagram\ndemo\ncaption: A demo diagram.\nsource: docs/install/README.md 1\nat: COMMIT DATE\n${labels}\`\`\`\n`;

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
<a href="/guides/install/">at the top level</a>
</div>

> <div>
> <a href="/guides/install/">in a blockquote</a>
> <img src="${RAW}/misc/logo.png" alt="">
> </div>

- An item

  <div>
  <a href='/reference/directives/#anchor'>in a list item</a>
  </div>

> - A list item in a blockquote
>
>   <p>
>   <a href="/reference/directives/">nested</a> and <a href="https://example.com/">absolute</a>
>   </p>

> One line,
> then <a href="/guides/install/">an inline link</a> and [a Markdown link](/reference/directives/).
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
  {
    name: 'a sample block becomes the code blocks of its files and a caption',
    source: `# A sample\n\n${SAMPLE()}`,
    contains: ['```nginx title="test/conf/conf.d/99-demo.conf"\nserver {\n    listen 18999;\n}\n```', '```ruby title="test/html/demo.rb"\nNginx.rputs "demo"\n```', 'the case <code>test/t/cases/demo.rb</code> sends this request'],
  },
  {
    name: 'a sample whose script is missing stops the build',
    source: `# A sample\n\n${SAMPLE('test/html/missing.rb')}`,
    error: 'the script of the sample, test/html/missing.rb, is missing',
  },
  {
    name: 'a sample whose case does not name the response that the page shows stops the build',
    files: { 'test/html/other.response': 'HTTP/1.1 404 Not Found\n' },
    source: `# A sample\n\n${SAMPLE('test/html/demo.rb', 'test/html/other.response')}`,
    error: 'the case test/t/cases/demo.rb does not name other.response',
  },
  {
    name: 'a sample whose case names the response only in a comment stops the build',
    files: { 'test/t/cases/demo.rb': "# Config: test/conf/conf.d/99-demo.conf (port 18999)\n# compares demo.response\nrequest = html_path('demo.request')\nport = 18999\n" },
    source: `# A sample\n\n${SAMPLE()}`,
    error: 'the case test/t/cases/demo.rb does not name demo.response in its code',
  },
  {
    name: 'a diagram block becomes a figure with its drawing and HTML labels',
    source: `# A diagram\n\n${DIAGRAM('a: First `label`\nb: Second\n')}`,
    contains: ['<figure class="diagram diagram-demo not-content"><div class="diagram-grid" role="img" aria-label="A demo diagram.">', 'aria-hidden="true"', '<div class="diagram-label" data-key="a">First <code>label</code></div>'],
  },
  {
    name: 'a diagram block whose keys differ from those of its drawing stops the build',
    source: `# A diagram\n\n${DIAGRAM('a: First\nc: Third\n')}`,
    error: 'the keys of the diagram block demo differ from those of the drawing site/src/diagrams/demo.svg: it lacks b; it has c',
  },
  {
    name: 'a diagram block of a Japanese page whose source lines differ from those of the English page stops the build',
    source: `# A diagram\n\n${DIAGRAM('a: First\nb: Second\n')}`,
    files: { 'docs/ja/README.md': `# 図\n\n${DIAGRAM('a: 一つ目\nb: 二つ目\n').replace('README.md 1', 'README.md 1-2')}` },
    error: 'the source, nginx and at lines of the diagram block demo differ from those of the English page',
  },
];

fixtures.push({
  name: 'the routes of SOURCE_ROUTES: a page moved on the site, and the start page from examples/start/',
  source: '# Routes\n\n[Install](install/README.md), [start](../examples/start/README.md) and [Japanese](ja/install/README.md#anchor).\n',
  files: {
    'examples/start/README.md': '# Get started\n\n[Install](../../docs/install/README.md) and [the configuration](nginx.conf).\n',
    'examples/start/nginx.conf': 'events {}\n',
    'docs/ja/install/README.md': '# インストール\n\n## Anchor\n',
  },
  contains: ['[Install](/guides/install/)', '[start](/start/)', '[Japanese](/ja/guides/install/#anchor)'],
  others: {
    'start/index.md': ['title: "Get started"', 'slug: "start"', '[Install](/guides/install/)', '(https://github.com/matsumotory/ngx_mruby/blob/next/examples/start/nginx.conf)'],
    'guides/install.md': ['slug: "guides/install"', 'sidebar:\n  order: 1'],
    'ja/guides/install.md': ['slug: "ja/guides/install"', 'sidebar:\n  order: 1'],
  },
});

fixtures.push({
  name: 'long names get <wbr> in text, not in code, links written as URLs, or URLs of the text',
  source: '# Names\n\n## mruby_upstream_keepalive\n\nCall Nginx::Stream::Connection#remote_port and Nginx::Headers_in#delete(string) with `mruby_ssl_handshake_handler_code`.\n\nThe script is at http://127.0.0.1/YOUR_MRUBY_SCRIPT.rb and <https://example.com/a_b_c_d>.\n',
  contains: [
    '## mruby_<wbr>upstream_<wbr>keepalive',
    'Nginx::<wbr>Stream::<wbr>Connection<wbr>#remote_<wbr>port',
    'Nginx::<wbr>Headers_in<wbr>#delete<wbr>(string)',
    '`mruby_ssl_handshake_handler_code`',
    'http://127.0.0.1/YOUR_MRUBY_SCRIPT.rb and',
    '<https://example.com/a_b_c_d>',
  ],
});

function run(fixture) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx_mruby-sync-docs-'));
  try {
    fs.cpSync(path.join(siteDir, 'scripts'), path.join(dir, 'site', 'scripts'), { recursive: true });
    fs.symlinkSync(path.join(siteDir, 'node_modules'), path.join(dir, 'site', 'node_modules'), 'dir');
    const git = (...args) =>
      execFileSync('git', ['-C', dir, '-c', 'user.name=test', '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', ...args], { stdio: 'pipe', encoding: 'utf8' });
    git('init', '--quiet');
    const write = (files) => {
      for (const [file, text] of Object.entries(files)) {
        fs.mkdirSync(path.join(dir, path.dirname(file)), { recursive: true });
        fs.writeFileSync(path.join(dir, file), text);
      }
    };
    // A first commit, which the "at:" line of a diagram block names
    write(PAGES);
    git('add', 'docs', 'misc', 'test', 'site/src');
    git('commit', '--quiet', '-m', 'fixture');
    const at = git('log', '-1', '--format=%h %cs').trim();
    const withAt = (text) => text.replaceAll('COMMIT DATE', at);
    write(Object.fromEntries(Object.entries({ ...fixture.files, 'docs/README.md': fixture.source }).map(([f, t]) => [f, withAt(t)])));
    git('add', 'docs', 'misc', 'test', 'site/src', ...(fs.existsSync(path.join(dir, 'examples')) ? ['examples'] : []));
    git('commit', '--quiet', '-m', 'fixture page');
    const result = spawnSync(process.execPath, [path.join(dir, 'site', 'scripts', 'sync-docs.mjs')], { cwd: dir, encoding: 'utf8' });
    if (fixture.error) {
      if (result.status === 1 && result.stderr.includes(fixture.error)) return [];
      return [`expected exit 1 with "${fixture.error}", got exit ${result.status}: ${result.stderr.trim() || result.stdout.trim()}`];
    }
    if (result.status !== 0) return [`sync-docs.mjs exited ${result.status}: ${result.stderr.trim()}`];
    // docs/README.md is the page /docs/ (5.2: / is the home page)
    const written = fs.readFileSync(path.join(dir, 'site', 'src', 'content', 'docs', 'docs', 'index.md'), 'utf8');
    const body = written.replace(/^---\n[\s\S]*?\n---\n\n/, '');
    if (fixture.contains) {
      const missing = fixture.contains.filter((c) => !body.includes(c));
      // Other pages that the fixture writes, with the text each must hold
      for (const [file, texts] of Object.entries(fixture.others ?? {})) {
        const full = path.join(dir, 'site', 'src', 'content', 'docs', file);
        if (!fs.existsSync(full)) return [`the generator wrote no ${file}`];
        const text = fs.readFileSync(full, 'utf8');
        for (const t of texts) if (!text.includes(t)) missing.push(`${t} (in ${file})`);
      }
      return missing.map((m) => `the page lacks: ${m}\n  page: ${body.slice(0, 600)}`);
    }
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
// scripts/mark-num-cells.mjs on the cells of a table: numbers, versions,
// sizes and numbers in parentheses take the class num, words do not
{
  const html = '<table><tr><th>Name</th><th>1.31.6</th></tr><tr><td>mruby</td><td>4.0.0, 3.3.0</td><td>21952 (21952)</td><td>1.5 MiB</td><td class="x">80</td><td>a_1</td></tr></table>';
  const want = '<table><tr><th>Name</th><th class="num">1.31.6</th></tr><tr><td>mruby</td><td class="num">4.0.0, 3.3.0</td><td class="num">21952 (21952)</td><td class="num">1.5 MiB</td><td class="num x">80</td><td>a_1</td></tr></table>';
  const got = markCells(html).html;
  if (got === want) console.log('ok: mark-num-cells marks the cells of numbers');
  else {
    failed++;
    console.log(`not ok: mark-num-cells marks the cells of numbers\n  expected: ${want}\n  actual:   ${got}`);
  }
}
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
  console.log(`test-sync-docs: ${failed} of ${fixtures.length + 1} test(s) failed`);
  process.exit(1);
}
console.log(`test-sync-docs: ok; ${fixtures.length} fixtures and the cells of mark-num-cells.mjs`);
