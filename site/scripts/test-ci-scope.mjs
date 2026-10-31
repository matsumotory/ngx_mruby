// Requires npm ci in site/: uses the same satteri parser as the generator.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isLocalProseChange, planBrowserScope } from './lib/ci-scope.mjs';

const manifest = [
  { source: 'docs/guide.md', route: 'guides/a', lang: 'en' },
  { source: 'docs/ja/guide.md', route: 'ja/guides/a', lang: 'ja' },
  { source: 'docs/HANDOFF.md', route: 'contributing/handoff', lang: 'en' },
];
const change = (path = 'docs/guide.md', extra = {}) => ({ path, status: 'M', oldMode: '100644', newMode: '100644',
  oldText: '# Guide\n\nOld prose.\n', newText: '# Guide\n\nNew [link](other.md).\n', ...extra });
const plan = (changes = [change()], extra = {}) => planBrowserScope({ changes, manifest, event: 'pull_request', baselineKnown: true, manifestComplete: true, ...extra });

test('local prose and links select both language routes', () => {
  assert.deepEqual(plan(), { mode: 'targeted', pages: ['/guides/a/', '/ja/guides/a/'], reason: 'local-prose-or-links' });
  assert.deepEqual(plan([change('docs/ja/guide.md')]).pages, plan().pages);
});
test('rendered handoff includes its generated language fallback', () => {
  assert.deepEqual(plan([change('docs/HANDOFF.md')]).pages, ['/contributing/handoff/', '/ja/contributing/handoff/']);
});
test('record-only changes need no page browser checks', () => {
  assert.equal(plan(['AGENTS.md', 'CLAUDE.md', 'README.md'].map((path) => change(path))).mode, 'none');
  assert.equal(plan([change('README.md')], { manifest: [...manifest, { source: 'README.md', route: 'readme', lang: 'en' }] }).mode, 'full');
});
test('mixed local changes union pages; shared inputs override', () => {
  assert.equal(plan([change(), change('docs/HANDOFF.md'), change('README.md')]).pages.length, 4);
  for (const path of ['site/src/styles/site.css', 'site/src/layouts/a.astro', 'site/scripts/sync-docs.mjs', 'site/package-lock.json',
    'site/src/content/docs/index.mdx', '.github/workflows/site.yml', 'test/t/cases/a.rb', 'src/a.c', 'unknown.md', 'examples/start/README.md']) {
    assert.equal(plan([change(), change(path)]).mode, 'full', path);
  }
});
test('file additions, deletion, rename and mode changes stay full', () => {
  for (const extra of [{ status: 'A' }, { status: 'D' }, { status: 'R100' }, { oldMode: '120000' },
    { newMode: '100755' }, { oldMode: '160000' }, { path: 'docs/../README.md' }, { path: 'docs/a\nb.md' }]) {
    assert.equal(plan([change('docs/guide.md', extra)]).mode, 'full', JSON.stringify(extra));
  }
});
test('title, headings, frontmatter, HTML and code changes stay full', () => {
  for (const [oldText, newText] of [
    ['# Old\nbody', '# New\nbody'], ['# A\n## Old\nbody', '# A\n## New\nbody'],
    ['Old\n===\nbody', 'New\n===\nbody'], ['---\ntitle: A\n---\n# A\nbody', '---\ntitle: B\n---\n# A\nbody'],
    ['# A\n<div>old</div>', '# A\n<div>new</div>'],
    ['# A\n```ruby\nx\n```', '# A\n```ruby\ny\n```'], ['# A\n    x', '# A\n    y'],
    ['# A\n`old`', '# A\n`new`'], ['# A\n```\nold', '# A\n```\nnew'],
  ]) assert.equal(plan([change('docs/guide.md', { oldText, newText })]).mode, 'full', newText);
});
test('unchanged code and Japanese heading wbr permit plain prose edits', () => {
  assert.equal(isLocalProseChange('# A<wbr>B\n```ruby\nx\n```\nold', '# A<wbr>B\n```ruby\nx\n```\nnew'), true);
});
test('unknown and partial manifest fail closed', () => {
  for (const extra of [{ manifest: [] }, { manifestComplete: false }, { manifest: null },
    { manifest: [{ source: 'docs/ja/guide.md', route: 'ja/guides/a', lang: 'ja' }] },
    { manifest: [...manifest, manifest[0]] }, { manifest: [{ source: '../a', route: 'a', lang: 'en' }] },
    { manifest: [{ source: 'docs/guide.md', route: 'a,b', lang: 'en' }] }]) {
    assert.equal(plan([change('docs/ja/guide.md')], extra).mode, 'full');
  }
  assert.equal(plan([change('docs/missing.md')]).mode, 'full');
});
test('only confirmed branch/PR ranges may narrow browser checks', () => {
  for (const event of ['workflow_dispatch', 'schedule', 'tag', '', undefined]) assert.equal(plan(undefined, { event }).mode, 'full');
  assert.equal(plan(undefined, { baselineKnown: false }).mode, 'full');
  assert.equal(plan(undefined, { event: 'push' }).mode, 'targeted');
  assert.equal(plan([]).mode, 'full');
  assert.equal(planBrowserScope().mode, 'full');
});

test('selection deduplicates and does not mutate caller data', () => {
  const input = { changes: [change(), change()], manifest, event: 'pull_request', baselineKnown: true, manifestComplete: true };
  const before = JSON.stringify(input);
  assert.equal(planBrowserScope(input).pages.length, 2);
  assert.equal(JSON.stringify(input), before);
});

test('multiline Setext titles and thematic underlines remain full', () => {
  for (const underline of ['===', '---']) {
    const oldText = `Old first line\nSame last line\n${underline}\n\nBody`;
    const newText = `New first line\nSame last line\n${underline}\n\nBody`;
    assert.equal(plan([change('docs/guide.md', { oldText, newText })]).mode, 'full');
  }
});

test('indent and container context cannot silently change block structure', () => {
  for (const block of ['    code', '\tcode']) {
    const oldText = `# A\n\nparagraph\n\n${block}\n`;
    const newText = `# A\n\nparagraph\n${block}\n`;
    assert.equal(plan([change('docs/guide.md', { oldText, newText })]).mode, 'full', block);
  }
});


test('fenced code keeps indentation local while multiline inline code is full', () => {
  assert.equal(isLocalProseChange('# A\n```ruby\n    x\n```\nold', '# A\n```ruby\n    x\n```\nnew'), true);
  assert.equal(isLocalProseChange('# A\n`code\nold\nend`', '# A\n`code\nnew\nend`'), false);
});

test('Markdown directives cannot move the title into a nested container', () => {
  const oldText = '# Old\n\n# Next\n';
  const newText = ':::note\n# Old\n:::\n\n# Next\n';
  assert.equal(isLocalProseChange(oldText, newText), false);
});


test('image reference definitions that change rendered title stay full', () => {
  assert.equal(isLocalProseChange('# Title ![image]\n\nBody', '# Title ![image]\n\nBody\n\n[image]: image.png'), false);
});

test('unchanged rich Markdown structure permits local prose and links', () => {
  for (const [oldText, newText] of [
    ['# A\n\n- Old list text', '# A\n\n- New [list text](other.md)'],
    ['# A\n\n> Old quote', '# A\n\n> New quote'],
    ['# A\n\n:::note\nOld prose\n:::', '# A\n\n:::note\nNew prose\n:::'],
    ['# A\n\n- Old text', '# A\n\n1. New text'],
    ['---\ntitle: A\n---\n# A\n\nOld text', '---\ntitle: A\n---\n# A\n\nNew text'],
    ['# A\n\n<div>Unchanged</div>\n\nOld text', '# A\n\n<div>Unchanged</div>\n\nNew text'],
  ]) assert.equal(plan([change('docs/guide.md', { oldText, newText })]).mode, 'targeted', newText);
});

test('invalid text inputs fail closed', () => {
  assert.equal(isLocalProseChange(null, '# A'), false);
  assert.equal(isLocalProseChange('# A', undefined), false);
  assert.equal(isLocalProseChange('# A', '# A\0'), false);
});

const { shouldMeasureScope } = await import('./lib/ci-scope.mjs');
assert.equal(shouldMeasureScope([{path:'.github/workflows/site.yml'}],'pull_request'),true);
assert.equal(shouldMeasureScope([{path:'site/scripts/ci-browser.mjs'}],'pull_request'),true);
assert.equal(shouldMeasureScope([{path:'site/scripts/lib/ci-scope.mjs'}],'pull_request'),true);
assert.equal(shouldMeasureScope([{path:'docs/install.md'}],'pull_request'),false);
assert.equal(shouldMeasureScope([{path:'site/src/styles/site.css'}],'pull_request'),false);
assert.equal(shouldMeasureScope([{path:'.github/workflows/site.yml'}],'push'),false);
assert.equal(shouldMeasureScope([],'pull_request'),false);
console.log('Only PR CI-policy changes request the extra same-artifact comparison: PASS');
