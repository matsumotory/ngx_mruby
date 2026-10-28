// Samples of docs/proposals/site.md, 3.5 ("Samples") and 3.3 item 8: a
// server block, its Ruby script, the request that a case of test/t/cases/
// sends and the response that it compares, copied from the test files into
// a page with the date of the last commit to them. Nothing is copied by
// hand. scripts/sync-docs.mjs expands a fenced block with the language
// `sample` in docs/ with these functions, and src/components/Sample.astro
// shows a sample on the home pages.
//
// A sample block gives one file per line:
//
//   ```sample
//   case: test/t/cases/home_example.rb
//   conf: test/conf/conf.d/70-home-example.conf
//   script: test/html/home_example.rb
//   request: test/html/home_example.request
//   response: test/html/home_example.response
//   ```
//
// loadSample stops (throws) when a key is missing or unknown, when a file
// is missing or not tracked by git, and when the case does not name the
// request and the response files, so a page never shows a file that the
// case does not compare.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

export const SAMPLE_KEYS = ['case', 'conf', 'script', 'request', 'response'];
// Where each file of a sample lives (docs/test/README.md, "Add a test as a
// fragment and a case file").
const PLACES = {
  case: /^test\/t\/cases\/[^_/][^/]*\.rb$/,
  conf: /^test\/conf\/conf\.d\/(stream\/)?[^/]+\.conf$/,
  script: /^test\/html\/[^/]+\.rb$/,
  request: /^test\/html\/[^/]+$/,
  response: /^test\/html\/[^/]+$/,
};
// The language of each file in the page's code blocks.
export const SAMPLE_LANGS = { conf: 'nginx', script: 'ruby', request: 'http', response: 'http' };

export function parseSampleBlock(text, where) {
  const spec = {};
  for (const [i, line] of text.split('\n').entries()) {
    if (!line.trim()) continue;
    const m = /^([a-z]+):\s*(\S+)\s*$/.exec(line);
    if (!m) throw new Error(`${where}: line ${i + 1} of the sample block is not "key: path": ${line}`);
    if (!SAMPLE_KEYS.includes(m[1])) throw new Error(`${where}: the sample block has the unknown key ${m[1]} (keys: ${SAMPLE_KEYS.join(', ')})`);
    if (spec[m[1]]) throw new Error(`${where}: the sample block gives ${m[1]} twice`);
    spec[m[1]] = m[2];
  }
  for (const key of SAMPLE_KEYS) if (!spec[key]) throw new Error(`${where}: the sample block has no ${key}`);
  return spec;
}

// The comment lines at the top of a configuration or a script: notes for
// the test suite (which case reads it, its port), not part of the example.
function withoutLeadingComments(text) {
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length && (lines[i].startsWith('#') || (i > 0 && lines[i].trim() === '' && lines[i - 1].startsWith('#')))) i++;
  return lines.slice(i).join('\n').replace(/\n+$/, '\n');
}

export function loadSample(spec, repo, where) {
  const tracked = new Set(execFileSync('git', ['-C', repo, 'ls-files', '-z', '--', 'test'], { encoding: 'utf8' }).split('\0'));
  const files = {};
  for (const key of SAMPLE_KEYS) {
    const file = spec[key];
    if (!PLACES[key].test(file)) throw new Error(`${where}: the ${key} of the sample, ${file}, is not where docs/test/README.md puts it`);
    if (!fs.existsSync(path.join(repo, file))) throw new Error(`${where}: the ${key} of the sample, ${file}, is missing`);
    if (!tracked.has(file)) throw new Error(`${where}: the ${key} of the sample, ${file}, is not tracked by git`);
    files[key] = fs.readFileSync(path.join(repo, file), 'utf8');
  }
  const caseText = files.case;
  for (const key of ['request', 'response', 'conf']) {
    const name = key === 'conf' ? portOf(files.conf, spec.conf, where) : path.posix.basename(spec[key]);
    if (!caseText.includes(name)) {
      throw new Error(`${where}: the case ${spec.case} does not name ${key === 'conf' ? `the port ${name} of ${spec.conf}` : name}, so it does not compare what the page would show`);
    }
  }
  const out = execFileSync('git', ['-C', repo, 'log', '-1', '--format=%h %cs', '--', ...SAMPLE_KEYS.map((k) => spec[k])], { encoding: 'utf8' }).trim();
  const [commit, date] = out.split(' ');
  if (!commit) throw new Error(`${where}: no commit changed the files of the sample yet`);
  return {
    spec,
    commit,
    date,
    shown: [
      { key: 'conf', file: spec.conf, lang: SAMPLE_LANGS.conf, text: withoutLeadingComments(files.conf) },
      { key: 'script', file: spec.script, lang: SAMPLE_LANGS.script, text: withoutLeadingComments(files.script) },
      { key: 'request', file: spec.request, lang: SAMPLE_LANGS.request, text: files.request },
      { key: 'response', file: spec.response, lang: SAMPLE_LANGS.response, text: files.response },
    ],
  };
}

function portOf(conf, file, where) {
  const m = /^\s*listen\s+(\d+)/m.exec(conf);
  if (!m) throw new Error(`${where}: ${file} has no listen directive with a port`);
  return m[1];
}

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// The line under a sample: the case, what it compares, and the date and
// commit of the last change. Dates and commits do not break inside (the
// owner's practice keeps numbers with units together).
export function sampleCaptionHtml(sample, lang) {
  const c = `<code>${escapeHtml(sample.spec.case)}</code>`;
  const date = `<span class="nowrap">${sample.date}</span>`;
  const commit = `<code class="nowrap">${sample.commit}</code>`;
  return lang === 'ja'
    ? `CIを実行するたびに、ケースの${c}がこのリクエストを送ります。比べるのは、ステータス行、表示したヘッダ、ボディの全体です。5つのファイルを最後に変更したコミットは${commit}で、その日付は${date}です。`
    : `On every CI run, the case ${c} sends this request and compares the status line, the headers shown and the whole body. The five files last changed on ${date} in commit ${commit}.`;
}

// The titles of the code blocks of a sample.
export function sampleTitle(item, lang) {
  if (item.key === 'request') return lang === 'ja' ? `${item.file}: ケースが送るリクエスト` : `${item.file}: the request that the case sends`;
  if (item.key === 'response') return lang === 'ja' ? `${item.file}: ケースが比べるレスポンス` : `${item.file}: the response that the case compares`;
  return item.file;
}

// The sample as Markdown, for a page of docs/: one fenced code block per
// file, with its title, and the caption line as an HTML paragraph.
export function sampleMarkdown(sample, lang) {
  const blocks = sample.shown.map((item) => {
    let fence = '```';
    while (item.text.includes(fence)) fence += '`';
    return `${fence}${item.lang} title=${JSON.stringify(sampleTitle(item, lang))}\n${item.text.replace(/\n$/, '')}\n${fence}`;
  });
  return `${blocks.join('\n\n')}\n\n<p class="caption sample-caption">${sampleCaptionHtml(sample, lang)}</p>`;
}
