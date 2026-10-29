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
// is missing or not tracked by git, and when the code of the case (not
// only a comment) does not name the request and the response files and the
// port of the configuration.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { DEVELOPMENT_LABEL } from './diagrams.mjs';

export const SAMPLE_KEYS = ['case', 'conf', 'script', 'request', 'response', 'compared', 'label'];
// A key that a block may give more than once: a sample of several scripts,
// or of several files of compared values.
const REPEATED = new Set(['script', 'compared']);
// Where each file of a sample lives (docs/test/README.md, "Add a test as a
// fragment and a case file").
const PLACES = {
  case: /^test\/t\/cases\/[^_/][^/]*\.rb$/,
  conf: /^test\/conf\/conf\.d\/(stream\/)?[^/]+\.conf$/,
  script: /^test\/html\/[^/]+\.rb$/,
  request: /^test\/html\/[^/]+$/,
  response: /^test\/html\/[^/]+$/,
  compared: /^test\/html\/[^/]+$/,
};
// The language of each file in the page's code blocks.
export const SAMPLE_LANGS = { conf: 'nginx', script: 'ruby', request: 'http', response: 'http', compared: 'text' };

// A sample block gives one file per line, and either a request and the
// response that the case compares, or one or more files of the values that
// the case compares (compared:), for a case whose client prints values
// instead of whole responses (the agent proxy recipes).
export function parseSampleBlock(text, where) {
  const spec = { script: [], compared: [] };
  for (const [i, line] of text.split('\n').entries()) {
    if (!line.trim()) continue;
    const m = /^([a-z]+):\s*(\S+)\s*$/.exec(line);
    if (!m) throw new Error(`${where}: line ${i + 1} of the sample block is not "key: path": ${line}`);
    if (!SAMPLE_KEYS.includes(m[1])) throw new Error(`${where}: the sample block has the unknown key ${m[1]} (keys: ${SAMPLE_KEYS.join(', ')})`);
    if (REPEATED.has(m[1])) {
      spec[m[1]].push(m[2]);
      continue;
    }
    if (spec[m[1]]) throw new Error(`${where}: the sample block gives ${m[1]} twice`);
    spec[m[1]] = m[2];
  }
  if (spec.label !== undefined && spec.label !== 'development') throw new Error(`${where}: the label of a sample block is development, not ${spec.label}`);
  for (const key of ['case', 'conf']) if (!spec[key]) throw new Error(`${where}: the sample block has no ${key}`);
  if (!spec.script.length) throw new Error(`${where}: the sample block has no script`);
  if (spec.compared.length) {
    if (spec.request || spec.response) throw new Error(`${where}: a sample block gives either request and response, or compared`);
  } else {
    for (const key of ['request', 'response']) if (!spec[key]) throw new Error(`${where}: the sample block has no ${key}`);
  }
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

// The spec of a sample from the attributes of <Sample> on the home pages
// (one script, a request and a response).
export function specFromProps(props) {
  return { case: props.case, conf: props.conf, script: [props.script], request: props.request, response: props.response, compared: [] };
}

// The files of a sample, in the order of the page: [key, path].
function sampleFiles(spec) {
  const files = [['conf', spec.conf], ...spec.script.map((f) => ['script', f])];
  if (spec.compared.length) files.push(...spec.compared.map((f) => ['compared', f]));
  else files.push(['request', spec.request], ['response', spec.response]);
  return files;
}

export function loadSample(spec, repo, where) {
  const tracked = new Set(execFileSync('git', ['-C', repo, 'ls-files', '-z', '--', 'test'], { encoding: 'utf8' }).split('\0'));
  const text = {};
  for (const [key, file] of [['case', spec.case], ...sampleFiles(spec)]) {
    if (!PLACES[key].test(file)) throw new Error(`${where}: the ${key} of the sample, ${file}, is not where docs/test/README.md puts it`);
    if (!fs.existsSync(path.join(repo, file))) throw new Error(`${where}: the ${key} of the sample, ${file}, is missing`);
    if (!tracked.has(file)) throw new Error(`${where}: the ${key} of the sample, ${file}, is not tracked by git`);
    text[file] = fs.readFileSync(path.join(repo, file), 'utf8');
  }
  // The case names the request and the response (or each file of compared
  // values) and the port in its code, not only in a comment. This checks
  // the name, not what the case does with the file; the case's own
  // assertions are the test.
  const caseCode = text[spec.case].split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  const named = [portOf(text[spec.conf], spec.conf, where), ...sampleFiles(spec).filter(([k]) => k === 'request' || k === 'response' || k === 'compared').map(([, f]) => path.posix.basename(f))];
  for (const name of named) {
    if (!caseCode.includes(name)) {
      throw new Error(`${where}: the case ${spec.case} does not name ${/^\d+$/.test(name) ? `the port ${name} of ${spec.conf}` : name} in its code, so it does not compare what the page would show`);
    }
  }
  const out = execFileSync('git', ['-C', repo, 'log', '-1', '--format=%h %cs', '--', spec.case, ...sampleFiles(spec).map(([, f]) => f)], { encoding: 'utf8' }).trim();
  const [commit, date] = out.split(' ');
  if (!commit) throw new Error(`${where}: no commit changed the files of the sample yet`);
  return {
    spec,
    commit,
    date,
    shown: sampleFiles(spec).map(([key, file]) => ({
      key,
      file,
      lang: SAMPLE_LANGS[key],
      text: key === 'conf' || key === 'script' ? withoutLeadingComments(text[file]) : text[file],
    })),
  };
}

function portOf(conf, file, where) {
  // listen 18161; or, in a stream fragment, listen 127.0.0.1:12364;
  const m = /^\s*listen\s+(?:[0-9.]+:)?(\d+)/m.exec(conf);
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
  const count = sample.shown.length + 1;
  const n = { en: ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'][count] ?? String(count) };
  if (sample.spec.compared.length) {
    return lang === 'ja'
      ? `CIが動くたびに、ケースの${c}がクライアントでリクエストを送り、クライアントが出力する値を、ここに載せた値と比べます。<span class="nowrap">${count}個</span>のファイルを最後に変えたのは、${date}のコミット<span class="nowrap"><code>${sample.commit}</code>です。</span>`
      : `On every CI run, the case ${c} sends the requests of its client and compares the values that the client prints with the values shown on this page. The ${n.en} files last changed on ${date} in commit ${commit}.`;
  }
  return lang === 'ja'
    ? `CIが動くたびに、ケースの${c}がこのリクエストを送ります。ケースは、ステータス行、ここに載せたヘッダ、ボディ全体を比べます。<span class="nowrap">${count}個</span>のファイルを最後に変えたのは、${date}のコミット<span class="nowrap"><code>${sample.commit}</code>です。</span>`
    : `On every CI run, the case ${c} sends this request and compares the status line, the headers shown on this page and the whole body. The ${n.en} files last changed on ${date} in commit ${commit}.`;
}

// The titles of the code blocks of a sample.
export function sampleTitle(item, lang) {
  if (item.key === 'request') return lang === 'ja' ? `${item.file}：ケースが送るリクエスト` : `${item.file}: the request that the case sends`;
  if (item.key === 'response') return lang === 'ja' ? `${item.file}：ケースが比べるレスポンス` : `${item.file}: the response that the case compares`;
  if (item.key === 'compared') return lang === 'ja' ? `${item.file}：ケースが比べる値` : `${item.file}: the values that the case compares`;
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
  const label = sample.spec.label === 'development' ? `<p class="caption development-label">${DEVELOPMENT_LABEL[lang === 'ja' ? 'ja' : 'en']}</p>\n\n` : '';
  return `${label}${blocks.join('\n\n')}\n\n<p class="caption sample-caption">${sampleCaptionHtml(sample, lang)}</p>`;
}
