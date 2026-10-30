// The home page checks of step 3 (docs/proposals/site.md, section 6;
// 3.3 item 8; Q8 of section 7), on the built home pages / and /ja/, read
// without running scripts:
//
// - the example: each file of the <Sample> of the page's source (the
//   configuration, the script, the request and the response that the case
//   compares) is the text of one code block of the page, and the line under
//   it names the case, the date and the commit of the last change to the
//   five files, as git gives them;
// - no benchmark image (an <img> whose source or text says bench) and no
//   performance figure (a number with a unit of throughput or latency, or
//   a percentage of faster or slower), since performance appears only as
//   the perf lane's measurements with their date and method (Q8).
//
//   node scripts/check-home.mjs [--dist DIR] [--repo DIR]
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent, visibleText } from './lib/html.mjs';
import { loadSample, specFromProps } from './lib/samples.mjs';
import { HOME_PAGES } from './lib/site.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE, 'dist'), repo: path.resolve(SITE, '..') };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else if (a[i] === '--repo') out.repo = path.resolve(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

// A number with a unit of throughput or latency, or a percentage of faster
// or slower, in English or in Japanese.
const PERFORMANCE = /\b\d[\d,.]*\s*(k|K|M)?\s*(req\/s|requests?\s*(per|\/)\s*s(ec(ond)?)?|rps|qps|ops\/s|ms\b|µs|usec|instructions per request)|\b\d+(\.\d+)?\s*%\s*(faster|slower|quicker|less|more)|\b(faster|slower) than\b|[\d０-９][\d０-９,.，．]*\s*[万千億]?\s*(リクエスト|件|回)?\s*(毎秒|\/秒|／秒|ミリ秒|マイクロ秒)|[\d０-９]+\s*[%％]\s*(速|高速|遅|短|少な|多)|倍(速|高速)|より(速|高速|遅)い/;

// The text of each code block: Expressive Code renders each line as a
// div.ec-line inside <pre>.
function codeBlockTexts(tree) {
  return elements(tree)
    .filter((e) => e.tagName === 'pre')
    .map((pre) => {
      const lines = elements(pre).filter((e) => hasClass(e, 'ec-line'));
      return (lines.length ? lines.map((l) => textContent(l).replace(/\n$/, '')).join('\n') : textContent(pre)).replace(/\n$/, '');
    });
}

function main() {
  const opt = args();
  const problems = [];
  let files = 0;
  for (const [i, rel] of HOME_PAGES.entries()) {
    const route = i === 0 ? '' : 'ja';
    const html = path.join(opt.dist, route, 'index.html');
    const where = `/${route ? `${route}/` : ''}`;
    if (!fs.existsSync(html)) {
      problems.push(`${where}: missing in ${opt.dist}`);
      continue;
    }
    const tree = readHtml(html);
    const source = fs.readFileSync(path.join(SITE, 'src', 'content', 'docs', rel), 'utf8');
    const tags = [...source.matchAll(/<Sample\b([^>]*)\/>/g)];
    if (!tags.length) problems.push(`${where}: site/src/content/docs/${rel} has no <Sample>: the home page shows an example that CI runs (3.3 item 8)`);
    const blocks = codeBlockTexts(tree);
    const text = visibleText(tree);
    // The prominent interactive table is a verbatim excerpt from the local
    // walkthrough, not a different fixture presented as the same exercise.
    const localHandler = fs.readFileSync(path.join(opt.repo, 'examples/start/route.rb'), 'utf8');
    const localMapping = localHandler.slice(localHandler.indexOf('  routes = {'), localHandler.indexOf('\n  begin')).trimEnd();
    if (!localMapping || !blocks.includes(localMapping)) problems.push(`${where}: missing canonical local route table`);
    const walkthrough = fs.readFileSync(path.join(opt.repo, 'examples/start/README.md'), 'utf8');
    for (const model of ['a', 'b']) {
      const output = { upstream: model, model: `mock-model-${model}`, credential_replaced: true };
      if (!blocks.includes(JSON.stringify(output, null, 2))) problems.push(`${where}: missing mock response ${model}`);
      if (!walkthrough.includes(JSON.stringify(output))) problems.push(`${where}: mock response ${model} is not checked by the walkthrough`);
    }
    for (const tag of tags) {
      const spec = Object.fromEntries([...tag[1].matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1], m[2]]));
      let sample;
      try {
        sample = loadSample(specFromProps(spec), opt.repo, where);
      } catch (e) {
        problems.push(e.message);
        continue;
      }
      for (const item of sample.shown) {
        files++;
        if (!blocks.includes(item.text.replace(/\n$/, ''))) problems.push(`${where}: no code block of the page is the text of ${item.file} (the ${item.key} of the sample)`);
      }
      const caption = elements(tree).find((e) => hasClass(e, 'sample-caption'));
      const line = caption ? textContent(caption) : '';
      for (const [what, value] of [['case', sample.spec.case], ['date', sample.date], ['commit', sample.commit]]) {
        if (!line.includes(value)) problems.push(`${where}: the line under the sample does not give the ${what} ${value}: "${line.slice(0, 120)}"`);
      }
    }
    for (const img of elements(tree).filter((e) => e.tagName === 'img')) {
      const desc = `${img.properties?.src ?? ''} ${img.properties?.alt ?? ''}`;
      if (/bench/i.test(desc)) problems.push(`${where}: a benchmark image: <img src="${img.properties?.src}"> (Q8)`);
    }
    const figure = PERFORMANCE.exec(text);
    if (figure) problems.push(`${where}: a performance figure without its date and method: "${text.slice(Math.max(0, figure.index - 40), figure.index + 40).replace(/\s+/g, ' ')}" (Q8)`);
  }
  for (const p of problems) console.log(p);
  if (problems.length) {
    console.log(`check-home: ${problems.length} problem(s); ${HOME_PAGES.length} home pages`);
    process.exit(1);
  }
  console.log(`check-home: ok; ${HOME_PAGES.length} home pages show the ${files} files that their case compares, with the case, the date and the commit, and no benchmark image or performance figure`);
}

main();
