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
// - the hero (the owner on 2026-11-02, section 7): the heading, the text
//   under it, one action and the status in the first column of .v3-intro;
//   the one action leads to the heading of the use cases on the same page;
//   the status has two lines, the second with the release badge, and the
//   first links to the newest pre-release above the stable release when the
//   git tags have one (latestPrereleaseTag), and to no other release;
// - what the pre-release gives now (V3Now.astro): the performance figures
//   of the page stand only in .now-measured, which gives the month of the
//   report in src/data/, callgrind, and a link to its pull request, and
//   whose table has the numbers of the report's rows; the PERFORMANCE
//   pattern below still applies to the rest of the page.
//
//   node scripts/check-home.mjs [--dist DIR] [--repo DIR]
import fs from 'node:fs';
import path from 'node:path';
import { elements, hasClass, readHtml, textContent, visibleText } from './lib/html.mjs';
import { loadSample, specFromProps } from './lib/samples.mjs';
import { HOME_PAGES } from './lib/site.mjs';
import { latestPrereleaseTag } from './lib/release-state.mjs';
import { measuredMonth, readPerfReport } from './lib/perf-report.mjs';

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
const PERFORMANCE = /\b\d[\d,.]*\s*(k|K|M)?\s*(req\/s|requests?\s*(per|\/)\s*s(ec(ond)?)?|rps|qps|ops\/s|ms\b|µs|usec|instructions per request)|\b\d+(\.\d+)?\s*%\s*(faster|slower|quicker|less|more|fewer|lower|higher)|\b(faster|slower) than\b|[\d０-９][\d０-９,.，．]*\s*[万千億]?\s*(リクエスト|件|回)?\s*(毎秒|\/秒|／秒|ミリ秒|マイクロ秒)|[\d０-９]+(\.\d+)?\s*[%％]\s*(速|高速|遅|短|少な|多|減|増)|倍(速|高速)|より(速|高速|遅)い/;

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
    const intro = elements(tree).find((e) => hasClass(e, 'v3-intro'));
    const heroText = intro && elements(intro).find((e) => hasClass(e, 'v3-hero-text'));
    if (!heroText || !elements(heroText).some((e) => e.tagName === 'h1' && e.properties?.id === '_top')) problems.push(`${where}: the heading is not in the first column of the hero (.v3-intro .v3-hero-text)`);
    const actions = heroText ? elements(heroText).filter((e) => e.tagName === 'a' && (hasClass(e, 'button-primary') || hasClass(e, 'button-secondary') || hasClass(e, 'intro-link'))) : [];
    if (actions.length !== 1 || actions[0].properties?.href !== '#directions-title') problems.push(`${where}: the hero has ${actions.length} action(s) (${actions.map((e) => e.properties?.href).join(', ')}), expected one to #directions-title`);
    if (!elements(tree).some((e) => e.properties?.id === 'directions-title')) problems.push(`${where}: no element #directions-title for the hero's action`);
    const status = heroText && elements(heroText).find((e) => hasClass(e, 'v3-status'));
    const statusLines = status ? (status.children ?? []).filter((e) => e.tagName === 'p') : [];
    if (statusLines.length !== 2 || !elements(statusLines[1]).some((e) => hasClass(e, 'release-badge'))) problems.push(`${where}: the status of the hero is not two lines with the release badge on the second`);
    const prerelease = latestPrereleaseTag(opt.repo);
    const releaseLinks = statusLines[0] ? elements(statusLines[0]).filter((e) => e.tagName === 'a' && /\/releases\/tag\//.test(e.properties?.href ?? '')) : [];
    const expected = prerelease ? [`https://github.com/matsumotory/ngx_mruby/releases/tag/${prerelease}`] : [];
    if (JSON.stringify(releaseLinks.map((e) => e.properties.href)) !== JSON.stringify(expected)) problems.push(`${where}: the first line of the status links to ${releaseLinks.map((e) => e.properties?.href).join(', ') || 'no release'}, expected ${expected.join(', ') || 'none'} (the newest pre-release of the git tags)`);
    if (prerelease && !textContent(statusLines[0]).includes(prerelease.slice(1))) problems.push(`${where}: the first line of the status does not name ${prerelease.slice(1)}`);
    // The measured change: its month, method and source beside the numbers.
    const report = readPerfReport(path.join(SITE, 'src', 'data', 'perf-v3.0.0-alpha.1.txt'));
    const measured = elements(tree).find((e) => hasClass(e, 'now-measured'));
    if (!measured) problems.push(`${where}: no .now-measured with the measured change of ${report.head.tag}`);
    else {
      const mtext = visibleText(measured).replace(/\s+/g, ' ');
      const month = measuredMonth(report, route ? 'ja' : 'en');
      const heading = elements(measured).find((e) => e.tagName === 'h3');
      if (!heading || !textContent(heading).includes(month)) problems.push(`${where}: the heading of .now-measured does not give the month ${month}`);
      if (!mtext.includes('callgrind')) problems.push(`${where}: .now-measured does not name callgrind`);
      if (!elements(measured).some((e) => e.tagName === 'a' && e.properties?.href === report.source)) problems.push(`${where}: .now-measured does not link to ${report.source}`);
      const bodyRows = elements(measured).filter((e) => e.tagName === 'tbody').flatMap((b) => elements(b).filter((e) => e.tagName === 'tr'));
      if (!bodyRows.length) problems.push(`${where}: .now-measured has no table rows`);
      for (const tr of bodyRows) {
        const row = report.rows.find((r) => r.scenario === tr.properties?.dataScenario);
        const cells = elements(tr).filter((e) => e.tagName === 'td').map((e) => textContent(e).trim());
        const want = row && [row.base.toLocaleString('en-US'), row.head.toLocaleString('en-US'), row.change.replace('-', '\u2212')];
        if (!want || JSON.stringify(cells) !== JSON.stringify(want)) problems.push(`${where}: the row ${tr.properties?.dataScenario ?? '(no data-scenario)'} of .now-measured is ${cells.join(' | ')}, the report gives ${want ? want.join(' | ') : 'no such row'}`);
      }
    }
    const blocks = codeBlockTexts(tree);
    // The rest of the page is read without the measured block.
    const kept = measured?.children;
    if (measured) measured.children = [];
    const text = visibleText(tree);
    if (measured) measured.children = kept;
    // The prominent interactive table is a verbatim excerpt from the local
    // walkthrough, not a different fixture presented as the same exercise.
    const localHandler = fs.readFileSync(path.join(opt.repo, 'examples/start/route.rb'), 'utf8');
    const localMapping = localHandler.slice(localHandler.indexOf('  routes = {'), localHandler.indexOf('\n  begin')).trimEnd();
    if (!localMapping || !blocks.includes(localMapping)) problems.push(`${where}: missing canonical local route table`);
    const walkthrough = fs.readFileSync(path.join(opt.repo, 'examples/start/README.md'), 'utf8');
    for (const model of ['a', 'b']) {
      const output = { upstream: model, model: `mock-model-${model}`, credential_replaced: true };
      if (!blocks.includes(JSON.stringify(output, null, 2).replaceAll('": ', '":'))) problems.push(`${where}: missing mock response ${model}`);
      if (!walkthrough.includes(JSON.stringify(output, null, 2).replaceAll('": ', '":'))) problems.push(`${where}: mock response ${model} is not checked by the walkthrough`);
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
  console.log(`check-home: ok; ${HOME_PAGES.length} home pages show the ${files} files that their case compares, with the case, the date and the commit; performance figures only in the measured block, with its month, method and source, and none elsewhere`);
}

main();
