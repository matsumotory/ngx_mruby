// A report of sh test/perf/compare.sh kept for the home pages
// (src/data/perf-*.txt): the header lines that name the source, the month of
// the measurement and the two builds, then the report as compare.sh prints
// it. V3Now.astro shows rows of it, and check-home.mjs compares the page
// with it, so that no number on the page is typed by hand
// (docs/proposals/site.md, Q8: performance only with its date and method).
import fs from 'node:fs';

// The report that the home pages show: the newest 2.x release against the
// newest pre-release of 3.0, in src/data/. A new pre-release of 3.0 replaces
// the file and this name in one pull request.
export const HOME_PERF_REPORT = 'perf-v3.0.0-alpha.3.txt';

const ROW = /^(\S+)\s+(\d+)\s+(\d+)\s+([+-]\d+\.\d+%)\s+(\d+)\s+(\d+)\s+([+-]\d+\.\d+%)\s+(\d+)\s+(\d+)\s+([+-]\d+\.\d+%)\s+\S+\s+(w\/o GC\/const|w\/o GC)\s+(\S+)$/;

export function parsePerfReport(text) {
  const meta = {};
  for (const m of text.matchAll(/^# (source|measured|base|head|where): (.+)$/gm)) meta[m[1]] = m[2].trim();
  for (const key of ['source', 'measured', 'base', 'head', 'where']) if (!meta[key]) throw new Error(`perf report: no "# ${key}:" line`);
  if (!/^https:\/\/github\.com\/matsumotory\/ngx_mruby\/pull\/\d+$/.test(meta.source)) throw new Error(`perf report: the source is not a pull request of ngx_mruby: ${meta.source}`);
  if (!/^\d{4}-\d{2}$/.test(meta.measured)) throw new Error(`perf report: the month is not YYYY-MM: ${meta.measured}`);
  const build = (value) => {
    const m = /^(v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?) ([0-9a-f]{7,40})\b/.exec(value);
    if (!m) throw new Error(`perf report: not "<tag> <commit>": ${value}`);
    return { tag: m[1], version: m[1].slice(1), commit: m[2] };
  };
  const head = /^perf: N=(\d+) WARMUP=(\d+);/m.exec(text);
  if (!head) throw new Error('perf report: no "perf: N=... WARMUP=..." line');
  const rows = text.split('\n').filter((line) => ROW.test(line)).map((line) => {
    const f = ROW.exec(line);
    const judgedConst = f[11] === 'w/o GC/const';
    return {
      scenario: f[1],
      base: Number(f[2]),
      head: Number(f[3]),
      change: f[4],
      noGcBase: Number(f[5]),
      noGcHead: Number(f[6]),
      judgedBase: Number(judgedConst ? f[8] : f[5]),
      judgedHead: Number(judgedConst ? f[9] : f[6]),
      judgedChange: judgedConst ? f[10] : f[7],
      result: f[12],
    };
  });
  if (!rows.length) throw new Error('perf report: no rows');
  // The scenarios that count per TCP session instead of per request.
  const unitsLine = /^perf: units: (.+)$/m.exec(text);
  const units = unitsLine ? [...unitsLine[1].matchAll(/(\w+) = completed TCP session/g)].map((m) => m[1]) : [];
  const [y, mo] = meta.measured.split('-').map(Number);
  return {
    source: meta.source,
    number: Number(meta.source.split('/').pop()),
    year: y,
    month: mo,
    where: meta.where,
    base: build(meta.base),
    head: build(meta.head),
    n: Number(head[1]),
    warmup: Number(head[2]),
    rows,
    units,
  };
}

export function readPerfReport(file) {
  return parsePerfReport(fs.readFileSync(file, 'utf8'));
}

// The month in the words of each language: November 2026, 2026年11月.
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
export function measuredMonth(report, lang) {
  return lang === 'ja' ? `${report.year}年${report.month}月` : `${MONTHS[report.month - 1]} ${report.year}`;
}
