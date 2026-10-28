// The diagram checks of step 3 (docs/proposals/site.md, 3.5 and section 6)
// that need no browser:
//
// - every drawing in site/src/diagrams/ holds lines, boxes and symbols
//   only: no <text> (or other element that draws text or an image), no
//   color in an attribute or a style, and only the classes that
//   diagrams.css colors from the tokens;
// - every diagram block of docs/ names a drawing that exists, with the
//   same keys, and source lines that exist: each file at HEAD and at the
//   commit of its "at:" line, each line range inside the file at that
//   commit, and the date of the "at:" line equal to the commit's date;
// - it lists every diagram whose lines changed since its commit, with the
//   changed lines, in its output and in the run summary of GitHub Actions
//   ($GITHUB_STEP_SUMMARY). A listed diagram is not a failure: the session
//   that redraws or confirms it moves its commit and date (3.5, "Keeping
//   them true"). `git log -L <start>,<end>:<file>` reads its range at the
//   newest commit, so the check reads the ranges at the diagram's commit
//   and compares them with the hunks of `git diff <commit> HEAD`.
//
//   node scripts/check-diagrams.mjs [--repo DIR]
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { checkKeys, diagramsDir, loadDrawings, parseDiagramBlock } from './lib/diagrams.mjs';
import { parseMarkdown } from './lib/markdown.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

function args() {
  const a = process.argv.slice(2);
  const out = { repo: path.resolve(SITE, '..') };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--repo') out.repo = path.resolve(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

const ELEMENTS = new Set(['svg', 'g', 'rect', 'line', 'path', 'circle', 'ellipse', 'polyline', 'polygon']);
const CLASSES = new Set(['d-box', 'd-line', 'd-mark', 'd-quiet']);
const ATTRIBUTES = new Set(['xmlns', 'viewBox', 'preserveAspectRatio', 'data-labels', 'class', 'x', 'y', 'width', 'height', 'x1', 'y1', 'x2', 'y2', 'cx', 'cy', 'r', 'rx', 'ry', 'd', 'points']);

export function checkDrawing(file, svg) {
  const problems = [];
  const body = svg.replace(/<!--[\s\S]*?-->/g, '');
  for (const m of body.matchAll(/<([a-zA-Z][\w:-]*)\b([^>]*)>/g)) {
    const [, tag, attrs] = m;
    if (!ELEMENTS.has(tag)) problems.push(`${file}: <${tag}> is not a line, box or symbol (3.5: no <text>, the labels are HTML)`);
    for (const a of attrs.matchAll(/([\w:-]+)\s*=\s*"([^"]*)"/g)) {
      const [, name, value] = a;
      if (!ATTRIBUTES.has(name)) problems.push(`${file}: <${tag} ${name}="${value.slice(0, 40)}">: the attribute ${name} is not one of a drawing (colors come from the classes and the tokens, 3.5)`);
      if (name === 'class') for (const c of value.split(/\s+/)) if (c && !CLASSES.has(c)) problems.push(`${file}: <${tag} class="${value}">: the class ${c} is not one of ${[...CLASSES].join(', ')}`);
      if (/#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|oklch\(/i.test(value)) problems.push(`${file}: <${tag} ${name}="${value.slice(0, 40)}"> holds a color`);
    }
  }
  if (!/<svg\b[^>]*\bdata-labels="[^"]+"/.test(body)) problems.push(`${file}: <svg> has no data-labels attribute with the keys of its labels`);
  return problems;
}

function git(repo, ...args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function markdownFiles(repo, dir, out = []) {
  for (const e of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    const rel = `${dir}/${e.name}`;
    if (e.isDirectory()) {
      if (rel !== 'docs/proposals') markdownFiles(repo, rel, out);
    } else if (e.name.endsWith('.md')) out.push(rel);
  }
  return out;
}

// The hunks of `git diff -U0 commit HEAD -- file` as old ranges and text.
function hunks(repo, commit, file) {
  const diff = git(repo, 'diff', '-U0', commit, 'HEAD', '--', file);
  const out = [];
  let cur = null;
  for (const line of diff.split('\n')) {
    const m = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (m) {
      const start = Number(m[1]);
      const count = m[2] === undefined ? 1 : Number(m[2]);
      cur = { start, end: count === 0 ? start : start + count - 1, text: [line] };
      out.push(cur);
    } else if (cur && /^[-+]/.test(line) && !/^(---|\+\+\+) /.test(line)) cur.text.push(line);
  }
  return out;
}

function main() {
  const opt = args();
  const problems = [];
  const changed = [];
  const dir = diagramsDir(path.join(opt.repo, 'site'));
  const drawings = fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.svg')) : [];
  for (const f of drawings) problems.push(...checkDrawing(`site/src/diagrams/${f}`, fs.readFileSync(path.join(dir, f), 'utf8')));
  const tracked = new Set(git(opt.repo, 'ls-files', '-z').split('\0'));
  let blocks = 0;
  for (const source of markdownFiles(opt.repo, 'docs')) {
    const tree = parseMarkdown(fs.readFileSync(path.join(opt.repo, source), 'utf8'));
    for (const node of tree.children) {
      if (node.type !== 'code' || node.lang !== 'diagram') continue;
      const where = `${source}:${node.position.start.line}`;
      let block;
      try {
        block = parseDiagramBlock(node.value, where);
        checkKeys(block, loadDrawings(path.join(opt.repo, 'site'), block.name, where)[0].keys, where, `the drawing site/src/diagrams/${block.name}.svg`);
      } catch (e) {
        problems.push(e.message);
        continue;
      }
      blocks++;
      const { commit, date } = block.at;
      let full;
      try {
        full = git(opt.repo, 'rev-parse', '--verify', '--quiet', `${commit}^{commit}`).trim();
      } catch {
        problems.push(`${where}: the commit ${commit} of the diagram ${block.name} does not exist`);
        continue;
      }
      const real = git(opt.repo, 'log', '-1', '--format=%cs', full).trim();
      if (real !== date) problems.push(`${where}: the date of the diagram ${block.name} is ${date}, but the commit ${commit} is of ${real}`);
      for (const s of block.sources) {
        if (!tracked.has(s.file)) {
          problems.push(`${where}: the diagram ${block.name} describes ${s.file}, which git does not track at HEAD`);
          continue;
        }
        let then;
        try {
          then = git(opt.repo, 'show', `${full}:${s.file}`);
        } catch {
          problems.push(`${where}: the diagram ${block.name} describes ${s.file}, which does not exist at ${commit}`);
          continue;
        }
        const count = then.endsWith('\n') ? then.split('\n').length - 1 : then.split('\n').length;
        for (const [a, b] of s.ranges) {
          if (b > count) problems.push(`${where}: the diagram ${block.name} describes ${s.file} lines ${a} to ${b}, but the file has ${count} lines at ${commit}`);
        }
        for (const h of hunks(opt.repo, full, s.file)) {
          for (const [a, b] of s.ranges) {
            // A hunk that only adds lines sits after its start line.
            const touches = h.start <= b && h.end >= a;
            if (touches) changed.push({ where, name: block.name, file: s.file, range: [a, b], hunk: h.text.slice(0, 12).join('\n') });
          }
        }
      }
      for (const n of block.nginx) {
        const pinned = /NGINX_SRC_MAJOR=(\d+)\s+NGINX_SRC_MINOR=(\d+)\s+NGINX_SRC_PATCH=(\d+)/.exec(fs.readFileSync(path.join(opt.repo, 'nginx_version'), 'utf8'));
        const version = pinned ? pinned.slice(1).join('.') : '';
        if (version !== n.version) changed.push({ where, name: block.name, file: `nginx ${n.file}`, range: n.ranges[0], hunk: `nginx_version names ${version}, the diagram describes nginx ${n.version}` });
      }
    }
  }
  const lines = changed.map((c) => `changed: ${c.where}: the diagram ${c.name} describes ${c.file} lines ${c.range[0]} to ${c.range[1]}, which changed since its commit:\n${c.hunk}`);
  for (const l of lines) console.log(l);
  if (process.env.GITHUB_STEP_SUMMARY) {
    const md = ['### Diagrams whose source changed since their commit (3.5)', ''];
    if (!changed.length) md.push(`None of the ${blocks} diagram blocks of docs/.`);
    for (const c of changed) md.push(`- ${c.where}: ${c.name}, ${c.file} lines ${c.range[0]} to ${c.range[1]}`, '', '  ```diff', ...c.hunk.split('\n').map((x) => `  ${x}`), '  ```');
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md.join('\n')}\n`);
  }
  for (const p of problems) console.log(p);
  const summary = `${drawings.length} drawing(s), ${blocks} diagram block(s) of docs/, ${changed.length} described range(s) changed since their commit`;
  if (problems.length) {
    console.log(`check-diagrams: ${problems.length} problem(s); ${summary}`);
    process.exit(1);
  }
  console.log(`check-diagrams: ok; ${summary}`);
}

main();
