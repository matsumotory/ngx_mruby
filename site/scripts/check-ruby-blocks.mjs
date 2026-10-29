// The check of step 4 (docs/proposals/site.md, section 6): "every Ruby
// block in the docs compiles with the bundled mruby's mrbc".
//
// It compiles every fenced code block with the language ruby (or rb) of
// the pages (the Markdown files of docs/ outside docs/proposals/, and the
// pages of SOURCE_ROUTES outside docs/) with mrbc, and every script file of
// a sample block (scripts/lib/samples.mjs). mrbc checks the syntax only: a
// constant or a method that the build lacks still compiles. A block that
// shows a syntax error on purpose says so with `syntax-error` after the
// language (```ruby syntax-error), and must not compile.
//
//   node scripts/check-ruby-blocks.mjs --mrbc PATH [--repo DIR]
//
// mrbc comes from the bundled mruby (mruby/), built alone, which takes
// about ten seconds:
//
//   cd mruby && MRUBY_CONFIG=build_config/mrbc.rb MRUBY_BUILD_DIR=DIR rake
//
// and is then DIR/host/bin/mrbc. It exits 1 and lists every block that does
// not compile, by file and line, with mrbc's message.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseMarkdown } from './lib/markdown.mjs';
import { finish, repoDir, SOURCE_ROUTES } from './lib/site.mjs';
import { parseSampleBlock } from './lib/samples.mjs';

const argv = process.argv.slice(2);
let repo = repoDir;
let mrbc = null;
for (let i = 0; i < argv.length; i += 2) {
  if (argv[i] === '--repo') repo = path.resolve(argv[i + 1]);
  else if (argv[i] === '--mrbc') mrbc = path.resolve(argv[i + 1]);
  else {
    mrbc = null;
    break;
  }
}
if (!mrbc || !fs.existsSync(mrbc)) {
  console.error('usage: node scripts/check-ruby-blocks.mjs --mrbc PATH [--repo DIR] (build mrbc as the comment at the top says)');
  process.exit(2);
}

function markdownFiles(dir, out = []) {
  for (const entry of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (rel !== 'docs/proposals') markdownFiles(rel, out);
    } else if (entry.name.endsWith('.md')) out.push(rel);
  }
  return out;
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx_mruby-ruby-blocks-'));
const problems = [];
let blocks = 0;
const scripts = new Set();
let errors = 0;
function compile(code, where, error = false) {
  const file = path.join(tmp, `block${blocks}.rb`);
  fs.writeFileSync(file, code);
  const r = spawnSync(mrbc, ['-o', path.join(tmp, 'out.mrb'), file], { encoding: 'utf8' });
  if (error) {
    errors++;
    if (r.status === 0) problems.push(`${where}: the block is marked syntax-error, but mrbc compiles it`);
  } else if (r.status !== 0) {
    const message = `${r.stderr}${r.stdout}`.trim().replaceAll(file, 'block');
    problems.push(`${where}: mrbc does not compile this Ruby block: ${message}`);
  }
}
try {
  const sources = [...markdownFiles('docs'), ...Object.keys(SOURCE_ROUTES).filter((s) => !s.startsWith('docs/') && fs.existsSync(path.join(repo, s)))];
  for (const source of sources) {
    const visit = (node) => {
      if (node.type === 'code' && /^(ruby|rb)$/i.test(node.lang ?? '')) {
        blocks++;
        compile(node.value, `${source}:${node.position.start.line}`, /(^|\s)syntax-error(\s|$)/.test(node.meta ?? ''));
      } else if (node.type === 'code' && node.lang === 'sample') {
        try {
          scripts.add(parseSampleBlock(node.value, source).script);
        } catch {
          // check-samples.mjs and the generator report a broken sample block
        }
      }
      for (const child of node.children ?? []) visit(child);
    };
    visit(parseMarkdown(fs.readFileSync(path.join(repo, source), 'utf8')));
  }
  for (const script of scripts) {
    blocks++;
    if (fs.existsSync(path.join(repo, script))) compile(fs.readFileSync(path.join(repo, script), 'utf8'), script);
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

finish('check-ruby-blocks', problems, `${blocks - scripts.size - errors} Ruby block(s) of the pages and ${scripts.size} script(s) of their samples compiled, and ${errors} block(s) marked syntax-error did not compile, with ${path.relative(process.cwd(), mrbc) || mrbc}`);
