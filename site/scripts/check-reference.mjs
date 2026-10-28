// The reference checks of step 4 (docs/proposals/site.md, section 6):
//
// - "every directive in the ngx_command_t tables of src/ has a section in
//   the directive reference": every name of the ngx_command_t tables of
//   the C sources under src/ is a word of a heading of
//   docs/directives/README.md;
// - "mruby_output_filter appears in docs/ only in a removal note": every
//   block of the Markdown files of docs/ (outside docs/proposals/) that
//   names mruby_output_filter or mruby_output_filter_code, a paragraph, a
//   list item, a table row or a heading, says that it was removed or that
//   nginx rejects it ("removed", "rejects", 削除, 拒む), or stands in a
//   section whose heading says so;
// - "the default gems listed in the docs equal the uncommented conf.gem
//   lines of build_config.rb": the items of the list under "Default
//   mrbgems" in docs/reference/build.md, by the name in their first code
//   span, are the gems of the conf.gem lines of the host build of
//   build_config.rb that are not comments and have no condition (github:
//   'owner/name' as owner/name, './mrbgems/name' as mrbgems/name).
//
//   node scripts/check-reference.mjs [--repo DIR]
//
// It needs no build. It exits 1 and lists every problem.
import fs from 'node:fs';
import path from 'node:path';
import { parseMarkdown } from './lib/markdown.mjs';
import { finish, repoDir } from './lib/site.mjs';

const argv = process.argv.slice(2);
let repo = repoDir;
if (argv[0] === '--repo' && argv[1]) repo = path.resolve(argv[1]);
else if (argv.length) {
  console.error('usage: node scripts/check-reference.mjs [--repo DIR]');
  process.exit(2);
}
const read = (rel) => fs.readFileSync(path.join(repo, rel), 'utf8');
const text = (node) => (node.value ?? '') + (node.children ?? []).map(text).join('');
const problems = [];

// 1. The directives of the ngx_command_t tables
function cFiles(dir, out = []) {
  for (const entry of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) cFiles(rel, out);
    else if (/\.[ch]$/.test(entry.name)) out.push(rel);
  }
  return out;
}
const directives = new Map();
for (const file of cFiles('src')) {
  const src = read(file);
  for (const table of src.matchAll(/ngx_command_t\s+\w+\[\]\s*=\s*\{([\s\S]*?)ngx_null_command/g)) {
    for (const m of table[1].matchAll(/\{\s*ngx_string\("([a-z0-9_]+)"\)/g)) directives.set(m[1], file);
  }
}
if (directives.size === 0) problems.push('no ngx_command_t table found under src/');
const DIRECTIVES = 'docs/directives/README.md';
const headings = [];
const tree = parseMarkdown(read(DIRECTIVES));
for (const node of tree.children) if (node.type === 'heading') headings.push(text(node));
const headingWords = new Set(headings.flatMap((h) => h.split(/[^a-z0-9_]+/)));
for (const [name, file] of directives) {
  if (!headingWords.has(name)) problems.push(`${DIRECTIVES}: no heading names the directive ${name} of the ngx_command_t table of ${file}`);
}

// 2. mruby_output_filter only in removal notes
const REMOVED = /removed|rejects|削除|拒む|拒み/i;
const OUTPUT_FILTER = /mruby_output_filter(?!_?(?:body|header))/;
function markdownFiles(dir, out = []) {
  for (const entry of fs.readdirSync(path.join(repo, dir), { withFileTypes: true })) {
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (rel !== 'docs/proposals') markdownFiles(rel, out);
    } else if (entry.name.endsWith('.md')) out.push(rel);
  }
  return out;
}
let mentions = 0;
for (const file of markdownFiles('docs')) {
  const src = read(file);
  if (!OUTPUT_FILTER.test(src)) continue;
  const md = parseMarkdown(src);
  // The heading of each section, by depth, while walking the top level
  const section = [];
  const check = (node, inRemovedSection) => {
    const own = ['paragraph', 'listItem', 'tableRow', 'heading', 'code', 'html'].includes(node.type);
    if (own) {
      const t = node.type === 'listItem' ? (node.children ?? []).filter((c) => c.type === 'paragraph').map(text).join(' ') : text(node);
      if (OUTPUT_FILTER.test(t)) {
        mentions++;
        if (!REMOVED.test(t) && !inRemovedSection) {
          problems.push(`${file}:${node.position.start.line}: names mruby_output_filter outside a removal note (a block that says "removed" or that nginx rejects it, or a section whose heading does)`);
        }
      }
      if (node.type !== 'listItem') return;
    }
    for (const child of node.children ?? []) check(child, inRemovedSection);
  };
  for (const node of md.children) {
    if (node.type === 'heading') {
      section.length = node.depth - 1;
      section[node.depth - 1] = text(node);
    }
    check(node, section.some((h) => h && REMOVED.test(h)));
  }
}

// 3. The default gems
const BUILD = 'docs/reference/build.md';
const config = read('build_config.rb');
const host = /MRuby::Build\.new\('host'\) do \|conf\|([\s\S]*?)\nend\n/.exec(config);
const gems = new Set();
if (!host) problems.push("build_config.rb: no MRuby::Build.new('host') block");
else {
  for (const line of host[1].split('\n')) {
    // A comment, or a gem that a condition adds (auto-ssl with
    // NGX_MRUBY_AUTO_SSL=1), is not in the default build
    if (/^\s*#/.test(line) || /\b(if|unless)\b/.test(line)) continue;
    const m = /^\s*conf\.gem\s+(?:github:\s*'([^']+)'|'\.\/(mrbgems\/[^']+)')/.exec(line);
    if (m) gems.add(m[1] ?? m[2]);
  }
}
const listed = new Set();
if (!fs.existsSync(path.join(repo, BUILD))) problems.push(`${BUILD} is missing`);
else {
  const md = parseMarkdown(read(BUILD));
  let inSection = false;
  for (const node of md.children) {
    if (node.type === 'heading') inSection = text(node) === 'Default mrbgems';
    else if (inSection && node.type === 'list') {
      for (const item of node.children) {
        let code = null;
        const find = (n) => {
          if (code === null && n.type === 'inlineCode') code = n.value;
          for (const c of n.children ?? []) find(c);
        };
        find(item);
        if (code) listed.add(code);
      }
    }
  }
  if (!listed.size) problems.push(`${BUILD}: no list under the heading "Default mrbgems"`);
  for (const g of gems) if (!listed.has(g)) problems.push(`${BUILD}: "Default mrbgems" does not list ${g}, which build_config.rb builds`);
  for (const g of listed) if (!gems.has(g)) problems.push(`${BUILD}: "Default mrbgems" lists ${g}, which build_config.rb does not build (or names in a comment)`);
}

finish(
  'check-reference',
  problems,
  `${directives.size} directives of the ngx_command_t tables have a heading in ${DIRECTIVES}; ${mentions} mention(s) of mruby_output_filter in docs/, each in a removal note; the ${listed.size} default mrbgems of ${BUILD} are the ${gems.size} conf.gem lines of build_config.rb`,
);
