// Marks the table cells of the built pages that hold only numbers with the
// class num, which site.css sets in the monospace face with tabular
// figures (docs/proposals/site.md, 4.3 item 2: the numbers of tables and
// measurements): versions such as 1.31.6, lists of them, ports, sizes and
// durations. A cell with any other word stays in the text face.
//
// `npm run build` runs it on dist/ after `astro build`, because the
// Markdown processor of Astro 7 runs no rehype plugin without another
// package.
//
//   node scripts/mark-num-cells.mjs [--dist DIR]
import fs from 'node:fs';
import path from 'node:path';
import { distDir, htmlFiles } from './lib/site.mjs';

const NUMERIC = /^[0-9][0-9.,:/x%+ -]*( ?(px|ms|s|KiB|MiB|GiB|KB|MB|GB))?$/;
export const isNumeric = (text) => NUMERIC.test(text.trim());

const decode = (s) => s.replace(/<[^>]*>/g, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
const argv = process.argv.slice(2);
const dist = argv[0] === '--dist' && argv[1] ? path.resolve(argv[1]) : distDir;
let cells = 0;
for (const file of htmlFiles(dist)) {
  const full = path.join(dist, file);
  const html = fs.readFileSync(full, 'utf8');
  const out = html.replace(/<(td|th)((?:\s[^>]*)?)>([\s\S]*?)<\/\1>/g, (all, tag, attrs, inner) => {
    if (!isNumeric(decode(inner)) || /\bclass="[^"]*\bnum\b/.test(attrs)) return all;
    cells++;
    const withClass = /\bclass="/.test(attrs) ? attrs.replace(/\bclass="/, 'class="num ') : `${attrs} class="num"`;
    return `<${tag}${withClass}>${inner}</${tag}>`;
  });
  if (out !== html) fs.writeFileSync(full, out);
}
console.log(`mark-num-cells: ${cells} table cell(s) of numbers marked with the class num`);
