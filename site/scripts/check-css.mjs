// The checks of step 2 (docs/proposals/site.md, section 6) on the built CSS
// and HTML, and on the CSS of site/src/:
//
// - no hex color in the built CSS outside the declarations of tokens.css
//   and Expressive Code's stylesheet (_astro/ec.*.css) (4.6); a hex with
//   alpha 0 is the minified `transparent`;
// - no hex color in site/src/ outside src/styles/tokens.css (4.6);
// - no text-wrap: pretty or balance (4.4);
// - word-break: keep-all or auto-phrase only for the h2 of Japanese pages
//   and the labels of diagrams (4.4);
// - transitions only of color, background color, border color, opacity
//   and transform, for 200 ms or less, no transition-property: all, and no
//   animation of top, left, width or height (4.8);
// - no element with the class is-terminal on any page (4.6);
// - no external font URL in the built CSS or HTML (4.4).
//
//   node scripts/check-css.mjs [--dist DIR]
import fs from 'node:fs';
import path from 'node:path';
import postcss from 'postcss';
import { TOKENS_CSS, SITE_ROOT } from './lib/tokens.mjs';

function args() {
  const a = process.argv.slice(2);
  const out = { dist: path.join(SITE_ROOT, 'dist') };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist') out.dist = path.resolve(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

const HEX = /#[0-9a-fA-F]{3,8}\b/g;
const normal = (h) => {
  h = h.toLowerCase().slice(1);
  if (h.length === 3 || h.length === 4) h = [...h].map((c) => c + c).join('');
  return '#' + h;
};
const transparent = (h) => {
  const n = normal(h);
  return n.length === 9 && n.endsWith('00');
};
// 4.8: the properties that may move, as computed names
const MOVING = new Set(['color', 'background-color', 'border-color', 'border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color', 'outline-color', 'text-decoration-color', 'opacity', 'transform']);
// Declarations of Starlight's and Pagefind's stylesheets that this check
// lets pass, each with the reason. Nothing that a checked page renders.
const EXEMPT = [
  {
    selector: /\.pagefind-ui__filter-value/,
    prop: /^transition/,
    reason: "Pagefind's filter checkbox, which Starlight's search does not show (the index has no filters)",
  },
  {
    selector: /^\.expressive-code \.copy button$/,
    prop: /^transition-property$/,
    reason: 'Expressive Code\'s copy button, whose stylesheet does not go through the build\'s PostCSS; site.css sets opacity, background-color and border-color, and check-styles.mjs checks the computed value',
  },
];

function walk(dir, ext, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, ext, out);
    else if (ext.test(e.name)) out.push(p);
  }
  return out;
}

function times(value) {
  return [...value.matchAll(/(?<![\w-])(-?[0-9.]+)(ms|s)\b/g)].map((m) => parseFloat(m[1]) * (m[2] === 's' ? 1000 : 1));
}

function main() {
  const opt = args();
  const problems = [];
  const exempted = new Map();
  const tokenRoot = postcss.parse(fs.readFileSync(TOKENS_CSS, 'utf8'));
  const tokenDecls = new Set();
  tokenRoot.walkDecls((d) => {
    for (const m of d.value.matchAll(HEX)) tokenDecls.add(`${d.prop}:${normal(m[0])}`);
  });

  // The built CSS: the files under _astro/ and the <style> elements of the pages
  const sheets = walk(path.join(opt.dist, '_astro'), /\.css$/).map((f) => ({ name: path.relative(opt.dist, f), css: fs.readFileSync(f, 'utf8') }));
  const pages = walk(opt.dist, /\.html$/);
  const inline = new Map();
  for (const p of pages) {
    const html = fs.readFileSync(p, 'utf8');
    for (const m of html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) if (!inline.has(m[1])) inline.set(m[1], path.relative(opt.dist, p));
    if (/class="[^"]*\bis-terminal\b/.test(html)) problems.push(`${path.relative(opt.dist, p)}: an element with the class is-terminal (a terminal frame; 4.3 item 1, 4.6)`);
    for (const m of html.matchAll(/<link\b[^>]*>/g)) {
      const tag = m[0];
      if (/rel="(stylesheet|preload|preconnect|dns-prefetch)"/.test(tag) && /href="(https?:)?\/\//.test(tag)) problems.push(`${path.relative(opt.dist, p)}: a link to another host: ${tag}`);
    }
    if (/fonts\.(googleapis|gstatic)\.com|use\.typekit|fonts\.bunny/.test(html)) problems.push(`${path.relative(opt.dist, p)}: names a hosted font service`);
  }
  for (const [css, page] of inline) sheets.push({ name: `<style> of ${page}`, css });

  for (const { name, css } of sheets) {
    const ec = /^_astro\/ec\.[^/]+\.css$/.test(name);
    const root = postcss.parse(css);
    root.walkAtRules('font-face', (r) => {
      r.walkDecls('src', (d) => {
        if (/url\(\s*["']?(https?:)?\/\//.test(d.value)) problems.push(`${name}: @font-face loads a font from another host: ${d.value.slice(0, 120)}`);
      });
    });
    root.walkAtRules('import', (r) => {
      if (/(https?:)?\/\//.test(r.params)) problems.push(`${name}: @import from another host: ${r.params}`);
    });
    root.walkAtRules(/keyframes$/, (r) => {
      r.walkDecls((d) => {
        if (/^(top|left|width|height)$/.test(d.prop)) problems.push(`${name}: @keyframes ${r.params} animates ${d.prop} (4.8)`);
      });
    });
    root.walkDecls((d) => {
      const sel = d.parent.type === 'rule' ? d.parent.selector : `@${d.parent.name} ${d.parent.params ?? ''}`;
      const where = `${name}: ${sel.slice(0, 100)} { ${d.prop}: ${d.value.slice(0, 80)} }`;
      const ex = EXEMPT.find((e) => e.selector.test(sel) && e.prop.test(d.prop));
      const report = (msg) => {
        if (ex) exempted.set(`${sel.slice(0, 80)} ${d.prop}`, ex.reason);
        else problems.push(`${where}: ${msg}`);
      };
      if (!ec) {
        for (const m of d.value.matchAll(HEX)) {
          if (transparent(m[0])) continue;
          if (!tokenDecls.has(`${d.prop}:${normal(m[0])}`)) report(`hex color ${m[0]} outside tokens.css (4.6)`);
        }
      }
      if (/^text-wrap(-style)?$/.test(d.prop) && /\b(pretty|balance)\b/.test(d.value)) report('text-wrap pretty or balance (4.4)');
      if (d.prop === 'word-break' && /keep-all|auto-phrase/.test(d.value)) {
        const ok = sel.split(',').every((s) => /\[lang=["']?ja["']?\][^,]*\bh2\b/.test(s) || /\.(box|note)\b/.test(s));
        if (!ok) report(`${d.value} outside the h2 of Japanese pages and diagram labels (4.4)`);
      }
      if (d.prop === 'transition' || d.prop === 'transition-property') {
        for (const item of d.value.split(',')) {
          const words = item.trim().split(/\s+/);
          const prop = d.prop === 'transition-property' ? words[0] : words.find((w) => !/^(-?[0-9.]+m?s|ease.*|linear|step.*|cubic-bezier\(.*|allow-discrete|normal)$/.test(w));
          if (!prop || /^(none|inherit|initial|unset|var\()/.test(prop)) continue;
          if (prop === 'all') report('transition of all (4.8)');
          else if (!MOVING.has(prop)) report(`transition of ${prop}, not one of color, background color, border color, opacity and transform (4.8)`);
        }
      }
      if (/^(transition|transition-duration|animation|animation-duration|transition-delay|animation-delay)$/.test(d.prop)) {
        const long = times(d.value).filter((t) => t > 200);
        if (long.length) report(`${long[0]} ms, over 200 ms (4.8)`);
      }
    });
  }

  // Component CSS: no hex outside tokens.css (4.6)
  for (const f of walk(path.join(SITE_ROOT, 'src'), /\.(css|astro|mjs|js|ts|mdx)$/)) {
    if (path.resolve(f) === path.resolve(TOKENS_CSS)) continue;
    const text = fs.readFileSync(f, 'utf8');
    for (const m of text.matchAll(/(?<![&\w])#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?(?:[0-9a-fA-F]{2})?\b(?![-\w])/g)) {
      const line = text.slice(0, m.index).split('\n').length;
      const lineText = text.split('\n')[line - 1];
      // ids in links and selectors (href="#x", .a#b) are not colors
      if (/href=|id=|slug:|#_top|#[a-z]/i.test(m[0].slice(1)) && !/^#[0-9a-f]+$/i.test(m[0])) continue;
      if (/(color|background|border|fill|stroke|outline|shadow|:\s*#)/i.test(lineText)) problems.push(`${path.relative(SITE_ROOT, f)}:${line}: hex color ${m[0]} outside tokens.css (4.6)`);
    }
  }

  for (const [what, why] of exempted) console.log(`exempt: ${what}: ${why}`);
  for (const p of problems) console.log(p);
  if (problems.length) {
    console.log(`check-css: ${problems.length} problem(s); ${sheets.length} stylesheets and ${pages.length} pages checked`);
    process.exit(1);
  }
  console.log(`check-css: ok; ${sheets.length} stylesheets and ${pages.length} pages checked, ${exempted.size} declaration(s) exempt`);
}

main();
