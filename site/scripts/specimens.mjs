// Screenshots of the specimens of step 2 (docs/proposals/site.md, 4.12):
// the home page and the reference page, light and dark, at 390 by 664 and
// 1440 by 900 px, in Chromium and WebKit, one set per choice of 4.12.
//
//   node scripts/specimens.mjs [--out DIR] [--set ID ...]
//
// It reads dist-specimens/ and dist-specimens-b/, the builds of
// `SITE_SPECIMENS=1 npm run build` and of the same with
// SITE_CODE_PALETTE=b, and writes DIR/<set>/<engine>-<page>-<lang>-<theme>-<size>.png
// -first.png (the first screen) and -full.png (the whole page)
// (default DIR: build-specimens/) and DIR/index.md, the list of the files
// with the choice each set shows. Each set changes one choice of 4.12 from
// the recommended set, by attributes of <html> that tokens.css and
// src/specimens/specimens.css read.
import fs from 'node:fs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';

const SITE = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

export const SETS = [
  {
    id: 'recommended',
    choice: 'The four recommendations of 4.12: palette A, Geist Mono, code blocks at 12 px, the means of 4.3',
    attrs: {},
    langs: ['en', 'ja'],
  },
  { id: 'palette-b', choice: '4.12 item 1, the alternative: palette B (the three sites\' warm neutrals with the teal accent)', attrs: { palette: 'b' }, dist: 'b' },
  { id: 'mono-system', choice: '4.12 item 2, the alternative: the system monospace stack alone', attrs: { mono: 'system' } },
  { id: 'radius-8', choice: '4.12 item 3, the alternative: code blocks at 8 px', attrs: { radius: '8' } },
  { id: 'radius-0', choice: '4.12 item 3, the alternative: code blocks at 0 px', attrs: { radius: '0' } },
  { id: 'cyber-mono-headings', choice: '4.12 item 4, one step further: the monospace face for h1 and h2 on English pages', attrs: { cyber: 'mono-headings' } },
  { id: 'cyber-dark-hero', choice: '4.12 item 4, the other step further: a dark first screen on the home page in both themes', attrs: { cyber: 'dark-hero' } },
  {
    id: 'cyber-step-back',
    choice: "4.12 item 4, the step back: the gold accent with palette B's neutrals, the header shadow and the entrance motion of the corporate site",
    attrs: { cyber: 'back', palette: 'b', accent: 'gold' },
    dist: 'b',
  },
];
export const PAGES = ['home', 'reference'];
export const THEMES = ['light', 'dark'];
export const SIZES = [
  { width: 390, height: 664 },
  { width: 1440, height: 900 },
];
export const ENGINES = { chromium, webkit };

function args() {
  const a = process.argv.slice(2);
  const out = { out: path.join(SITE, 'build-specimens'), sets: [] };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--out') out.out = path.resolve(a[++i]);
    else if (a[i] === '--set') out.sets.push(a[++i]);
    else throw new Error(`unknown argument ${a[i]}`);
  }
  return out;
}

async function main() {
  const opt = args();
  const sets = opt.sets.length ? SETS.filter((s) => opt.sets.includes(s.id)) : SETS;
  const servers = {};
  for (const d of new Set(sets.map((s) => s.dist ?? 'a'))) {
    const dir = path.join(SITE, d === 'b' ? 'dist-specimens-b' : 'dist-specimens');
    if (!fs.existsSync(path.join(dir, 'specimens/home/index.html'))) throw new Error(`${dir} has no specimen pages: build it first`);
    servers[d] = await serve(dir);
  }
  const lines = ['# Specimens of step 2 (docs/proposals/site.md, 4.12)', ''];
  let count = 0;
  for (const [engineName, engine] of Object.entries(ENGINES)) {
    const browser = await engine.launch();
    for (const set of sets) {
      const dir = path.join(opt.out, set.id);
      fs.mkdirSync(dir, { recursive: true });
      for (const lang of set.langs ?? ['en']) {
        for (const page of PAGES) {
          for (const theme of THEMES) {
            for (const size of SIZES) {
              const context = await browser.newContext({ viewport: size, colorScheme: theme, deviceScaleFactor: size.width < 640 ? 2 : 1 });
              const tab = await context.newPage();
              const url = `${servers[set.dist ?? 'a'].url}${lang === 'ja' ? '/ja' : ''}/specimens/${page}/`;
              await tab.goto(url, { waitUntil: 'load' });
              await tab.evaluate((attrs) => {
                for (const [k, v] of Object.entries(attrs)) document.documentElement.setAttribute(`data-${k}`, v);
              }, set.attrs);
              await tab.evaluate(() => document.fonts.ready);
              // The entrance motion of the step back lasts 0.5 s.
              await tab.waitForTimeout(set.attrs.cyber === 'back' ? 900 : 150);
              // The first screen at the size of 4.12, and the whole page. In
              // the whole page, Starlight's fixed header and sidebar keep
              // the height of the first screen.
              const base = `${engineName}-${page}-${lang}-${theme}-${size.width}x${size.height}`;
              await tab.screenshot({ path: path.join(dir, `${base}-first.png`) });
              await tab.screenshot({ path: path.join(dir, `${base}-full.png`), fullPage: true });
              await context.close();
              count += 2;
            }
          }
        }
      }
    }
    await browser.close();
  }
  // 4.12 item 2: Geist Mono stays if it tells 0 from O and 1 from l and I,
  // and if its x-height at 15 px is not larger than Inter's at 16 px.
  {
    const browser = await chromium.launch();
    const tab = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    await tab.goto(`${servers[Object.keys(servers)[0]].url}/specimens/reference/`, { waitUntil: 'load' });
    const m = await tab.evaluate(async () => {
      await document.fonts.load('15px "Geist Mono Variable"', 'x0O1lI');
      await document.fonts.load('16px "Inter Variable"', 'x');
      const c = document.createElement('canvas').getContext('2d');
      const xh = (font) => {
        c.font = font;
        return c.measureText('x').actualBoundingBoxAscent;
      };
      const div = document.createElement('div');
      div.id = 'glyphs';
      div.style.cssText = 'position:fixed;inset:0 auto auto 0;z-index:99;padding:16px;background:var(--color-bg-primary);color:var(--color-text-primary);font-size:15px;line-height:1.7';
      div.innerHTML = '<div style="font-family:var(--font-mono)">Geist Mono 15 px: 0O 1lI rn m 5S 8B {}[]() mruby_output_body_filter</div>' +
        '<div style="font-family:SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace">System stack 15 px: 0O 1lI rn m 5S 8B {}[]() mruby_output_body_filter</div>' +
        '<div style="font-family:var(--font-latin);font-size:16px">Inter 16 px: 0O 1lI rn m 5S 8B x the prose around inline code</div>';
      document.body.append(div);
      return { geist15: xh('15px "Geist Mono Variable"'), inter16: xh('16px "Inter Variable"') };
    });
    await tab.locator('#glyphs').screenshot({ path: path.join(opt.out, 'glyphs.png') });
    await browser.close();
    const verdict = m.geist15 <= m.inter16 ? 'not larger' : 'larger';
    lines.push('## Monospace face (4.12 item 2)', '', `x-height in Chromium: Geist Mono at 15 px ${m.geist15.toFixed(2)} px, Inter at 16 px ${m.inter16.toFixed(2)} px: ${verdict}. The glyphs 0 O 1 l I side by side: glyphs.png.`, '');
    console.log(`specimens: x-height of Geist Mono at 15 px ${m.geist15.toFixed(2)} px, of Inter at 16 px ${m.inter16.toFixed(2)} px (${verdict})`);
  }
  // One contact sheet per set (sheets/<set>.png): the first screens of
  // both pages in Chromium, light and dark, at both sizes, so that a set
  // can be judged from one image.
  {
    const browser = await chromium.launch();
    fs.mkdirSync(path.join(opt.out, 'sheets'), { recursive: true });
    for (const set of sets) {
      const img = (page, theme, size, lang = 'en') => {
        const f = path.join(opt.out, set.id, `chromium-${page}-${lang}-${theme}-${size}-first.png`);
        return `data:image/png;base64,${fs.readFileSync(f).toString('base64')}`;
      };
      const rows = PAGES.map(
        (page) =>
          `<div class="row"><p>${page}</p>` +
          THEMES.map((t) => `<figure><img class="wide" src="${img(page, t, '1440x900')}"><figcaption>${t}, 1440 by 900</figcaption></figure>`).join('') +
          THEMES.map((t) => `<figure><img class="narrow" src="${img(page, t, '390x664')}"><figcaption>${t}, 390 by 664</figcaption></figure>`).join('') +
          '</div>',
      ).join('');
      const tab = await browser.newPage({ viewport: { width: 1480, height: 800 } });
      await tab.setContent(
        `<style>body{margin:16px;font:14px/1.5 sans-serif;background:#fff;color:#111}h1{font-size:16px;margin:0 0 8px}.row{display:flex;gap:12px;align-items:flex-start;margin-bottom:12px}.row>p{writing-mode:vertical-rl;margin:0}figure{margin:0}img{display:block;border:1px solid #888}.wide{width:480px}.narrow{width:180px}figcaption{font-size:12px}</style><h1>${set.id}: ${set.choice}</h1>${rows}`,
      );
      await tab.screenshot({ path: path.join(opt.out, 'sheets', `${set.id}.png`), fullPage: true });
      await tab.close();
    }
    await browser.close();
    lines.push('## Contact sheets', '', 'sheets/<set>.png: the first screens of both pages in Chromium, light and dark, at both sizes.', '');
  }
  for (const set of sets) {
    lines.push(`## ${set.id}`, '', set.choice, '');
    for (const f of fs.readdirSync(path.join(opt.out, set.id)).filter((x) => x.endsWith('.png')).sort()) lines.push(`- ${set.id}/${f}`);
    lines.push('');
  }
  fs.writeFileSync(path.join(opt.out, 'index.md'), lines.join('\n'));
  for (const s of Object.values(servers)) await s.close();
  console.log(`specimens: ${count} screenshots of ${sets.length} set(s) in ${opt.out}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
