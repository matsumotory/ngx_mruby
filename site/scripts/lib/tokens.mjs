// Reads the color tokens of src/styles/tokens.css (docs/proposals/site.md,
// 4.6), for the Expressive Code themes (code-themes.mjs) and the checks.
// scripts/contrast.py reads the same file on its own, without Node.js.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postcss from 'postcss';

// This module runs from scripts/lib/, and also bundled into Astro's build
// output (through ec.config.mjs), where import.meta.url points elsewhere;
// the build runs in site/.
const here = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const SITE_ROOT = fs.existsSync(path.join(here, 'src/styles/tokens.css')) ? here : process.cwd();
export const TOKENS_CSS = path.join(SITE_ROOT, 'src/styles/tokens.css');

// The selector of each block of tokens.css, by palette, theme and place.
// The two dark blocks of a palette (the media query and the forced dark
// theme) must hold the same values; contrast.py checks that.
export const BLOCKS = {
  'a-light': { selector: ':root', media: false },
  'a-dark': { selector: ':root[data-theme="dark"][data-theme-script]', media: false },
  'a-dark-media': { selector: ':root:not([data-theme="light"])', media: true },
  'b-light': { selector: ':root[data-palette="b"]', media: false },
  'b-dark': { selector: ':root[data-palette="b"][data-theme="dark"][data-theme-script]', media: false },
  'b-dark-media': { selector: ':root[data-palette="b"]:not([data-theme="light"])', media: true },
  'gold-light': { selector: ':root[data-palette="b"][data-accent="gold"]', media: false },
  'gold-dark': {
    selector: ':root[data-palette="b"][data-accent="gold"][data-theme="dark"][data-theme-script]',
    media: false,
  },
};

const HEX = /^#[0-9a-f]{6}$/;

/** The hex color declarations (--color-*) of each block of tokens.css. */
export function readTokenBlocks(file = TOKENS_CSS) {
  const root = postcss.parse(fs.readFileSync(file, 'utf8'), { from: file });
  const found = {};
  root.walkRules((rule) => {
    const media = rule.parent?.type === 'atrule' && rule.parent.name === 'media';
    for (const [name, b] of Object.entries(BLOCKS)) {
      if (rule.selector !== b.selector || media !== b.media) continue;
      found[name] ??= {};
      rule.walkDecls(/^--color-/, (d) => {
        const v = d.value.trim().toLowerCase();
        if (!HEX.test(v)) throw new Error(`${file}: ${rule.selector} ${d.prop}: ${d.value} is not a 6-digit hex color`);
        found[name][d.prop] = v;
      });
    }
  });
  return found;
}

/**
 * The full color set of a palette and theme: palette B and the gold take
 * the values they do not set from palette A, as the cascade does.
 */
export function paletteColors(palette = 'a', theme = 'light', file = TOKENS_CSS) {
  const blocks = readTokenBlocks(file);
  const out = { ...blocks[`a-${theme}`] };
  if (palette === 'b' || palette === 'gold') Object.assign(out, blocks[`b-${theme}`]);
  if (palette === 'gold') Object.assign(out, blocks[`gold-${theme}`]);
  return out;
}
