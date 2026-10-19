// The Expressive Code themes of the site, written from the tokens of
// src/styles/tokens.css (docs/proposals/site.md, 4.6 "Code blocks"): every
// syntax color is text, text-muted or one of the four code colors. The
// frame (background, border, title row) comes from the --sl-color-*
// variables and the styleOverrides in astro.config.mjs, not from here.
import { ExpressiveCodeTheme } from 'astro-expressive-code';
import { paletteColors } from './tokens.mjs';

// TextMate scopes of the Shiki grammars that the docs use (nginx, ruby,
// shellsession, sh, json, c), by code color.
const SCOPES = {
  '--color-text-muted': ['comment', 'punctuation.definition.comment', 'string.comment'],
  '--color-code-keyword': [
    'keyword',
    'storage',
    'storage.type',
    'storage.modifier',
    'keyword.control',
    'keyword.other',
    'keyword.directive',
    'entity.name.function.directive',
    'support.function.builtin',
    'support.type.property-name',
  ],
  '--color-code-string': ['string', 'string.quoted', 'string.regexp', 'markup.inline.raw'],
  '--color-code-number': [
    'constant.numeric',
    'constant.language',
    'constant.character',
    'constant.other',
    'variable.other.constant',
    'variable.other.readwrite.instance',
    'variable.other.readwrite.global',
    'support.constant',
    'variable.parameter',
  ],
  '--color-code-name': [
    'entity.name.function',
    'entity.name.class',
    'entity.name.type',
    'entity.name.tag',
    'entity.other.inherited-class',
    'support.class',
    'support.function',
    'entity.name.section',
  ],
};

/** The VS Code theme object of one palette and theme. */
export function codeThemeJson(palette, type) {
  const c = paletteColors(palette, type);
  return {
    name: `ngx-mruby-${palette}-${type}`,
    type,
    colors: {
      'editor.background': c['--color-bg-tertiary'],
      'editor.foreground': c['--color-text-primary'],
    },
    tokenColors: [
      { settings: { foreground: c['--color-text-primary'] } },
      ...Object.entries(SCOPES).map(([token, scope]) => ({ scope, settings: { foreground: c[token] } })),
    ],
  };
}

/** The light and the dark theme, light first: the base theme (4.7). */
export function codeThemes(palette = 'a') {
  return ['light', 'dark'].map((type) =>
    ExpressiveCodeTheme.fromJSONString(JSON.stringify(codeThemeJson(palette, type))),
  );
}

/** The hex values that a highlighted span may carry in a palette. */
export function allowedSpanColors(palette = 'a') {
  const out = new Set();
  for (const type of ['light', 'dark']) {
    const c = paletteColors(palette, type);
    for (const k of ['--color-text-primary', '--color-text-muted', ...Object.keys(SCOPES)]) out.add(c[k]);
  }
  return out;
}
