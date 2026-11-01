// Narrow fixtures for the own shell's Starlight 0.42.6 compatibility contract.
import assert from 'node:assert/strict';
import { applySiteUiThemeColors, createBlockLocale } from './lib/expressive-code-compat.mjs';

for (const type of ['light', 'dark']) {
  const dark = type === 'dark';
  const theme = { type, colors: { 'editor.foreground': 'syntax-color' }, styleOverrides: {} };
  assert.equal(applySiteUiThemeColors(theme), theme, 'customization mutates and returns the theme');
  const border = 'color-mix(in srgb, var(--color-border), transparent 25%)';
  const bg = dark ? '#23262f' : '#f6f7f9';
  const minimal = dark ? '#ffffff17' : '#0000001a';
  const dimmed = dark ? '#ffffff40' : '#00000055';
  const editor = dark ? 'var(--color-bg-tertiary)' : 'var(--color-bg-tertiary)';
  const title = dark ? 'var(--color-bg-primary)' : 'var(--color-bg-tertiary)';
  assert.equal(theme.bg, bg);
  assert.deepEqual(theme.colors, {
    'editor.foreground': 'syntax-color',
    'titleBar.border': border,
    'editorGroupHeader.tabsBorder': border,
    'titleBar.activeBackground': title,
    'editorGroupHeader.tabsBackground': title,
    'titleBar.activeForeground': 'var(--color-text-primary)',
    'tab.activeForeground': 'var(--color-text-primary)',
    'tab.activeBorder': 'transparent',
    'tab.activeBorderTop': dark ? 'var(--color-accent-text)' : 'var(--color-accent)',
    'scrollbarSlider.background': minimal,
    'scrollbarSlider.hoverBackground': dimmed,
    'editor.background': bg,
  });
  assert.deepEqual(theme.styleOverrides, {
    frames: {
      editorBackground: editor,
      terminalBackground: editor,
      editorActiveTabBackground: editor,
      terminalTitlebarDotsForeground: border,
      terminalTitlebarDotsOpacity: '0.75',
      inlineButtonForeground: 'var(--color-text-primary)',
      frameBoxShadowCssValue: 'none',
    },
    textMarkers: { markBackground: minimal, markBorderColor: dimmed },
  });
}

// A checkout containing /ja/ must not make its English docs Japanese.
const locale = createBlockLocale(new URL('file:///work/ja/project/site/src/content/docs/'));
for (const [file, expected] of [
  [{ path: '/work/ja/project/site/src/content/docs/install.md' }, 'en'],
  [{ path: '/work/ja/project/site/src/content/docs/ja/install.md' }, 'ja'],
  [{ path: '/work/ja/project/site/src/content/docs/v2/install.md' }, 'en'],
  [{ path: '/work/ja/project/site/src/content/docs/ja/v2/install.md' }, 'ja'],
  [{ path: 'work/ja/project/site/src/content/docs/ja/install.md' }, 'ja'],
  [{ path: '/work/ja/project/site/src/content/docs/guide/ja/example.md' }, 'en'],
  [{ path: '/work/ja/project/site/src/content/docs-extra/ja/install.md' }, 'en'],
  [{ path: '/other/ja/install.md' }, 'en'],
  [{}, 'en'],
  [{ url: new URL('https://ngx.mruby.org/ja/install/') }, 'ja'],
  [{ url: new URL('https://ngx.mruby.org/install/ja/') }, 'en'],
  [{ url: new URL('file:///work/ja/project/site/src/content/docs/install.md'), path: '/work/ja/project/site/src/content/docs/install.md' }, 'en'],
]) assert.equal(locale({ file }), expected, JSON.stringify(file));
const windowsLocale = createBlockLocale('C:\\work\\ja\\site\\src\\content\\docs\\');
assert.equal(windowsLocale({ file: { path: 'C:\\work\\ja\\site\\src\\content\\docs\\index.md' } }), 'en');
assert.equal(windowsLocale({ file: { path: 'C:\\work\\ja\\site\\src\\content\\docs\\ja\\index.md' } }), 'ja');
console.log('Expressive Code compatibility: light/dark theme values and collection-relative locale fixtures passed');
