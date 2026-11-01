// Expressive Code's options for the site's code blocks
// (docs/proposals/site.md, 4.6 "Code blocks"). The themes are written from
// src/styles/tokens.css by scripts/lib/code-themes.mjs.
import { defineEcConfig } from 'astro-expressive-code';
import { pluginFramesTexts } from '@expressive-code/plugin-frames';
import { addClassName } from 'astro-expressive-code/hast';
pluginFramesTexts.addLocale('ja', { copyButtonTooltip: 'クリップボードにコピー', copyButtonCopied: 'コピーしました！' });
import { codeThemes } from './scripts/lib/code-themes.mjs';
import { applySiteUiThemeColors, createBlockLocale } from './scripts/lib/expressive-code-compat.mjs';

export default defineEcConfig({
  themes: codeThemes(),
  // Keep the colors of the themes as written; scripts/contrast.py is
  // the gate for their contrast.
  minSyntaxHighlightingColorContrast: 0,
  // Draw the frame directly from the site tokens.
  ...{
    defaultLocale:'en',cascadeLayer:'site.components',
    customizeTheme: applySiteUiThemeColors,
    getBlockLocale: createBlockLocale(new URL('./src/content/docs/', import.meta.url)),
    plugins:[{name:'Site block classes',hooks:{postprocessRenderedBlock:({renderData})=>addClassName(renderData.blockAst,'not-content')}}],
  },
  // No terminal window (4.3 item 1): every block is a code frame,
  // and a title such as nginx.conf is one flat row of text.
  // Wrapping is display-only: copy retains the exact unwrapped source.
  defaultProps: { frame: 'code', wrap: true, preserveIndent: false },
  // Light is the base theme; dark applies under the OS setting
  // without JavaScript, and with data-theme="dark" only once the
  // theme script ran (4.7, tokens.css).
  themeCssSelector: (theme) =>
    theme.type === 'dark' ? "[data-theme='dark'][data-theme-script]" : "[data-theme='light']",
  useDarkModeMediaQuery: true,
  styleOverrides: {
    borderWidth: '1px',
    borderColor: 'var(--color-border)',
    borderRadius: 'var(--radius-code)',
    codeBackground: 'var(--color-bg-tertiary)',
    codeFontFamily: 'var(--font-mono)',
    codeFontSize: 'var(--text-code)',
    codeLineHeight: 'var(--leading-nav)',
    codePaddingBlock: 'var(--space-3)',
    codePaddingInline: 'var(--space-4)',
    uiFontFamily: 'var(--font-body)',
    uiFontSize: 'var(--text-nav)',
    uiLineHeight: 'var(--leading-nav)',
    uiPaddingBlock: 'var(--space-2)',
    uiPaddingInline: 'var(--space-4)',
    scrollbarThumbColor: 'var(--color-border-strong)',
    scrollbarThumbHoverColor: 'var(--color-text-muted)',
    focusBorder: 'var(--color-accent)',
    frames: {
      editorBackground: 'var(--color-bg-tertiary)',
      editorTabBarBackground: 'var(--color-bg-tertiary)',
      editorTabBarBorderColor: 'var(--color-border)',
      editorTabBarBorderBottomColor: 'var(--color-border)',
      editorActiveTabBackground: 'var(--color-bg-tertiary)',
      editorActiveTabForeground: 'var(--color-text-muted)',
      editorActiveTabBorderColor: 'transparent',
      editorActiveTabIndicatorTopColor: 'transparent',
      editorActiveTabIndicatorBottomColor: 'transparent',
      editorActiveTabIndicatorHeight: '0px',
      frameBoxShadowCssValue: 'none',
      inlineButtonBackground: 'var(--color-bg-primary)',
      inlineButtonForeground: 'var(--color-text-primary)',
      inlineButtonBorder: 'var(--color-border-strong)',
      inlineButtonBackgroundIdleOpacity: '1',
      inlineButtonBackgroundHoverOrFocusOpacity: '1',
      inlineButtonBackgroundActiveOpacity: '1',
      tooltipSuccessBackground: 'var(--color-text-primary)',
      tooltipSuccessForeground: 'var(--color-bg-primary)',
    },
    textMarkers: {
      lineDiffIndicatorMarginLeft:'0.25rem',defaultChroma:'45',backgroundOpacity:'60%',
      markBackground: 'var(--color-border)',
      markBorderColor: 'var(--color-border-strong)',
    },
  },
  // Keep every line of a code block in the code. By default Expressive
  // Code takes a first comment that looks like a file name (such as
  // "#User-Agent: curl/7.29.0" in docs/class_and_method/README.md) out
  // of the code and shows it as the title of the frame.
  frames: { extractFileNameFromCode: false },
});
