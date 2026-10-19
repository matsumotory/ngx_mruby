// Expressive Code's options for Starlight's code blocks
// (docs/proposals/site.md, 4.6 "Code blocks"). The themes are written from
// src/styles/tokens.css by scripts/lib/code-themes.mjs.
import { defineEcConfig } from '@astrojs/starlight/expressive-code';
import { codeThemes } from './scripts/lib/code-themes.mjs';

// The palette whose text colors the code themes take. The specimens of
// palette B are built with SITE_CODE_PALETTE=b (into dist-specimens-b/),
// because Expressive Code writes the color of each span into the HTML.
const codePalette = process.env.SITE_CODE_PALETTE === 'b' ? 'b' : 'a';

export default defineEcConfig({
  themes: codeThemes(codePalette),
  // Keep the colors of the themes as written; scripts/contrast.py is
  // the gate for their contrast.
  minSyntaxHighlightingColorContrast: 0,
  // Draw the frame with the --sl-color-* variables of tokens.css.
  useStarlightUiThemeColors: true,
  // No terminal window (4.3 item 1): every block is a code frame,
  // and a title such as nginx.conf is one flat row of text.
  defaultProps: { frame: 'code' },
  // Light is the base theme; dark applies under the OS setting
  // without JavaScript, and with data-theme="dark" only once the
  // theme script ran (4.7, tokens.css).
  themeCssSelector: (theme) =>
    theme.type === 'dark' ? "[data-theme='dark'][data-theme-script]" : "[data-theme='light']",
  useDarkModeMediaQuery: true,
  styleOverrides: {
    borderColor: 'var(--color-border)',
    borderRadius: 'var(--radius-code)',
    codeBackground: 'var(--color-bg-tertiary)',
    codeFontFamily: 'var(--font-mono)',
    codeFontSize: 'var(--text-nav)',
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
