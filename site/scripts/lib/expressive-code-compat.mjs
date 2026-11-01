// Compatibility with Starlight 0.42.6 expressive-code/theming.ts.
// MIT attribution: ../../src/components/STARLIGHT-LICENSE.
// Preserve its theme-derived fallback values before ec.config's token overrides;
// the existing PostCSS normalization maps generated CSS colors to site tokens.
import { fileURLToPath } from 'node:url';

export function applySiteUiThemeColors(theme) {
	const isDark = theme.type === "dark";
	const neutralMinimal = isDark ? "#ffffff17" : "#0000001a";
	const neutralDimmed = isDark ? "#ffffff40" : "#00000055";
	const borderColor = "color-mix(in srgb, var(--color-border), transparent 25%)";
	theme.colors["titleBar.border"] = borderColor;
	theme.colors["editorGroupHeader.tabsBorder"] = borderColor;
	const backgroundColor = isDark ? "var(--color-bg-primary)" : "var(--color-bg-tertiary)";
	theme.colors["titleBar.activeBackground"] = backgroundColor;
	theme.colors["editorGroupHeader.tabsBackground"] = backgroundColor;
	theme.colors["titleBar.activeForeground"] = "var(--color-text-primary)";
	theme.colors["tab.activeForeground"] = "var(--color-text-primary)";
	const activeBorderColor = isDark ? "var(--color-accent-text)" : "var(--color-accent)";
	theme.colors["tab.activeBorder"] = "transparent";
	theme.colors["tab.activeBorderTop"] = activeBorderColor;
	theme.colors["scrollbarSlider.background"] = neutralMinimal;
	theme.colors["scrollbarSlider.hoverBackground"] = neutralDimmed;
	theme.bg = isDark ? "#23262f" : "#f6f7f9";
	theme.colors["editor.background"] = theme.bg;
	const editorBackgroundColor = isDark ? "var(--color-bg-tertiary)" : "var(--color-bg-tertiary)";
	theme.styleOverrides.frames = {
		editorBackground: editorBackgroundColor,
		terminalBackground: editorBackgroundColor,
		editorActiveTabBackground: editorBackgroundColor,
		terminalTitlebarDotsForeground: borderColor,
		terminalTitlebarDotsOpacity: "0.75",
		inlineButtonForeground: "var(--color-text-primary)",
		frameBoxShadowCssValue: "none"
	};
	theme.styleOverrides.textMarkers = {
		markBackground: neutralMinimal,
		markBorderColor: neutralDimmed
	};
	return theme;
}

/** Resolve language within the docs collection, never within its checkout path. */
export function createBlockLocale(docsDirectory) {
  const docsPath = (docsDirectory instanceof URL ? fileURLToPath(docsDirectory) : docsDirectory)
    .replace(/\\/g, '/').replace(/\/?$/, '/');
  return ({ file }) => {
    if (file.url && file.url.protocol !== 'file:') {
      return file.url.pathname.slice(1).split('/')[0] === 'ja' ? 'ja' : 'en';
    }
    let path = file.path?.replace(/\\/g, '/');
    // VFile can omit the initial slash even when the collection is absolute.
    if (path && !path.startsWith('/') && docsPath.startsWith('/')) path = '/' + path;
    const slug = path?.startsWith(docsPath) ? path.slice(docsPath.length) : undefined;
    return slug?.split('/')[0] === 'ja' ? 'ja' : 'en';
  };
}
