// The two patterns that the layout and wrapping checks of the site measure
// (check-styles.mjs, check-japanese-lines.mjs; "Site design acceptance" in
// docs/proposals/site.md): PC at full screen, 1440 px in Chromium, and
// iPhone Safari, 402 px in WebKit. The owner decided on 2026-11-01 that no
// other width, browser or font combination is added.
// Each engine measures its own pattern only.
export const PC = { engine: 'chromium', width: 1440, height: 900 };
export const PHONE = { engine: 'webkit', width: 390, height: 664 };
export const PATTERNS = [PHONE, PC];
export const patternsFor = (engine) => PATTERNS.filter((p) => p.engine === engine).map(({ width, height }) => ({ width, height }));
