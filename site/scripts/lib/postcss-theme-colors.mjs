// A PostCSS plugin for the build (astro.config.mjs, vite.css.postcss):
// removes the color custom properties that Starlight and Pagefind define in
// their own stylesheets (Starlight's gray scale at hue 224, its accent and
// five hue palettes, its badge text #fff and its shadows; Pagefind's UI
// colors), because src/styles/tokens.css defines every one of them from the
// site's tokens (docs/proposals/site.md, 4.6 "Starlight's own colors").
// Without it the minified built CSS would hold Starlight's colors as hex
// beside the tokens, which scripts/check-css.mjs refuses.
//
// Only custom properties whose value holds a color literal are removed;
// the rules that use them stay, and read the values of tokens.css. The one
// color literal of another declaration, the #fff of Pagefind's checkbox
// tick, becomes Pagefind's background variable, and the transition of the
// width and height of that tick goes. Any other color literal is
// left as it is and reported by scripts/check-css.mjs.

const FROM = /node_modules[\\/](?:@astrojs[\\/]starlight|@pagefind[\\/]default-ui)[\\/]/;
const PAGEFIND = /node_modules[\\/]@pagefind[\\/]default-ui[\\/]/;
const COLOR = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(/i;

export const removed = [];

export default function themeColors() {
  return {
    postcssPlugin: 'ngx-mruby-theme-colors',
    Declaration(decl) {
      const file = decl.source?.input?.file ?? decl.root()?.source?.input?.file ?? '';
      if (!FROM.test(file)) return;
      // Pagefind draws the tick of its filter checkbox in #fff, its
      // default background: the site's background instead.
      // Pagefind animates the width and height of the tick of its filter
      // checkbox, which 4.8 rules out and Starlight's search does not show
      // (its index has no filters): the declaration goes.
      if (PAGEFIND.test(file) && /^transition/.test(decl.prop) && /\b(width|height)\b/.test(decl.value)) {
        removed.push(`${file.replace(/^.*node_modules[\\/]/, '')}: ${decl.prop} ${decl.value}`);
        decl.remove();
        return;
      }
      if (!decl.prop.startsWith('--')) {
        if (PAGEFIND.test(file) && /#fff\b/i.test(decl.value)) {
          removed.push(`${file.replace(/^.*node_modules[\\/]/, '')}: ${decl.prop} #fff`);
          decl.value = decl.value.replace(/#fff\b/gi, 'var(--pagefind-ui-background)');
        }
        return;
      }
      if (!COLOR.test(decl.value)) return;
      removed.push(`${file.replace(/^.*node_modules[\\/]/, '')}: ${decl.prop}`);
      decl.remove();
    },
  };
}
themeColors.postcss = true;
