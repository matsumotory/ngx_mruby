// Normalize only Pagefind UI colors through the site tokens.
const PAGEFIND = /node_modules[\\/]@pagefind[\\/]default-ui[\\/]/;
const COLOR = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(/i;

export const removed = [];

export default function themeColors() {
  return {
    postcssPlugin: 'ngx-mruby-theme-colors',
    Declaration(decl) {
      const file = decl.source?.input?.file ?? decl.root()?.source?.input?.file ?? '';
      if (!PAGEFIND.test(file)) return;
      // Pagefind draws the tick of its filter checkbox in #fff, its
      // default background: the site's background instead.
      // Pagefind animates the width and height of the tick of its filter
      // checkbox, which 4.8 rules out and the site's search does not show
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
