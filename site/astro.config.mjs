// The ngx.mruby.org site: Astro with Starlight, built from docs/
// (docs/proposals/site.md, section 5). scripts/sync-docs.mjs writes the
// pages before the build. The design of section 4 comes from
// src/styles/tokens.css: Starlight's colors, Expressive Code's themes and
// frames, the type scale, spacing, radii and durations are set from it.
//
// SITE_SPECIMENS=1 adds the specimen pages of step 2 (4.12) under
// /specimens/ and /ja/specimens/ and builds into dist-specimens/; the
// normal build has no specimen page. The browser checks and the
// screenshots run on them, since they hold a diagram, code blocks and
// tables before the pages of step 3 and 4 do.
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { SITE_URL } from './scripts/lib/site.mjs';
import themeColors from './scripts/lib/postcss-theme-colors.mjs';

const specimens = process.env.SITE_SPECIMENS === '1';

/** Injects the specimen pages of 4.12 when SITE_SPECIMENS=1. */
function specimenPages() {
  return {
    name: 'ngx-mruby-specimens',
    hooks: {
      'astro:config:setup': ({ injectRoute }) => {
        if (!specimens) return;
        for (const lang of ['en', 'ja']) {
          const prefix = lang === 'en' ? '' : '/ja';
          for (const page of ['home', 'reference']) {
            injectRoute({
              pattern: `${prefix}/specimens/${page}`,
              entrypoint: `./src/specimens/${page}-${lang}.astro`,
            });
          }
        }
      },
    },
  };
}

export default defineConfig({
  site: SITE_URL,
  outDir: specimens ? './dist-specimens' : './dist',
  vite: {
    css: { postcss: { plugins: [themeColors()] } },
  },
  integrations: [
    starlight({
      title: 'ngx_mruby',
      // A copy of misc/logo.png.
      favicon: '/favicon.png',
      // English at unprefixed paths, Japanese under /ja/ (3.4).
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
        ja: { label: '日本語', lang: 'ja' },
      },
      // The fonts are served by the site from the Fontsource packages
      // (4.4, 4.12 item 2); tokens.css and site.css come after them.
      customCss: [
        '@fontsource-variable/inter',
        '@fontsource-variable/noto-sans-jp',
        '@fontsource-variable/geist-mono',
        './src/styles/tokens.css',
        './src/styles/site.css',
      ],
      components: {
        Banner: './src/components/Banner.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      // Expressive Code's options are in ec.config.mjs (4.6 "Code blocks"),
      // because the <Code> component of the specimens needs them there.
    }),
    specimenPages(),
  ],
});
