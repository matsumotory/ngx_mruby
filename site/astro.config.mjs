// The ngx.mruby.org site: Astro with Starlight, built from docs/
// (docs/proposals/site.md, section 5). scripts/sync-docs.mjs writes the
// pages of docs/ before the build; the home pages are
// src/content/docs/index.mdx and ja/index.mdx. The design of section 4
// comes from src/styles/tokens.css: Starlight's colors, Expressive Code's
// themes and frames, the type scale, spacing, radii and durations are set
// from it. The stylesheets of the diagrams of 3.5 are the CSS files of
// src/diagrams/.
import fs from 'node:fs';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { SITE_URL } from './scripts/lib/site.mjs';
import themeColors from './scripts/lib/postcss-theme-colors.mjs';

const diagramCss = fs
  .readdirSync(new URL('./src/diagrams/', import.meta.url))
  .filter((f) => f.endsWith('.css'))
  .sort((a, b) => (a === 'diagrams.css' ? -1 : b === 'diagrams.css' ? 1 : a.localeCompare(b)))
  .map((f) => `./src/diagrams/${f}`);

export default defineConfig({
  site: SITE_URL,
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
      // The pages of docs/ carry the date of the last commit to their
      // source in their front matter (scripts/sync-docs.mjs); the footer
      // gives the home pages the date of the last commit to their MDX file.
      // The fonts are served by the site from the Fontsource packages
      // (4.4, 4.12 item 2); tokens.css and site.css come after them.
      customCss: [
        '@fontsource-variable/inter',
        '@fontsource-variable/noto-sans-jp',
        '@fontsource-variable/geist-mono',
        './src/styles/tokens.css',
        './src/styles/site.css',
        ...diagramCss,
      ],
      // The sidebar shows the four kinds of page of 3.1 (Start, Guides,
      // Reference, Concepts), then Releases, Security and Contributing (3.2). The
      // routes come from the paths under docs/ and from SOURCE_ROUTES of
      // scripts/lib/site.mjs; SIDEBAR_ORDER there orders a group.
      sidebar: [
        { label: 'Overview', translations: { ja: '概要' }, slug: 'docs' },
        { label: 'Start', translations: { ja: 'はじめに' }, slug: 'start' },
        { label: 'Guides', translations: { ja: 'ガイド' }, items: [{ autogenerate: { directory: 'guides' } }] },
        { label: 'Reference', translations: { ja: 'リファレンス' }, items: [{ autogenerate: { directory: 'reference' } }] },
        { label: 'Concepts', translations: { ja: 'コンセプト' }, items: [{ autogenerate: { directory: 'concepts' } }] },
        { label: 'Releases', translations: { ja: 'リリース' }, items: [{ autogenerate: { directory: 'releases' } }] },
        { label: 'Security', translations: { ja: 'セキュリティ' }, items: [{ autogenerate: { directory: 'security' } }] },
        { label: 'Contributing', translations: { ja: '開発に参加する' }, items: [{ autogenerate: { directory: 'contributing' } }] },
      ],
      components: {
        Banner: './src/components/Banner.astro',
        FallbackContentNotice: './src/components/FallbackContentNotice.astro',
        Footer: './src/components/Footer.astro',
        Header: './src/components/Header.astro',
        MobileMenuFooter: './src/components/MobileMenuFooter.astro',
        PageFrame: './src/components/PageFrame.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      // Expressive Code's options are in ec.config.mjs (4.6 "Code blocks"),
      // because the <Code> component of the home pages needs them there.
    }),
  ],
});
