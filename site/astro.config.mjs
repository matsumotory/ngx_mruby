// The ngx.mruby.org site: Astro with Starlight, built from docs/
// (docs/proposals/site.md, section 5). scripts/sync-docs.mjs writes the
// pages of docs/ before the build; the home pages are
// src/content/docs/index.mdx and ja/index.mdx. The design of section 4
// comes from src/styles/tokens.css: Starlight's colors, Expressive Code's
// themes and frames, the type scale, spacing, radii and durations are set
// from it. The stylesheets of the diagrams of 3.5 are the CSS files of
// src/diagrams/.
//
// The same configuration builds the 2.x pages under /v2/ from docs/ of
// master (step 6): scripts/build-v2.mjs runs the build in a copy of site/
// with NGX_MRUBY_SITE_VERSION=2, which sets the base /v2/ and the sidebar
// of the 2.x pages, and has its own search index in /v2/pagefind/.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import expressiveCode from 'astro-expressive-code';
import { satteri, satteriHeadingIdsPlugin } from '@astrojs/markdown-satteri';
import ownShell from './src/own/integration.mjs';
import { satteriRtlCodeSupportPlugin, satteriAutolinkHeadingsPlugin } from './src/own/markdown.mjs';
const own = process.env.NGX_MRUBY_SITE_SHELL === 'own';

import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { SITE_URL, SITE_VERSION } from './scripts/lib/site.mjs';
import themeColors from './scripts/lib/postcss-theme-colors.mjs';
import { shareImageForVersion } from './scripts/lib/brand.mjs';
const SHARE_IMAGE = shareImageForVersion(SITE_VERSION);

const diagramCss = fs
  .readdirSync(new URL('./src/diagrams/', import.meta.url))
  .filter((f) => f.endsWith('.css'))
  .sort((a, b) => (a === 'diagrams.css' ? -1 : b === 'diagrams.css' ? 1 : a.localeCompare(b)))
  .map((f) => `./src/diagrams/${f}`);

// The sidebar shows the four kinds of page of 3.1 (Start, Guides,
// Reference, Concepts), then Releases, Security and Contributing (3.2). The
// routes come from the paths under docs/ and from SOURCE_ROUTES of
// scripts/lib/site.mjs; SIDEBAR_ORDER there orders a group. The 2.x pages
// have no Start or Concepts, and their index is /v2/.
const group = (label, ja, directory) => ({ label, translations: { ja }, items: [{ autogenerate: { directory } }] });
const sidebar =
  SITE_VERSION === 2
    ? [
        { label: 'Overview', translations: { ja: '概要' }, slug: 'index' },
        group('Guides', 'ガイド', 'guides'),
        group('Reference', 'リファレンス', 'reference'),
        group('Releases', 'リリース', 'releases'),
        group('Security', 'セキュリティ', 'security'),
        group('Contributing', '開発に参加する', 'contributing'),
      ]
    : [
        { label: 'Overview', translations: { ja: '概要' }, slug: 'docs' },
        { label: 'Start', translations: { ja: 'はじめに' }, slug: 'start' },
        group('Guides', 'ガイド', 'guides'),
        group('Reference', 'リファレンス', 'reference'),
        group('Concepts', 'コンセプト', 'concepts'),
        group('Releases', 'リリース', 'releases'),
        group('Security', 'セキュリティ', 'security'),
        group('Contributing', '開発に参加する', 'contributing'),
      ];

export default defineConfig({
  site: SITE_URL,
  scopedStyleStrategy: 'where',
  prefetch: { prefetchAll: true },
  base: SITE_VERSION === 2 ? '/v2' : undefined,
  ...(own ? { i18n: { defaultLocale: 'en', locales: ['en','ja'], routing: { prefixDefaultLocale: false } },
    markdown: { processor: satteri({ hastPlugins: [satteriRtlCodeSupportPlugin(),satteriHeadingIdsPlugin(),satteriAutolinkHeadingsPlugin((_key,{title})=>`Section titled “${title}”`)] }) } } : {}),
  vite: {
    resolve: { alias: { 'virtual:site/Search': own ? fileURLToPath(new URL('./src/own/Search.astro',import.meta.url)) : 'virtual:starlight/components/Search' } },
    css: { postcss: { plugins: [themeColors()] } },
  },
  integrations: own ? [expressiveCode(),mdx(),sitemap({i18n:{defaultLocale:"en",locales:{en:"en",ja:"ja"}},filter:page=>!page.endsWith("/404/")}),ownShell()] : [
    starlight({
      title: 'ngx_mruby',
      // Flat small-size derivative on an opaque dark tile.
      favicon: '/favicon.svg',
      // Product identity only; each page keeps its own title and canonical URL.
      head: [
        ...Object.entries({
          'og:image': `${SITE_URL}/${SHARE_IMAGE.file}`,
          'og:image:type': SHARE_IMAGE.type,
          'og:image:width': String(SHARE_IMAGE.width),
          'og:image:height': String(SHARE_IMAGE.height),
          'og:image:alt': SHARE_IMAGE.alt,
        }).map(([property, content]) => ({ tag: 'meta', attrs: { property, content } })),
        { tag: 'meta', attrs: { name: 'twitter:image', content: `${SITE_URL}/${SHARE_IMAGE.file}` } },
        { tag: 'meta', attrs: { name: 'twitter:image:alt', content: SHARE_IMAGE.alt } },
      ],
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
      sidebar,
      components: {
        Banner: './src/components/Banner.astro',
        FallbackContentNotice: './src/components/FallbackContentNotice.astro',
        Footer: './src/components/Footer.astro',
        Header: './src/components/Header.astro',
        PageTitle: './src/components/PageTitle.astro',
        MobileMenuFooter: './src/components/MobileMenuFooter.astro',
        PageFrame: './src/components/PageFrame.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
      },
      // Expressive Code's options are in ec.config.mjs (4.6 "Code blocks"),
      // because the <Code> component of the home pages needs them there.
    }),
  ],
});
