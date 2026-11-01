// ngx.mruby.org: Astro routes and repository-owned components.
// The same pipeline builds /v2/ from the master content checkout.
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import expressiveCode from 'astro-expressive-code';
import { satteri, satteriHeadingIdsPlugin } from '@astrojs/markdown-satteri';
import { satteriRtlCodeSupportPlugin, satteriAutolinkHeadingsPlugin } from './src/own/markdown.mjs';
import { SITE_URL, SITE_VERSION } from './scripts/lib/site.mjs';
import themeColors from './scripts/lib/postcss-theme-colors.mjs';
export default defineConfig({
  site: SITE_URL,
  scopedStyleStrategy: 'where',
  prefetch: { prefetchAll: true },
  base: SITE_VERSION === 2 ? '/v2' : undefined,
  i18n: { defaultLocale: 'en', locales: ['en', 'ja'], routing: { prefixDefaultLocale: false } },
  markdown: { processor: satteri({ hastPlugins: [satteriRtlCodeSupportPlugin(), satteriHeadingIdsPlugin(), satteriAutolinkHeadingsPlugin((_key,{title})=>`Section titled “${title}”`)] }) },
  vite: {
    resolve: { alias: { 'virtual:site/Search': fileURLToPath(new URL('./src/own/Search.astro', import.meta.url)) } },
    css: { postcss: { plugins: [themeColors()] } },
  },
  integrations: [expressiveCode(), mdx(), sitemap({ i18n: { defaultLocale: 'en', locales: { en: 'en', ja: 'ja' } }, filter: page=>!page.endsWith('/404/') })],
});
