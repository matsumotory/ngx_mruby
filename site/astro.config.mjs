// The ngx.mruby.org site: Astro with Starlight, built from docs/
// (docs/proposals/site.md, section 5). Step 1 of section 6 renders today's
// docs/ with Starlight's defaults; the design of section 4 comes with
// step 2. scripts/sync-docs.mjs writes the pages before the build.
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { SITE_URL } from './scripts/lib/site.mjs';

export default defineConfig({
  site: SITE_URL,
  integrations: [
    starlight({
      title: 'ngx_mruby',
      // A copy of misc/logo.png until the design of step 2.
      favicon: '/favicon.png',
      // English at unprefixed paths, Japanese under /ja/ (3.4).
      defaultLocale: 'root',
      locales: {
        root: { label: 'English', lang: 'en' },
        ja: { label: '日本語', lang: 'ja' },
      },
      // Keep every line of a code block in the code. By default Expressive
      // Code takes a first comment that looks like a file name (such as
      // "#User-Agent: curl/7.29.0" in docs/class_and_method/README.md) out
      // of the code and shows it as the title of the frame.
      expressiveCode: { frames: { extractFileNameFromCode: false } },
    }),
  ],
});
