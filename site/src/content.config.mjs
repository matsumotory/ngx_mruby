// Starlight's docs collection: the pages that scripts/sync-docs.mjs writes
// under src/content/docs/, and the home pages index.mdx and
// ja/index.mdx beside them.
//
// headline: the lines of the Japanese home page heading (PageTitle.astro),
// one phrase per line, which joined give the title (4.4).
import { glob } from 'astro/loaders';
import { ownSchema } from './own/schema.mjs';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { defineCollection, z } from 'astro:content';

export const collections = {
  docs: defineCollection({
    loader: process.env.NGX_MRUBY_SITE_SHELL === 'own' ? glob({ base: './src/content/docs', pattern: '**/[^_]*.{md,mdx}' }) : docsLoader(),
    schema: process.env.NGX_MRUBY_SITE_SHELL === 'own' ? ownSchema : docsSchema({ extend: z.object({ headline: z.array(z.string().min(1)).min(2).optional() }) }),
  }),
};
