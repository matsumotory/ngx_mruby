// Starlight's docs collection: the pages that scripts/sync-docs.mjs writes
// under src/content/docs/, and the home pages index.mdx and
// ja/index.mdx beside them.
//
// headline: the lines of the Japanese home page heading (PageTitle.astro),
// one phrase per line, which joined give the title (4.4).
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { defineCollection, z } from 'astro:content';

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    schema: docsSchema({ extend: z.object({ headline: z.array(z.string().min(1)).min(2).optional() }) }),
  }),
};
