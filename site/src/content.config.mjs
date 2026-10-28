// Starlight's docs collection: the pages that scripts/sync-docs.mjs writes
// under src/content/docs/, and the home pages index.mdx and
// ja/index.mdx beside them.
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { defineCollection } from 'astro:content';

export const collections = {
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
