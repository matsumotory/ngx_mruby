// Repository-owned strict schema for generated docs and the MDX home pages.
import { glob } from 'astro/loaders';
import { ownSchema } from './own/schema.mjs';
import { defineCollection } from 'astro:content';
export const collections = {
  docs: defineCollection({
    loader: glob({ base: './src/content/docs', pattern: '**/[^_]*.{md,mdx}' }),
    schema: ownSchema,
  }),
};
