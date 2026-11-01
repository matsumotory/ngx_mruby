import { z } from 'astro/zod';
// Reject generator fields that the shell has not explicitly implemented.
export const ownSchema = z.object({
  title: z.string(), slug: z.string().optional(), description: z.string().optional(),
  headline: z.array(z.string()).optional(), template: z.enum(['doc','splash']).default('doc'),
  lastUpdated: z.union([z.boolean(),z.coerce.date()]).optional(),
  head: z.array(z.object({tag:z.string(),attrs:z.record(z.string(),z.union([z.string(),z.boolean(),z.number()])).optional(),content:z.string().optional()}).strict()).default([]),
  sidebar: z.object({order:z.number().optional(),label:z.string().optional(),hidden:z.boolean().default(false),attrs:z.record(z.string(),z.string()).default({})}).strict().default({hidden:false,attrs:{}}),
  prev:z.union([z.boolean(),z.string(),z.object({label:z.string().optional(),link:z.string().optional()}).strict()]).optional(),
  next:z.union([z.boolean(),z.string(),z.object({label:z.string().optional(),link:z.string().optional()}).strict()]).optional(),
  banner:z.object({content:z.string()}).strict().optional(), identifiers:z.array(z.string()).optional(),
  pagefind:z.boolean().default(true),draft:z.boolean().default(false),
}).strict();
