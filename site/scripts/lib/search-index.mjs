import { fileURLToPath } from 'node:url';
import * as pagefind from 'pagefind';
// Index Astro output before mark-num-cells, preserving the original order.
export async function writeSearchIndex(dir, api = pagefind) {
  try {
    const { index, errors } = await api.createIndex({});
    if (errors.length) throw new Error(errors.join('\n'));
    const added = await index.addDirectory({ path: fileURLToPath(dir) });
    if (added.errors.length) throw new Error(added.errors.join('\n'));
    const written = await index.writeFiles({ outputPath: fileURLToPath(new URL('pagefind/', dir)) });
    if (written.errors.length) throw new Error(written.errors.join('\n'));
  } finally {
    await api.close();
  }
}
