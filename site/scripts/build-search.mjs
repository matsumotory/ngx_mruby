import { writeSearchIndex } from './lib/search-index.mjs';
await writeSearchIndex(new URL('../dist/', import.meta.url));
