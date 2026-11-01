// Evidence for every targeted page, including surrounding desktop/mobile space.
import fs from 'node:fs';
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { patternsFor } from './lib/patterns.mjs';
import { scopedPages } from './lib/ci-pages.mjs';
const pages = scopedPages('dist');
if (!pages) throw new Error('targeted screenshots require explicit pages');
const out = process.argv[2] === '--out' ? process.argv[3] : 'build-screenshots';
fs.mkdirSync(out, {recursive:true});
const server = await serve('dist');
try {
  for (const engine of [chromium, webkit]) {
    const browser = await engine.launch();
    try {
      for (const route of pages) for (const {width,height} of patternsFor(engine.name())) for (const colorScheme of ['light','dark']) {
        const context = await browser.newContext({viewport:{width,height},colorScheme});
        try {
          const tab = await context.newPage();
          const response = await tab.goto(server.url+route);
          if (!response?.ok()) throw new Error(`unavailable ${route}`);
          await tab.evaluate(() => document.fonts.ready);
          const name = `${engine.name()}-${route.replaceAll('/','_')}-${width}-${colorScheme}`;
          await tab.screenshot({path:path.join(out,name+'-viewport.png')});
          await tab.screenshot({path:path.join(out,name+'-full.png'),fullPage:true});
        } finally {await context.close();}
      }
    } finally {await browser.close();}
  }
} finally {await server.close();}
