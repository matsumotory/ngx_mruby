// Render the public sharing image from the same SVG and font as the site.
// Run manually after npm ci and Playwright installation; no network is used.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { SHARE_IMAGE } from './lib/brand.mjs';

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const data = (file, mime) => `data:${mime};base64,${fs.readFileSync(path.join(site, file)).toString('base64')}`;
const logo = data('public/brand/ngx-mruby-http.svg', 'image/svg+xml');
const font = data('node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2', 'font/woff2');
const html = `<!doctype html><html lang="en"><meta charset="utf-8"><style>
@font-face{font-family:Inter;src:url('${font}');font-weight:100 900}
*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;background:#0b1018;color:#e8edf3;font-family:Inter,sans-serif;display:grid;place-items:center;border:1px solid #344151;background-image:linear-gradient(135deg,#1c2635 0%,#101823 35%,#0b1018 66%)}
main{display:flex;align-items:center;gap:56px;width:960px}img{width:280px;height:296px;flex:none}h1{font-size:91px;letter-spacing:-5px;font-weight:650;margin:0 0 24px;line-height:1.05}p{font-size:38px;line-height:1.25;margin:0;color:#b7c3d2}.protocols{margin-top:32px;font-size:25px;letter-spacing:2px;color:#d2b77a}
</style><main><img src="${logo}" alt=""><div><h1>ngx_mruby</h1><p>Ruby inside nginx.</p><p class="protocols">HTTP / STREAM</p></div></main></html>`;
const browser = await chromium.launch();
try {
 const page = await browser.newPage({viewport:{width:SHARE_IMAGE.width,height:SHARE_IMAGE.height},deviceScaleFactor:1});
 await page.route('**/*', route => route.request().url().startsWith('data:') ? route.continue() : route.abort());
 await page.setContent(html);
 await page.evaluate(async () => { await document.fonts.ready; await Promise.all([...document.images].map(i=>i.decode())); });
 const out = path.join(site,'public',SHARE_IMAGE.file);
 await page.screenshot({path:out});
 console.log(`Rendered ${path.relative(site,out)} (1200 x 630)`);
} finally { await browser.close(); }
