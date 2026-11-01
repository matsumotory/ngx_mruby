// Render the public sharing image from the same SVG and font as the site.
// Run manually after npm ci and Playwright installation; no network is used.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { SHARE_IMAGE as STABLE_IMAGE, V3_SHARE_IMAGE } from './lib/brand.mjs';
const v3 = process.argv.includes('--v3');
const SHARE_IMAGE = v3 ? V3_SHARE_IMAGE : STABLE_IMAGE;

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const data = (file, mime) => `data:${mime};base64,${fs.readFileSync(path.join(site, file)).toString('base64')}`;
const logo = data(v3 ? 'public/brand/ngx-mruby-llm-proxy.svg' : 'public/brand/ngx-mruby-http.svg', 'image/svg+xml');
const font = data('node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2', 'font/woff2');
const stableHtml = `<!doctype html><html lang="en"><meta charset="utf-8"><style>
@font-face{font-family:Inter;src:url('${font}');font-weight:100 900}
*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;background:#0b1018;color:#e8edf3;font-family:Inter,sans-serif;display:grid;place-items:center;border:1px solid #344151;background-image:linear-gradient(135deg,#1c2635 0%,#101823 35%,#0b1018 66%)}
main{display:flex;align-items:center;gap:56px;width:960px}img{width:280px;height:296px;flex:none}h1{font-size:91px;letter-spacing:-5px;font-weight:650;margin:0 0 24px;line-height:1.05}p{font-size:38px;line-height:1.25;margin:0;color:#b7c3d2}.protocols{margin-top:32px;font-size:25px;letter-spacing:2px;color:#d2b77a}
</style><main><img src="${logo}" alt=""><div><h1>ngx_mruby</h1><p>Ruby inside nginx.</p><p class="protocols">HTTP / STREAM</p></div></main></html>`;
const v3Html = `<!doctype html><html lang="en"><meta charset="utf-8"><style>
@font-face{font-family:Inter;src:url('${font}');font-weight:100 900}
*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;color:#e8ebf1;background:#070a11;font-family:Inter,sans-serif;background-image:linear-gradient(115deg,#223448,#122334 34%,#070a11 82%)}
main{height:630px;padding:72px;display:grid;grid-template-columns:1fr 290px;align-items:center;gap:40px}
h1{font-size:80px;letter-spacing:-4px;font-weight:650;line-height:1.1;margin:0 0 30px}p{font-size:42px;line-height:1.25;margin:0;color:#e8ebf1}.state{font-size:25px;letter-spacing:1px;color:#ecba74;margin-bottom:30px}.runtime{font-size:28px;color:#b7c3d2;margin-top:28px;line-height:1.5}img{width:290px;height:310px}
</style><main><div><p class="state">v3 · IN DEVELOPMENT</p><h1>ngx_mruby</h1><p>Model API routing in nginx.</p><p class="runtime">Rules in Ruby.<br>Keys at your proxy.</p></div><img src="${logo}" alt=""></main></html>`;
const html = v3 ? v3Html : stableHtml;
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
