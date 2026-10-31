import assert from 'node:assert/strict';
import http from 'node:http';
import { chromium } from 'playwright';
import { readOnlyContext } from './lib/read-only-browser.mjs';

const requests = [];
const server = http.createServer((request, response) => {
  requests.push(`${request.method} ${request.url}`);
  if (request.url === '/redirect') {
    response.writeHead(302, { location: `http://localhost:${server.address().port}/off-origin-redirect` });
    response.end();
    return;
  }
  response.setHeader('content-type', 'text/html');
  response.end('<!doctype html><title>Read-only verification fixture</title>');
});
server.on('upgrade', (_request, socket) => { requests.push('UPGRADE'); socket.destroy(); });
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const badgeRequests = [];
const badgeServer = http.createServer((request, response) => {
  badgeRequests.push(`${request.method} ${request.url}`);
  if (request.url === '/badge-redirect.svg') {
    response.writeHead(302, { location: '/redirect-target.svg' }).end();
    return;
  }
  response.writeHead(200, { 'content-type': 'image/svg+xml' });
  response.end('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>');
});
await new Promise(resolve => badgeServer.listen(0, '127.0.0.1', resolve));
const external = `http://127.0.0.1:${badgeServer.address().port}`;
let browser;
try {
  browser = await chromium.launch();
  const { context, blocked } = await readOnlyContext(browser, origin);
  try {
    const page = await context.newPage();
    await page.goto(origin);
    await page.evaluate(async origin => {
      await fetch('/write', { method: 'POST', body: 'fixture' }).catch(() => {});
      await fetch(origin.replace('127.0.0.1', 'localhost') + '/off-origin').catch(() => {});
      await fetch('/redirect').catch(() => {});
      await navigator.serviceWorker.register('/worker.js').catch(() => {});
      await new Promise(resolve => {
        const socket = new WebSocket(origin.replace('http:', 'ws:') + '/socket');
        socket.onclose = resolve;
        socket.onerror = resolve;
      });
    }, origin);
    assert.equal(blocked.length, 4, 'POST, off-origin GET, redirect and WebSocket are blocked');
    assert.ok(blocked.some(item => item.startsWith('POST ')));
    assert.ok(blocked.some(item => item.startsWith('GET ')));
    assert.ok(blocked.some(item => item.startsWith('WebSocket ')));
    assert.ok(blocked.some(item => item.startsWith('Redirect ')));
    assert.ok(!requests.some(item => /write|off-origin|worker|UPGRADE/.test(item)), 'no rejected traffic reaches the server');
    assert.equal(context.serviceWorkers().length, 0);
  } finally {
    await context.close();
  }
  const badge = external + '/badge.svg';
  const redirected = external + '/badge-redirect.svg';
  const allowed = await readOnlyContext(browser, origin, {}, [badge, redirected]);
  try {
    const page = await allowed.context.newPage();
    await page.goto(origin);
    const loaded = await page.evaluate(async ({ badge, redirected }) => {
      const image = src => new Promise(resolve => {
        const img = document.createElement('img');
        img.onload = () => { const ok = img.naturalWidth > 0; img.remove(); resolve(ok); };
        img.onerror = () => { img.remove(); resolve(false); };
        img.src = src;
        document.body.append(img);
      });
      const ok = await image(badge);
      await fetch(badge).catch(() => {});
      for (const method of ['POST', 'HEAD']) await fetch(badge, { method }).catch(() => {});
      await new Promise(resolve => {
        const script = document.createElement('script');
        script.onload = script.onerror = () => { script.remove(); resolve(); };
        script.src = badge;
        document.body.append(script);
      });
      const nearMiss = await image(badge + '?other=1');
      const redirect = await image(redirected);
      return { ok, nearMiss, redirect };
    }, { badge, redirected });
    assert.deepEqual(loaded, { ok: true, nearMiss: false, redirect: false });
    const otherPage = await allowed.context.newPage();
    await assert.rejects(() => otherPage.goto(badge), 'a document at the image URL stays blocked');
    await otherPage.close();
    assert.equal(allowed.blocked.length, 7, 'fetch, POST, HEAD, script, near-miss image, redirect and document blocked');
    assert.deepEqual(badgeRequests, ['GET /badge.svg', 'GET /badge-redirect.svg'], 'only the exact image GET reaches the external server; no redirect follow-up');
  } finally { await allowed.context.close(); }
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
  await new Promise(resolve => badgeServer.close(resolve));
}
console.log('test-read-only-browser: opted-in exact external image GET accepted, non-image/method/URL/redirect negatives passed; same-origin GET accepted; POST, off-origin GET, redirect follow-up, service worker and WebSocket rejected without server traffic');
