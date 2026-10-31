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
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}
console.log('test-read-only-browser: same-origin GET accepted; POST, off-origin GET, redirect follow-up, service worker and WebSocket rejected without server traffic');
