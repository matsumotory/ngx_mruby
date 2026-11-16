// Checks the retry of screenshots-live.mjs after a 5xx of the site. A proxy
// in front of the built site (lib/serve.mjs) answers the first .woff2 file
// that a browser asks for with a given status, the first N times, and
// screenshots-live.mjs runs against it as against the published site
// (--origin). Needs dist/ with dist/v2/, as screenshots-live.mjs does.
//   a 503 once: the context is checked again, exit 0, the retry recorded
//   a 503 that stays: exit 1 at the limit of the wait, nothing checked again
//   a 404 once: exit 1 at once, no wait
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { serve } from './lib/serve.mjs';

const site = path.resolve(new URL('..', import.meta.url).pathname);
const dist = path.join(site, 'dist');
const backend = await serve(dist);

async function faultyProxy(status, times) {
  let target = null, injected = 0;
  const seen = [];
  const server = http.createServer((request, response) => {
    if (target === null && request.url.endsWith('.woff2')) target = request.url;
    if (request.url === target) {
      seen.push(request.headers['user-agent'] ?? '');
      if (injected < times) {
        injected++;
        response.writeHead(status, { 'content-type': 'text/plain' }).end('injected');
        return;
      }
    }
    const upstream = http.request(backend.url + request.url, { method: request.method, headers: request.headers }, answer => {
      response.writeHead(answer.statusCode, answer.headers);
      answer.pipe(response);
    });
    request.pipe(upstream);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    state: () => ({ target, injected, seen }),
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }),
  };
}

async function run(name, status, times, waitLimit) {
  const proxy = await faultyProxy(status, times);
  const out = path.join(site, 'build-screenshots', 'test-screenshots-live', name);
  fs.rmSync(out, { recursive: true, force: true });
  const started = Date.now();
  // Asynchronous: the proxy runs in this process while the child runs.
  const child = await new Promise(resolve => {
    const p = spawn(process.execPath, [path.join(site, 'scripts/screenshots-live.mjs'), '--origin', proxy.url, '--wait-limit', String(waitLimit), '--out', out], { cwd: site });
    let stdout = '', stderr = '';
    p.stdout.on('data', d => { stdout += d; });
    p.stderr.on('data', d => { stderr += d; });
    p.on('close', code => resolve({ code, stdout, stderr }));
  });
  const seconds = (Date.now() - started) / 1000;
  const state = proxy.state();
  await proxy.close();
  const evidence = JSON.parse(fs.readFileSync(path.join(out, 'evidence.json'), 'utf8'));
  console.log(`test-screenshots-live: ${name}: exit ${child.code} in ${seconds.toFixed(1)} s; ${state.target} answered ${status} ${state.injected} time(s) of ${state.seen.length}; retries ${JSON.stringify(evidence.retries)}`);
  return { ...child, state, evidence };
}

try {
  const once = await run('503-once', 503, 1, 30);
  assert.equal(once.code, 0, once.stderr);
  assert.equal(once.evidence.complete, true);
  assert.equal(once.evidence.pages.length, 12);
  assert.equal(once.evidence.retries.length, 1);
  assert.equal(once.evidence.retries[0].status, 503);
  assert.equal(once.evidence.retries[0].recovered, true);
  assert.ok(once.evidence.retries[0].url.endsWith(once.state.target));
  assert.match(once.stdout, /answered 503; it answered 200 after [\d.]+ s/);
  assert.match(once.stdout, /1 context\(s\) checked again after a 5xx/);

  const stays = await run('503-stays', 503, Infinity, 3);
  assert.equal(stays.code, 1);
  assert.equal(stays.evidence.complete, false);
  assert.equal(stays.evidence.retries.length, 1);
  assert.equal(stays.evidence.retries[0].recovered, false);
  assert.equal(stays.evidence.retries[0].last, 503);
  assert.match(stays.stdout, /still answered 503 after [\d.]+ s/);
  assert.match(stays.stderr, /HTTP 503/);

  const missing = await run('404-once', 404, 1, 30);
  assert.equal(missing.code, 1);
  assert.equal(missing.evidence.complete, false);
  assert.deepEqual(missing.evidence.retries, []);
  assert.equal(missing.state.seen.length, 1, 'a 404 is not fetched again');
  assert.match(missing.stderr, /HTTP 404/);
  console.log('test-screenshots-live: ok; a 503 that ends is checked again, a 503 that stays and a 404 fail');
} finally {
  await backend.close();
}
