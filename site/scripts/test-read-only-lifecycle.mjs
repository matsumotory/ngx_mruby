// Regression: a slow image route must settle before its request context closes.
// Fixture promises model browser callbacks; no browser or external service needed.
import assert from 'node:assert/strict';
import { readOnlyContext } from './lib/read-only-browser.mjs';
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function fixture() {
  const events = [];
  const context = {
    route: async (_pattern, handler) => { context.handler = handler; },
    routeWebSocket: async () => {},
    close: async () => { events.push('context-close'); },
  };
  const browser = { newContext: async options => { assert.equal(options.serviceWorkers, 'block'); return context; } };
  const request = { method: () => 'GET', url: () => 'https://site.test/image.svg', resourceType: () => 'image' };
  return { context, browser, events, request };
}
{
  const { context, browser, events, request } = fixture();
  const boundary = await readOnlyContext(browser, 'https://site.test');
  assert.equal(typeof boundary.close, 'function', 'boundary owns a draining close operation');
  const started = deferred(), finish = deferred();
  const route = {
    request: () => request,
    fetch: async options => {
      assert.equal(options.maxRedirects, 0); started.resolve(); await finish.promise;
      assert.ok(!events.includes('context-close'), 'request context stays alive for the fetch');
      return { status: () => 200, dispose: async () => { events.push('dispose'); } };
    },
    fulfill: async () => { events.push('fulfill'); },
    abort: async () => { events.push('abort'); },
  };
  const handling = context.handler(route); await started.promise;
  const closing = boundary.close();
  await Promise.resolve(); assert.ok(!events.includes('context-close'));
  await context.handler({ ...route, fetch: async () => { assert.fail('no new fetch after close begins'); } });
  finish.resolve(); await handling; await closing;
  assert.deepEqual(events, ['abort', 'fulfill', 'dispose', 'context-close']);
}
{
  const { context, browser, events, request } = fixture();
  const boundary = await readOnlyContext(browser, 'https://site.test');
  await context.handler({ request: () => request, fetch: async () => { throw new Error('image transport failed'); }, abort: async () => { events.push('abort'); } });
  await assert.rejects(() => boundary.close(), error => error instanceof AggregateError && error.errors.some(e => e.message === 'image transport failed'), 'transport failure must remain a failed verification');
  assert.deepEqual(events, ['abort', 'context-close']);
}
console.log('test-read-only-lifecycle: pending fetch drained before close; new closing traffic aborted; transport errors stay failures');
