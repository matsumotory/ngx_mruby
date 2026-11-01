// A verification context, not a runtime site policy. Never give this
// context a service worker, write request or WebSocket connection.
export function allowsReadOnlyRequest(request, origin, imageUrls = []) {
  if (request.method() !== 'GET') return false;
  if (new URL(request.url()).origin === new URL(origin).origin) return true;
  // Exact URL, not a host/prefix permission. A fetch, document or script at
  // the same URL remains forbidden. Callers opt in to the project badges only.
  return request.resourceType() === 'image' && imageUrls.includes(request.url());
}

// fixtures maps an exact off-origin image URL to { contentType, body }. Such
// a request is answered from the fixture and never reaches the network, so a
// check does not depend on a third-party service.
export async function readOnlyContext(browser, origin, options = {}, fixtures = {}) {
  const imageUrls = Object.keys(fixtures);
  const context = await browser.newContext({ ...options, serviceWorkers: 'block' });
  const blocked = [], errors = [];
  const pending = new Set();
  let closing = false, closePromise;
  async function handle(route) {
    if (closing) return route.abort();
    const request = route.request();
    if (!allowsReadOnlyRequest(request, origin, imageUrls)) {
      blocked.push(`${request.method()} ${request.url()}`);
      return route.abort();
    }
    if (new URL(request.url()).origin !== new URL(origin).origin) {
      const { contentType, body } = fixtures[request.url()];
      return route.fulfill({ status: 200, contentType, body });
    }
    // Route handlers do not intercept every hop of a browser redirect.
    // Fetch one response only; canonical verification URLs must not redirect.
    const response = await route.fetch({ maxRedirects: 0 });
    if (response.status() >= 300 && response.status() < 400) {
      blocked.push(`Redirect ${request.url()} (${response.status()})`);
      await response.dispose();
      return route.abort();
    }
    try {
      return await route.fulfill({ response });
    } finally {
      await response.dispose();
    }
  }
  await context.route('**/*', route => {
    // Event callbacks must not become unhandled rejections during cleanup.
    // Record failures and reject close(), so verification cannot call them green.
    const task = handle(route).catch(async error => {
      errors.push(error);
      try { await route.abort(); } catch (abortError) { errors.push(abortError); }
    });
    pending.add(task);
    void task.then(() => pending.delete(task));
    return task;
  });
  await context.routeWebSocket('**/*', socket => {
    blocked.push(`WebSocket ${socket.url()}`);
    return socket.close({ code: 1008, reason: 'Read-only site verification' });
  });
  function close() {
    if (closePromise) return closePromise;
    closing = true; // New requests are still intercepted, but no new fetch starts.
    closePromise = (async () => {
      while (pending.size) await Promise.all([...pending]);
      await context.close();
      while (pending.size) await Promise.all([...pending]);
      if (errors.length) throw new AggregateError(errors, 'Read-only verification request failed');
    })();
    return closePromise;
  }
  return { context, blocked, close };
}
