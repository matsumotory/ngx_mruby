// A verification context, not a runtime site policy. Never give this
// context a service worker, write request or WebSocket connection.
export function allowsReadOnlyRequest(request, origin, imageUrls = []) {
  if (request.method() !== 'GET') return false;
  if (new URL(request.url()).origin === new URL(origin).origin) return true;
  // Exact URL, not a host/prefix permission. A fetch, document or script at
  // the same URL remains forbidden. Callers opt in to the footer badge only.
  return request.resourceType() === 'image' && imageUrls.includes(request.url());
}

export async function readOnlyContext(browser, origin, options = {}, imageUrls = []) {
  const context = await browser.newContext({ ...options, serviceWorkers: 'block' });
  const blocked = [];
  await context.route('**/*', async route => {
    const request = route.request();
    if (!allowsReadOnlyRequest(request, origin, imageUrls)) {
      blocked.push(`${request.method()} ${request.url()}`);
      return route.abort();
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
  });
  await context.routeWebSocket('**/*', socket => {
    blocked.push(`WebSocket ${socket.url()}`);
    return socket.close({ code: 1008, reason: 'Read-only site verification' });
  });
  return { context, blocked };
}
