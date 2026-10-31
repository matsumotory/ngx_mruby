// The one third-party image used by the shared footer. Keep the original
// service URL; builds must not download or pin a changing badge result.
export const OPENSSF_BADGE = Object.freeze({
  href: 'https://www.bestpractices.dev/projects/16057',
  src: 'https://www.bestpractices.dev/projects/16057/badge',
  alt: 'OpenSSF Best Practices',
  width: 184,
  height: 20,
});

// The browser checks before the deploy serve this local stand-in at the
// badge URL, so that they never wait on bestpractices.dev. It has the badge's
// size, and its right half says "fixture", so screenshots do not pass it off
// as the service's answer. Only check-live.mjs, after the deploy, fetches the
// real image.
export const OPENSSF_BADGE_FIXTURE = Object.freeze({
  contentType: 'image/svg+xml',
  body: '<svg xmlns="http://www.w3.org/2000/svg" width="184" height="20" viewBox="0 0 184 20">'
    + '<rect width="134" height="20" fill="#555"/><rect x="134" width="50" height="20" fill="#007ec6"/>'
    + '<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="10">'
    + '<text x="6" y="14">openssf best practices</text><text x="140" y="14">fixture</text></g></svg>',
});

// Serve the stand-in at the exact badge URL in a Playwright context. A route
// registered later takes precedence over earlier ones, so this also works on
// a context that already has a catch-all route.
export async function serveBadgeFixture(context) {
  await context.route(OPENSSF_BADGE.src, route => {
    const request = route.request();
    if (request.method() !== 'GET' || request.resourceType() !== 'image') return route.abort();
    return route.fulfill({ status: 200, contentType: OPENSSF_BADGE_FIXTURE.contentType, body: OPENSSF_BADGE_FIXTURE.body });
  });
}
