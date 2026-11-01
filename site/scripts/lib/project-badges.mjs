// The row of project badges above the heading of the four index pages
// (/, /ja/, /v2/ and /v2/ja/; docs/proposals/site.md, 4.4 and 4.10): CI,
// CodeQL, OpenSSF Best Practices and the license. The CI and CodeQL badges
// show the branch that the page describes (next for 3.x, master for 2.x).
// Keep the original service URLs; builds must not download or pin a
// changing badge result. The license badge is a file of the site.
const REPO = 'https://github.com/matsumotory/ngx_mruby';

export const OPENSSF_BADGE = Object.freeze({
  id: 'openssf',
  href: 'https://www.bestpractices.dev/projects/16057',
  src: 'https://www.bestpractices.dev/projects/16057/badge',
  alt: 'OpenSSF Best Practices',
  width: 184,
  height: 20,
});

// The size of each badge as its service draws it in the state "passing"
// (GitHub's workflow badges for test and codeql, read on 2026-11-01). The
// page reserves this box, so the heading below does not move while the
// images load or when they fail.
const WORKFLOWS = Object.freeze({
  ci: { file: 'test.yml', width: 98, en: (ref) => `CI test workflow status on ${ref}`, ja: (ref) => `${ref}でのCIの結果` },
  codeql: { file: 'codeql.yml', width: 111, en: (ref) => `CodeQL workflow status on ${ref}`, ja: (ref) => `${ref}でのCodeQLの結果` },
});

export const LICENSE_BADGE_SRC = '/brand/license-mit.svg';

// The badges of the index pages of one version, in their order.
// ref: the branch that the page describes ('next' or 'master').
export function projectBadges(ref, lang) {
  if (ref !== 'next' && ref !== 'master') throw new Error(`projectBadges: unknown branch ${ref}`);
  const ja = lang === 'ja';
  const workflow = (id) => {
    const w = WORKFLOWS[id];
    return {
      id,
      href: `${REPO}/actions/workflows/${w.file}?query=branch%3A${ref}`,
      src: `${REPO}/actions/workflows/${w.file}/badge.svg?branch=${ref}`,
      alt: (ja ? w.ja : w.en)(ref),
      width: w.width,
      height: 20,
    };
  };
  return [
    workflow('ci'),
    workflow('codeql'),
    { ...OPENSSF_BADGE },
    { id: 'license', href: `${REPO}/blob/${ref}/MITL`, src: LICENSE_BADGE_SRC, alt: ja ? 'MITライセンス' : 'License: MIT', width: 78, height: 20 },
  ];
}

// The badge images that come from other services, for both versions.
export const EXTERNAL_BADGE_URLS = Object.freeze([...new Set(['next', 'master'].flatMap(ref => projectBadges(ref, 'en').map(b => b.src)).filter(src => /^https:/.test(src)))]);

// The browser checks before the deploy serve a local stand-in at each
// external badge URL, so that they never wait on GitHub or bestpractices.dev.
// A stand-in has the badge's size, and its right part says "fixture", so
// screenshots do not pass it off as the service's answer. Only
// check-live.mjs, after the deploy, fetches the real images.
function fixtureSvg(width, label) {
  const right = 50;
  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="20" viewBox="0 0 ' + width + ' 20">'
    + '<rect width="' + (width - right) + '" height="20" fill="#555"/><rect x="' + (width - right) + '" width="' + right + '" height="20" fill="#007ec6"/>'
    + '<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="10">'
    + '<text x="6" y="14">' + label + '</text><text x="' + (width - right + 6) + '" y="14">fixture</text></g></svg>';
}
const sizeOf = Object.fromEntries(['next', 'master'].flatMap(ref => projectBadges(ref, 'en')).map(b => [b.src, b]));
export const BADGE_FIXTURES = Object.freeze(Object.fromEntries(EXTERNAL_BADGE_URLS.map(src => [src, Object.freeze({
  contentType: 'image/svg+xml',
  body: fixtureSvg(sizeOf[src].width, { ci: 'test', codeql: 'codeql', openssf: 'openssf best practices' }[sizeOf[src].id]),
})])));

// Serve the stand-ins at the exact badge URLs in a Playwright context. The
// URLs hold a query, so they are matched by a predicate, not a glob. A route
// registered later takes precedence over earlier ones, so this also works on
// a context that already has a catch-all route.
export async function serveBadgeFixture(context) {
  await context.route(url => EXTERNAL_BADGE_URLS.includes(url.href), route => {
    const request = route.request();
    if (request.method() !== 'GET' || request.resourceType() !== 'image') return route.abort();
    const { contentType, body } = BADGE_FIXTURES[request.url()];
    return route.fulfill({ status: 200, contentType, body });
  });
}
