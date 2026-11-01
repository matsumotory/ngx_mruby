// The project's state on the site (docs/proposals/site.md, 4.10): the strip
// of development-practice badges below the hero of the index pages (/, /ja/,
// /v2/ and /v2/ja/), the release badge of the status line of the home
// pages, and the star count of the GitHub link of the header.
//
// The strip holds the badges of the workflows that test and check the
// branch that the page describes (next for 3.x, master for 2.x), OpenSSF
// Best Practices and the license. Keep the original service URLs; builds
// must not download or pin a changing badge result. The license badge is a
// file of the site. The release badge and the star count are made at build
// time from data that the build has (git tags) or is given (the star count
// that site.yml reads), so they add no other origin to the pages.
const REPO = 'https://github.com/matsumotory/ngx_mruby';

export const OPENSSF_BADGE = Object.freeze({
  id: 'openssf',
  href: 'https://www.bestpractices.dev/projects/16057',
  src: 'https://www.bestpractices.dev/projects/16057/badge',
  alt: 'OpenSSF Best Practices',
  width: 184,
  height: 20,
});

// The workflows of the strip, in their order. The width is that of GitHub's
// badge in the state "passing", read on 2026-11-01; the page reserves this
// box, so nothing below the strip moves while the images load or when they
// fail. branch: the branch whose runs the badge shows, for a page of next
// and for one of master. valgrind-nightly runs from master only, because
// GitHub runs a schedule only from the default branch, and each of its runs
// tests master and next, so both versions show its runs on master.
// nginx-tests exists on next only, and its badge for master says "no
// status", so the 2.x pages leave it out.
const WORKFLOWS = Object.freeze([
  { id: 'test', file: 'test.yml', width: 98, branch: { next: 'next', master: 'master' },
    en: (ref) => `test workflow status on ${ref}`, ja: (ref) => `${ref}でのtestの結果` },
  { id: 'nginx-tests', file: 'nginx-tests.yml', width: 139, branch: { next: 'next' },
    en: (ref) => `nginx-tests workflow status on ${ref}`, ja: (ref) => `${ref}でのnginx-testsの結果` },
  { id: 'valgrind', file: 'valgrind-nightly.yml', width: 164, branch: { next: 'master', master: 'master' },
    en: () => 'valgrind-nightly workflow status: the nightly valgrind runs of master and next', ja: () => 'masterとnextを毎晩valgrindの下で試すvalgrind-nightlyの結果' },
  { id: 'codeql', file: 'codeql.yml', width: 111, branch: { next: 'next', master: 'master' },
    en: (ref) => `CodeQL workflow status on ${ref}`, ja: (ref) => `${ref}でのCodeQLの結果` },
  { id: 'zizmor', file: 'zizmor.yml', width: 114, branch: { next: 'next', master: 'master' },
    en: (ref) => `zizmor workflow status on ${ref}`, ja: (ref) => `${ref}でのzizmorの結果` },
]);

export const LICENSE_BADGE_SRC = '/brand/license-mit.svg';

// The badges of the strip of one version, in their order.
// ref: the branch that the page describes ('next' or 'master').
export function projectBadges(ref, lang) {
  if (ref !== 'next' && ref !== 'master') throw new Error(`projectBadges: unknown branch ${ref}`);
  const ja = lang === 'ja';
  const workflows = WORKFLOWS.filter(w => w.branch[ref]).map(w => {
    const branch = w.branch[ref];
    return {
      id: w.id,
      href: `${REPO}/actions/workflows/${w.file}?query=branch%3A${branch}`,
      src: `${REPO}/actions/workflows/${w.file}/badge.svg?branch=${branch}`,
      alt: (ja ? w.ja : w.en)(branch),
      width: w.width,
      height: 20,
    };
  });
  return [
    ...workflows,
    { ...OPENSSF_BADGE },
    { id: 'license', href: `${REPO}/blob/${ref}/LICENSE`, src: LICENSE_BADGE_SRC, alt: ja ? 'MITライセンス' : 'License: MIT', width: 78, height: 20 },
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
const FIXTURE_LABELS = { test: 'test', 'nginx-tests': 'nginx-tests', valgrind: 'valgrind-nightly', codeql: 'codeql', zizmor: 'zizmor', openssf: 'openssf best practices' };
export const BADGE_FIXTURES = Object.freeze(Object.fromEntries(EXTERNAL_BADGE_URLS.map(src => [src, Object.freeze({
  contentType: 'image/svg+xml',
  body: fixtureSvg(sizeOf[src].width, FIXTURE_LABELS[sizeOf[src].id]),
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

// The release badge of the status line of / and /ja/: the newest stable tag
// (latestReleaseTag in release-state.mjs), drawn at build time in the flat
// style of the license badge as an image in a data URL, linking to that
// release. The widths of the two
// parts follow Verdana at 11 px, as shields.io measures them, and
// textLength fits each text to its part whatever font draws it.
const VERDANA_11 = { r: 4.3, e: 6.8, l: 3.0, a: 6.7, s: 5.7, v: 6.5, '.': 3.5 };
const textWidth = (text) => [...text].reduce((sum, ch) => sum + (/\d/.test(ch) ? 7.0 : VERDANA_11[ch] ?? 7.0), 0);
export function releaseBadge(tag, lang) {
  if (!/^v\d+\.\d+\.\d+$/.test(tag)) throw new Error(`releaseBadge: not a stable release tag: ${tag}`);
  const label = 'release';
  const lw = Math.round(textWidth(label) + 10), vw = Math.round(textWidth(tag) + 10), width = lw + vw;
  const text = (x, value, w) => `<text aria-hidden="true" x="${x * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(w - 10) * 10}">${value}</text><text x="${x * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(w - 10) * 10}">${value}</text>`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" viewBox="0 0 ${width} 20"><clipPath id="release-badge-clip"><rect width="${width}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#release-badge-clip)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${vw}" height="20" fill="#007ec6"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">${text(lw / 2, label, lw)}${text(lw + vw / 2, tag, vw)}</g></svg>`;
  return {
    id: 'release',
    tag,
    href: `${REPO}/releases/tag/${tag}`,
    alt: lang === 'ja' ? `最新のリリースは${tag}` : `Latest release: ${tag}`,
    width,
    height: 20,
    svg,
    // An image, as the badges of the strip are: the page's color checks
    // and tokens do not apply to the badge's own colors (4.3, item 5).
    src: `data:image/svg+xml,${encodeURIComponent(svg)}`,
  };
}

// The star count of the GitHub link of the header and the menu. site.yml
// reads the count from the GitHub API before the builds and passes it in
// NGX_MRUBY_SITE_STARS, with the day of the reading (YYYY-MM-DD, UTC) in
// NGX_MRUBY_SITE_STARS_DATE; the builds fetch nothing (4.4). Without the
// two variables, as in a local build or when the API did not answer, the
// link shows no count.
export function githubStars(lang, env = process.env) {
  const count = env.NGX_MRUBY_SITE_STARS, date = env.NGX_MRUBY_SITE_STARS_DATE;
  if (!count && !date) return null;
  if (!/^\d+$/.test(count ?? '') || !/^\d{4}-\d{2}-\d{2}$/.test(date ?? '')) throw new Error(`githubStars: NGX_MRUBY_SITE_STARS must be digits and NGX_MRUBY_SITE_STARS_DATE a date (YYYY-MM-DD), not "${count}" and "${date}"`);
  const n = Number(count);
  // At most four characters: 997, 1K, 1.2K, 12K.
  const short = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 }).format(n);
  const exact = n.toLocaleString('en-US');
  const [y, m, d] = date.split('-').map(Number);
  const ja = lang === 'ja';
  return {
    count: n,
    date,
    short,
    // Read after "GitHub", the link's own text.
    label: ja ? `、${y}年${m}月${d}日時点のスターは${exact}件` : `, ${exact} stars on ${date}`,
    title: ja ? `${y}年${m}月${d}日時点のスターは${exact}件` : `${exact} stars on ${date}`,
  };
}
