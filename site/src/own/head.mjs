// Head merging and ordering adapted from Starlight 0.42.6.
// Copyright Astro contributors, MIT: STARLIGHT-LICENSE.
import { SITE_URL, SITE_VERSION } from '../../scripts/lib/site.mjs';
import { shareImageForVersion } from '../../scripts/lib/brand.mjs';
export function getHead(route, { url, generator }) {
  const { data } = route.entry;
  const base = SITE_VERSION === 2 ? '/v2' : '';
  const canonical = new URL(url.pathname.replace(/\/?$/, '/'), SITE_URL).href;
  const rest = url.pathname.slice(base.length).replace(/^\/ja(?=\/|$)/, '') || '/';
  const image = shareImageForVersion(SITE_VERSION);
  const meta = (name, content) => ({ tag: 'meta', attrs: { name, content } });
  const og = (property, content) => ({ tag: 'meta', attrs: { property, content } });
  let head = [
    { tag: 'meta', attrs: { charset: 'utf-8' } }, meta('viewport', 'width=device-width, initial-scale=1'),
    { tag: 'title', content: `${data.title} | ngx_mruby` },
    { tag: 'link', attrs: { rel: 'canonical', href: canonical } },
    meta('generator', generator),
    { tag: 'link', attrs: { rel: 'shortcut icon', href: `${base}/favicon.svg`, type: 'image/svg+xml' } },
    og('og:title', data.title), og('og:type', 'article'), og('og:url', canonical), og('og:locale', route.lang ?? (route.locale === 'ja' ? 'ja' : 'en')),
    ...(data.description ? [og('og:description', data.description)] : []), og('og:site_name', 'ngx_mruby'), meta('twitter:card', 'summary_large_image'),
    ...(data.description ? [meta('description', data.description)] : []),
    ...[['en', `${base}${rest}`], ['ja', `${base}/ja${rest}`], ['x-default', `${base}${rest}`]].map(([hreflang, path]) => ({ tag: 'link', attrs: { rel: 'alternate', hreflang, href: new URL(path, SITE_URL).href } })),
    { tag: 'link', attrs: { rel: 'sitemap', href: `${base}/sitemap-index.xml` } },
    ...Object.entries({ 'og:image': `${SITE_URL}/${image.file}`, 'og:image:type': image.type, 'og:image:width': String(image.width), 'og:image:height': String(image.height), 'og:image:alt': image.alt }).map(([key, value]) => og(key, value)),
    meta('twitter:image', `${SITE_URL}/${image.file}`), meta('twitter:image:alt', image.alt),
  ];
  const overrides = data.head ?? [];
  const matches = (a, b) => a.tag === b.tag && (a.tag === 'title' || a.tag === 'meta' && ['name', 'property', 'http-equiv'].some((key) => b.attrs?.[key] && a.attrs?.[key] === b.attrs[key]) || a.tag === 'link' && ['canonical', 'sitemap'].includes(b.attrs?.rel) && a.attrs?.rel === b.attrs.rel);
  head = [...head.filter((entry) => !overrides.some((other) => matches(entry, other))), ...overrides];
  const weight = (entry) => entry.tag === 'meta' && ('charset' in (entry.attrs ?? {}) || 'http-equiv' in (entry.attrs ?? {}) || entry.attrs?.name === 'viewport') ? 100 : entry.tag === 'title' ? 90 : entry.tag !== 'meta' ? entry.tag === 'link' && entry.attrs?.rel === 'shortcut icon' ? 70 : 80 : 0;
  return head.sort((a, b) => weight(b) - weight(a));
}
