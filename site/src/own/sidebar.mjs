// Sidebar data for the independent shell. Ordering follows Starlight 0.42.6
// (Astro contributors, MIT; see STARLIGHT-LICENSE).
const groups = [
  ['Guides', 'ガイド', 'guides'], ['Reference', 'リファレンス', 'reference'],
  ['Concepts', 'コンセプト', 'concepts'], ['Releases', 'リリース', 'releases'],
  ['Security', 'セキュリティ', 'security'], ['Contributing', '開発に参加する', 'contributing'],
];
const collator = new Intl.Collator('en');
const slugOf = (entry) => (entry.data.slug ?? entry.id).replace(/\.(md|mdx)$/, '').replace(/(^|\/)index$/, '').replace(/\/$/, '');
export function flattenSidebar(sidebar) {
  return sidebar.flatMap((entry) => entry.type === 'link' ? [entry] : flattenSidebar(entry.entries));
}
export function buildSidebar(entries, { locale, pathname, version = 3, base = '' } = {}) {
  const ja = locale === 'ja';
  const prefix = ja ? 'ja/' : '';
  const map = new Map(entries.map((entry) => [slugOf(entry), entry]));
  const english = [...map.keys()].filter((slug) => !slug.startsWith('ja/') && slug !== 'ja');
  const routeEntries = english.map((slug) => ({ slug, entry: map.get(prefix + slug) ?? map.get(slug) }));
  const href = (slug) => `${base.replace(/\/$/, '')}/${prefix}${slug ? slug + '/' : ''}`;
  const makeLink = ({ slug, entry }, label) => ({
    type: 'link', label: label ?? entry.data.sidebar?.label ?? entry.data.title,
    href: href(slug), isCurrent: decodeURI(pathname ?? '') === href(slug),
    attrs: entry.data.sidebar?.attrs ?? {}, badge: entry.data.sidebar?.badge,
  });
  const top = version === 2 ? [['', ja ? '概要' : 'Overview']] : [['docs', ja ? '概要' : 'Overview'], ['start', ja ? 'はじめに' : 'Start']];
  const sidebar = top.map(([slug, label]) => {
    const found = routeEntries.find((r) => r.slug === slug);
    if (!found) throw new Error(`Sidebar route missing: ${prefix}${slug}`);
    return makeLink(found, label);
  });
  for (const [en, jp, directory] of groups) {
    if (version === 2 && directory === 'concepts') continue;
    // The current generator writes translated group roots as ja/<group>.md,
    // rather than <group>/index.md. Starlight's treeify omits that empty
    // breadcrumb; preserve its sidebar here instead of adding four links.
    const children = routeEntries.filter(({ slug, entry }) => (slug === directory || slug.startsWith(directory + '/')) && !entry.data.sidebar?.hidden && !(ja && slug === directory && map.has(prefix + slug)));
    children.sort((a, b) => (a.entry.data.sidebar?.order ?? Number.MAX_VALUE) - (b.entry.data.sidebar?.order ?? Number.MAX_VALUE) || collator.compare(prefix + a.slug, prefix + b.slug));
    sidebar.push({ type: 'group', label: ja ? jp : en, entries: children.map((r) => makeLink(r)), collapsed: false });
  }
  return sidebar;
}
export function makeToc(headings, locale) {
  const items = [{ depth: 2, slug: '_top', text: locale === 'ja' ? '概要' : 'Overview', children: [] }];
  let parent = items[0];
  for (const heading of headings) {
    if (heading.depth < 2 || heading.depth > 3) continue;
    const item = { ...heading, children: [] };
    if (heading.depth === 2 || !parent) { items.push(item); parent = item; }
    else parent.children.push(item);
  }
  return { minHeadingLevel: 2, maxHeadingLevel: 3, items };
}
