// The links of the header, the menu and the footer (docs/proposals/site.md,
// 3.2 and 4.10), in one place. The header has the five section links of
// 3.2. The version link of the footer leads to the index of the other
// version (3.4): from
// a 3.x page to /v2/, from a 2.x page to /docs/, in the same language. The
// pages of the 2.x build (step 6) are under /v2/ (BASE); their section
// links stay in 2.x, except Agent proxy, a page of 3.x only.
import { BASE, GITHUB_URL, SITE_VERSION } from '../scripts/lib/site.mjs';

export { GITHUB_URL };

const T = {
  en: {
    docs: 'Docs',
    agentProxy: 'Agent proxy',
    releases: 'Releases',
    security: 'Security',
    contributing: 'Contributing',
    version: SITE_VERSION === 2 ? '3.x docs' : '2.x docs',
    language: 'Language',
    sections: 'Sections',
    menu: 'Menu',
    home: 'ngx_mruby home',
  },
  ja: {
    docs: 'ドキュメント',
    agentProxy: 'エージェントプロキシ',
    releases: 'リリース',
    security: 'セキュリティ',
    contributing: '開発に参加する',
    version: SITE_VERSION === 2 ? '3.xのドキュメント' : '2.xのドキュメント',
    language: '言語',
    sections: 'セクション',
    menu: 'メニュー',
    home: 'ngx_mrubyのホーム',
  },
};

export const strings = (lang) => T[lang === 'ja' ? 'ja' : 'en'];

export function sectionLinks(lang) {
  const t = strings(lang);
  const p = lang === 'ja' ? '/ja' : '';
  const b = `${BASE}${p}`;
  return [
    { key: 'docs', label: t.docs, href: SITE_VERSION === 2 ? `${b}/` : `${b}/docs/` },
    { key: 'agent-proxy', label: t.agentProxy, href: `${p}/guides/agent-proxy/` },
    { key: 'releases', label: t.releases, href: `${b}/releases/` },
    { key: 'security', label: t.security, href: `${b}/security/` },
    { key: 'contributing', label: t.contributing, href: `${b}/contributing/` },
  ];
}

export function versionLink(lang) {
  const p = lang === 'ja' ? '/ja' : '';
  return { label: strings(lang).version, href: SITE_VERSION === 2 ? `${p}/docs/` : `/v2${p}/` };
}

// The same page in the other language (4.10): /ja/<path> and /<path>, and
// /v2/ja/<path> and /v2/<path> in the 2.x build.
export function otherLanguage(lang, pathname) {
  const rest = BASE && pathname.startsWith(`${BASE}/`) ? pathname.slice(BASE.length) : pathname;
  if (lang === 'ja') {
    return { lang: 'en', label: 'English', href: BASE + rest.replace(/^\/ja(\/|$)/, '/') };
  }
  return { lang: 'ja', label: '日本語', href: `${BASE}/ja${rest === '/' ? '/' : rest}` };
}

// The section link of the current page, by its path.
export function currentSection(lang, pathname) {
  const p = lang === 'ja' ? '/ja' : '';
  if (BASE && pathname.startsWith(`${BASE}/`)) {
    // The index of the 2.x build, /v2/, is its documentation index.
    pathname = pathname.slice(BASE.length);
    if (pathname === `${p}/`) return 'docs';
  }
  if (pathname.startsWith(`${p}/releases/`)) return 'releases';
  if (pathname.startsWith(`${p}/guides/agent-proxy/`)) return 'agent-proxy';
  if (pathname.startsWith(`${p}/security/`)) return 'security';
  if (pathname.startsWith(`${p}/contributing/`)) return 'contributing';
  if (pathname === `${p}/` || pathname === '/ja/' || pathname.startsWith(`${p}/404`)) return null;
  return 'docs';
}
