// The links of the header, the menu and the footer (docs/proposals/site.md,
// 3.2 and 4.10), in one place. The header has the five section links of
// 3.2; the pages of Security and Contributing come with step 4, so until
// then these links go to their sources on GitHub. The version
// link goes to the 2.x documentation on GitHub until step 6 builds /v2/.
export const GITHUB_URL = 'https://github.com/matsumotory/ngx_mruby';

const T = {
  en: {
    docs: 'Docs',
    agentProxy: 'Agent proxy',
    releases: 'Releases',
    security: 'Security',
    contributing: 'Contributing',
    version: '2.x docs',
    language: 'Language',
    sections: 'Sections',
    license: 'License',
    menu: 'Menu',
    home: 'ngx_mruby home',
  },
  ja: {
    docs: 'ドキュメント',
    agentProxy: 'エージェントプロキシ',
    releases: 'リリース',
    security: 'セキュリティ',
    contributing: '開発に参加する',
    version: '2.xのドキュメント',
    language: '言語',
    sections: 'セクション',
    license: 'ライセンス',
    menu: 'メニュー',
    home: 'ngx_mrubyのホーム',
  },
};

export const strings = (lang) => T[lang === 'ja' ? 'ja' : 'en'];

export function sectionLinks(lang) {
  const t = strings(lang);
  const p = lang === 'ja' ? '/ja' : '';
  return [
    { key: 'docs', label: t.docs, href: `${p}/docs/` },
    { key: 'agent-proxy', label: t.agentProxy, href: `${p}/guides/agent-proxy/` },
    { key: 'releases', label: t.releases, href: `${p}/releases/` },
    { key: 'security', label: t.security, href: `${GITHUB_URL}/blob/next/SECURITY.md` },
    { key: 'contributing', label: t.contributing, href: `${GITHUB_URL}/blob/next/AGENTS.md` },
  ];
}

export const versionLink = (lang) => ({ label: strings(lang).version, href: `${GITHUB_URL}/tree/master/docs` });

// The same page in the other language (4.10): /ja/<path> and /<path>.
export function otherLanguage(lang, pathname) {
  if (lang === 'ja') {
    const rest = pathname.replace(/^\/ja(\/|$)/, '/');
    return { lang: 'en', label: 'English', href: rest };
  }
  return { lang: 'ja', label: '日本語', href: `/ja${pathname === '/' ? '/' : pathname}` };
}

// The section link of the current page, by its path.
export function currentSection(lang, pathname) {
  const p = lang === 'ja' ? '/ja' : '';
  if (pathname.startsWith(`${p}/releases/`)) return 'releases';
  if (pathname.startsWith(`${p}/guides/agent-proxy/`)) return 'agent-proxy';
  if (pathname === `${p}/` || pathname === '/ja/' || pathname.startsWith(`${p}/404`)) return null;
  return 'docs';
}
