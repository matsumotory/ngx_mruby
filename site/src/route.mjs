// Shared components consume the same route contract in either shell.
// Return the original object: Footer sets the home page's git-derived date.
export function getSiteRoute(locals) {
  const route = locals.siteRoute ?? locals.starlightRoute;
  if (!route) throw new Error('Site route is unavailable: render within a site layout');
  return route;
}

export function isOwnShell(locals) {
  return Boolean(locals.siteRoute);
}

const labels = {
  en: {
    'sidebarNav.accessibleLabel': 'Main',
    'menuButton.accessibleLabel': 'Menu',
    'page.lastUpdated': 'Last updated:',
    'page.previousLink': 'Previous',
    'page.nextLink': 'Next',
  },
  ja: {
    'sidebarNav.accessibleLabel': 'メイン',
    'menuButton.accessibleLabel': 'メニュー',
    'page.lastUpdated': '最終更新日:',
    'page.previousLink': '前へ',
    'page.nextLink': '次へ',
  },
};

export function routeLabel(locals, key) {
  if (!isOwnShell(locals) && typeof locals.t === 'function') return locals.t(key);
  const language = getSiteRoute(locals).locale === 'ja' ? 'ja' : 'en';
  const label = labels[language][key];
  if (label === undefined) throw new Error(`Unknown shared route label: ${key}`);
  return label;
}
