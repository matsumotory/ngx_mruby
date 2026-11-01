import { strings } from './own/strings.mjs';

// Shared components consume the site route contract.
// Return the original object: Footer sets the home page's git-derived date.
export function getSiteRoute(locals) {
  const route = locals.siteRoute;
  if (!route) throw new Error('Site route is unavailable: render within a site layout');
  return route;
}

export function routeLabel(locals, key) {
  const language = getSiteRoute(locals).locale === 'ja' ? 'ja' : 'en';
  const label = strings(language)[key];
  if (label === undefined) throw new Error(`Unknown shared route label: ${key}`);
  return label;
}
