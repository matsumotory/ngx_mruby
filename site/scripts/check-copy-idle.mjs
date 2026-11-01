// Copy controls must be still before the reader interacts with them. In
// WebKit reported load-time animations and a non-token copy background.
// Record their targets/properties to check the initial-transition hypothesis.
// Check the idle transition contract as well as the actual load state; do
// not wait for animations to finish or disable motion in the test browser.
import path from 'node:path';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { patternsFor } from './lib/patterns.mjs';
import { homeColors } from './lib/tokens.mjs';

const site = path.resolve(new URL('..', import.meta.url).pathname);
const server = await serve(path.join(site, 'dist'));
const failures = [];
let states = 0;
try {
  for (const engine of [chromium, webkit]) {
    const browser = await engine.launch();
    try {
      for (const route of ['/', '/ja/']) for (const theme of ['light', 'dark']) for (const { width, height } of patternsFor(engine.name())) {
        const context = await browser.newContext({ viewport: { width, height }, colorScheme: theme, reducedMotion: 'no-preference' });
        try {
          const page = await context.newPage();
          await page.goto(server.url + route, { waitUntil: 'load' });
          const state = await page.evaluate(() => {
            const controls = [...document.querySelectorAll('.expressive-code .copy button')];
            const surfaces = controls.flatMap(button => [button, ...button.children]);
            return {
              count: controls.length,
              surfaces: surfaces.filter(el => el.getClientRects().length > 0).map(el => {
                const style = getComputedStyle(el);
                return { tag: el.tagName.toLowerCase(), transition: style.transitionProperty,
                  duration: style.transitionDuration, background: style.backgroundColor };
              }),
              running: document.getAnimations().filter(animation => animation.playState === 'running').map(animation => ({
                target: animation.effect?.target?.outerHTML?.slice(0, 180),
                property: animation.transitionProperty ?? animation.animationName,
              })),
            };
          });
          const label = `${engine.name()} ${route} ${theme} ${width}`;
          if (!state.count || !state.surfaces.length) failures.push(`${label}: no visible copy controls were checked`);
          const active = state.surfaces.filter(surface => surface.duration.split(',').some(value => parseFloat(value) !== 0) && surface.transition !== 'none');
          if (active.length) failures.push(`${label}: ${active.length} idle copy surfaces can animate before interaction: ${JSON.stringify(active[0])}`);
          if (state.running.length) failures.push(`${label}: animations running at load: ${JSON.stringify(state.running)}`);
          const tokens = new Set(Object.values(homeColors(theme)));
          for (const surface of state.surfaces) {
            const rgb = surface.background.match(/^rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)$/);
            if (!rgb) {
              failures.push(`${label}: idle ${surface.tag} background ${surface.background} is not an RGB token color`);
              continue;
            }
            const alpha = Number(rgb[4] ?? 1);
            if (alpha === 0) continue;
            if (alpha !== 1) failures.push(`${label}: idle ${surface.tag} background ${surface.background} is partially transparent`);
            const color = '#' + rgb.slice(1, 4).map(value => Number(value).toString(16).padStart(2, '0')).join('');
            if (!tokens.has(color)) failures.push(`${label}: idle ${surface.tag} background ${color} is not a theme token`);
          }
          states++;
        } finally {
          await context.close();
        }
      }
    } finally {
      await browser.close();
    }
  }
} finally {
  await server.close();
}
for (const failure of failures) console.error(failure);
if (failures.length) {
  console.error(`check-copy-idle: ${failures.length} failures in ${states} load states`);
  process.exit(1);
}
console.log(`check-copy-idle: ${states} Chromium/WebKit load states; idle copy surfaces have no transitions or running animations, and use theme-token backgrounds`);
