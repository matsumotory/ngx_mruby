// A painted edge must remain distinguishable from the copper face. Computed
// border widths alone missed a 1px lower edge painted in the gradient's low color.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import sharp from 'sharp';
import { chromium, webkit } from 'playwright';
import { serve } from './lib/serve.mjs';
import { PATTERNS } from './lib/patterns.mjs';
import { serveBadgeFixture } from './lib/project-badges.mjs';

const site = path.resolve(new URL('..', import.meta.url).pathname);
let out = path.join(site, 'build-screenshots/cta'), dist = path.join(site, 'dist');
for (let i = 2; i < process.argv.length; i += 2) {
  const option = process.argv[i], value = process.argv[i + 1];
  assert.ok(value && ['--out', '--dist'].includes(option), 'usage: check-cta-edges.mjs [--dist DIR] [--out DIR]');
  if (option === '--out') out = path.resolve(value); else dist = path.resolve(value);
}
fs.mkdirSync(out, { recursive: true });
const server = await serve(dist);
const results = [], failures = [];
const luminance = rgb => rgb.map(v => v / 255).map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
  .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
const contrast = (a, b) => (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
async function edgeContrast(png, box, clip) {
  const { data, info: { width, height, channels } } = await sharp(png).removeAlpha().raw().toBuffer({ resolveWithObject: true });
  const scale = 2;
  assert.equal(width, clip.width * scale, 'capture keeps two device pixels per CSS pixel');
  assert.equal(height, clip.height * scale, 'capture keeps two device pixels per CSS pixel');
  const pixel = (x, y) => luminance([...data.subarray((y * width + x) * channels, (y * width + x) * channels + 3)]);
  const left = (box.x - clip.x) * scale, top = (box.y - clip.y) * scale;
  const right = left + box.width * scale, bottom = top + box.height * scale;
  // A CSS 1px border spans two device pixels. These pixels lie wholly inside
  // the straight border even when the CSS box is fractional. Do not choose a
  // high-contrast pixel outside it: the light page background masked the old
  // dark lower rim. Compare with the face four CSS pixels farther inward.
  const edge = { left: Math.ceil(left), top: Math.ceil(top), right: Math.floor(right) - 1, bottom: Math.floor(bottom) - 1 };
  return Object.fromEntries(['top', 'right', 'bottom', 'left'].map(side => {
    const values = [0.3, 0.4, 0.5, 0.6, 0.7].map(fraction => {
      const x = Math.floor(left + (right - left) * fraction), y = Math.floor(top + (bottom - top) * fraction);
      const pair = offset => side === 'top' ? [x, edge.top + offset] : side === 'bottom' ? [x, edge.bottom - offset]
        : side === 'left' ? [edge.left + offset, y] : [edge.right - offset, y];
      return contrast(pixel(...pair(0)), pixel(...pair(4 * scale)));
    });
    return [side, values.sort((a, b) => a - b)[2]];
  }));
}
try {
  for (const { engine, width, height } of PATTERNS) {
    const browser = await { chromium, webkit }[engine].launch();
    try {
      for (const lang of ['en', 'ja']) for (const colorScheme of ['light', 'dark']) {
        const context = await browser.newContext({ viewport: { width, height }, colorScheme, deviceScaleFactor: 2 });
        try {
          await serveBadgeFixture(context);
          const page = await context.newPage();
          await page.goto(server.url + (lang === 'ja' ? '/ja/' : '/'));
          await page.evaluate(() => document.fonts.ready);
          const liveCount = await page.locator('.home-v3 .button-primary').count();
          assert.ok(liveCount > 0, 'the real shared CTA uses must be present');
          // The shared selector also accepts native controls. Keep these local
          // test-only fixtures in the same cascade; they never submit a request.
          await page.locator('.home-v3').evaluate(home => {
            const form = document.createElement('form');
            form.addEventListener('submit', event => event.preventDefault());
            for (const [tag, type] of [['button', 'button'], ['button', 'submit'], ['input', 'submit']]) {
              const control = document.createElement(tag);
              control.className = 'button-primary'; control.type = type;
              if (tag === 'input') control.value = 'Continue'; else control.textContent = 'Continue';
              const row = document.createElement('p'); row.append(control); form.append(row);
            }
            home.append(form);
          });
          const controls = page.locator('.home-v3 .button-primary');
          for (let index = 0; index < await controls.count(); index++) {
            const control = controls.nth(index);
            for (const state of ['rest', 'hover', 'focus', 'active']) {
              await page.mouse.move(0, 0);
              await control.evaluate(el => el.blur());
              await control.scrollIntoViewIfNeeded();
              if (state === 'hover' || state === 'active') await control.hover();
              if (state === 'focus') { await page.keyboard.press('Tab'); await control.focus(); }
              if (state === 'active') await page.mouse.down();
              try {
                const style = await control.evaluate(el => {
                  const s = getComputedStyle(el);
                  return { tag: el.tagName, type: el.type, text: el.textContent || el.value,
                    active: el.matches(':active'), focusVisible: el.matches(':focus-visible'),
                    borders: ['Top', 'Right', 'Bottom', 'Left'].map(side => ({ width: s[`border${side}Width`], style: s[`border${side}Style`] })),
                    backgroundImage: s.backgroundImage, boxShadow: s.boxShadow, fontSize: s.fontSize };
                });
                assert.ok(style.borders.every(b => parseFloat(b.width) >= 1 && b.style === 'solid'), 'all four borders remain present');
                if (state === 'active') assert.ok(style.active, 'pointer is holding the actual active state');
                if (state === 'focus') assert.ok(style.focusVisible, 'keyboard focus is visible');
                const name = `${engine}-${lang}-${colorScheme}-${index}-${state}`;
                const box = await control.evaluate(el => {
                  const r = el.getBoundingClientRect();
                  return { x: r.x, y: r.y, width: r.width, height: r.height };
                });
                const clip = { x: Math.floor(box.x), y: Math.floor(box.y),
                  width: Math.ceil(box.x + box.width) - Math.floor(box.x), height: Math.ceil(box.y + box.height) - Math.floor(box.y) };
                const png = await page.screenshot({ path: path.join(out, `${name}.png`), clip, scale: 'device' });
                const edges = await edgeContrast(png, box, clip);
                results.push({ name, realControl: index < liveCount, ...style, edges });
                // This is a visual regression threshold for the metal rim,
                // not an assertion about a particular token or CSS declaration.
                for (const [side, ratio] of Object.entries(edges)) if (ratio < 2) failures.push(`${name}: ${side} rim/face contrast ${ratio.toFixed(2)} < 2`);
              } finally {
                if (state === 'active') { await page.mouse.move(0, 0); await page.mouse.up(); }
              }
            }
          }
        } finally { await context.close(); }
      }
    } finally { await browser.close(); }
  }
} finally {
  await server.close();
  fs.writeFileSync(path.join(out, 'measurements.json'), JSON.stringify({ results, failures }, null, 2) + '\n');
}
for (const failure of failures) console.error(failure);
assert.equal(failures.length, 0, 'a shared CTA loses its painted perimeter');
console.log(`check-cta-edges: ${results.length} actual/probe control states, Chromium/WebKit, EN/JA, light/dark; four painted edges remain distinct at rest, hover, keyboard focus and active`);
