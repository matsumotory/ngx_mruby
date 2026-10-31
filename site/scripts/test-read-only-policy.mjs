import assert from 'node:assert/strict';
import { allowsReadOnlyRequest } from './lib/read-only-browser.mjs';
import { OPENSSF_BADGE } from './lib/project-badges.mjs';
const origin = 'https://ngx.mruby.org';
const request = (url, method = 'GET', type = 'image') => ({ url: () => url, method: () => method, resourceType: () => type });
assert.equal(allowsReadOnlyRequest(request(origin + '/local.svg'), origin), true);
assert.equal(allowsReadOnlyRequest(request(OPENSSF_BADGE.src), origin), false, 'default stays same-origin only');
const images = [OPENSSF_BADGE.src];
assert.equal(allowsReadOnlyRequest(request(OPENSSF_BADGE.src), origin, images), true);
for (const method of ['POST', 'HEAD', 'PUT']) assert.equal(allowsReadOnlyRequest(request(OPENSSF_BADGE.src, method), origin, images), false);
for (const type of ['fetch', 'document', 'script', 'stylesheet', 'xhr']) assert.equal(allowsReadOnlyRequest(request(OPENSSF_BADGE.src, 'GET', type), origin, images), false);
for (const url of [OPENSSF_BADGE.src + '/', OPENSSF_BADGE.src + '?tracking=1', OPENSSF_BADGE.src.replace('16057', '16058'), OPENSSF_BADGE.src.replace('www.', ''), OPENSSF_BADGE.src.replace('https:', 'http:')]) {
  assert.equal(allowsReadOnlyRequest(request(url), origin, images), false, url);
}
console.log('test-read-only-policy: exact opted-in image GET only; default, methods, resource types and URL near misses rejected');
