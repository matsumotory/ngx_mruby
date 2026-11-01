import assert from 'node:assert/strict';
import { ownSchema } from '../src/own/schema.mjs';
import { buildSidebar,makeToc } from '../src/own/sidebar.mjs';
import { getSiteRoute, routeLabel } from '../src/route.mjs';
import { makeRoute } from '../src/own/routes.mjs';
import { strings } from '../src/own/strings.mjs';
import { BASE } from './lib/site.mjs';
assert.equal(ownSchema.parse({title:'Test'}).template,'doc');
assert.throws(()=>ownSchema.parse({title:'Test',unknown:'dropped?'}));
assert.throws(()=>ownSchema.parse({title:'Test',template:'invalid'}));
assert.equal(ownSchema.parse({title:'Test',lastUpdated:'2026-10-31'}).lastUpdated.toISOString(),'2026-10-31T00:00:00.000Z');
assert.equal(ownSchema.parse({title:'Test',lastUpdated:false}).lastUpdated,false);
assert.equal(ownSchema.parse({title:'Test',lastUpdated:true}).lastUpdated,true);
assert.throws(()=>ownSchema.parse({title:'Test',sidebar:{unknown:'lost'}}));
const fallback={id:'guides/test',data:{title:'English',sidebar:{order:1}}};
const entries=[{id:'index',data:{title:'Home'}},{id:'docs',data:{title:'Overview'}},{id:'start',data:{title:'Start'}},fallback];
const sidebar=buildSidebar(entries,{locale:'ja',pathname:'/ja/guides/test/',base:'',version:3});
const link=sidebar.find(e=>e.label==='ガイド').entries[0];
assert.equal(link.href,'/ja/guides/test/');assert.equal(link.isCurrent,true);assert.equal(link.label,'English');
assert.equal(makeToc([{depth:2,slug:'a',text:'A'},{depth:3,slug:'b',text:'B'}],'ja').items[1].children[0].slug,'b');
const own={entry:{}};assert.equal(getSiteRoute({siteRoute:own,starlightRoute:{}}),own);
assert.throws(()=>getSiteRoute({}));
// Exercise the actual route builder, not only the ToC helper. A leading h3
// belongs to Overview; h1 and h4 must never become ToC entries.
const headings = [
  {depth:1,slug:'title',text:'Title'},
  {depth:3,slug:'intro-detail',text:'Intro detail'},
  {depth:2,slug:'first',text:'First'},
  {depth:4,slug:'hidden',text:'Hidden'},
  {depth:3,slug:'detail',text:'Detail'},
  {depth:2,slug:'second',text:'Second'},
];
for (const locale of [undefined, 'ja']) {
  const astro = {url:new URL(`https://ngx.mruby.org${BASE}/${locale ? locale+'/' : ''}guides/test/`),locals:{}};
  const route = makeRoute(astro,fallback,entries,headings,locale==='ja');
  assert.deepEqual(route.toc,makeToc(headings,locale));
  assert.deepEqual(route.toc.items.map(item=>item.slug),['_top','first','second']);
  assert.equal(route.toc.items[0].text,locale==='ja'?'概要':'Overview');
  assert.equal(route.toc.items[0].children[0].slug,'intro-detail');
  assert.equal(route.toc.items[1].children[0].slug,'detail');
  assert.deepEqual(route.headings,headings);
  assert.deepEqual(makeRoute(astro,fallback,entries).toc.items,[
    {depth:2,slug:'_top',text:locale==='ja'?'概要':'Overview',children:[]},
  ]);
  const splash = {...fallback,data:{...fallback.data,template:'splash'}};
  assert.equal(makeRoute(astro,splash,entries,headings).toc,undefined);
  const locals = {siteRoute:route};
  for (const key of ['sidebarNav.accessibleLabel','menuButton.accessibleLabel','page.lastUpdated','page.previousLink','page.nextLink']) {
    assert.equal(routeLabel(locals,key),strings(locale)[key]);
    assert.equal(astro.locals.t(key),routeLabel(locals,key));
  }
  assert.throws(()=>routeLabel(locals,'unknown.label'),/Unknown shared route label/);
}
// The completed migration must reject a legacy route, even with a translator.
assert.throws(()=>routeLabel({starlightRoute:{},t:key=>`legacy:${key}`},'page.nextLink'),/Site route is unavailable/);
assert.throws(()=>getSiteRoute({starlightRoute:{}}),/Site route is unavailable/);
console.log('test-own-shell: schema, fallback navigation, ToC and shared route contract pass');
