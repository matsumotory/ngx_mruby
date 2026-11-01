import { execFileSync } from 'node:child_process';
import { buildSidebar } from './sidebar.mjs';
import { t } from './strings.mjs';
import { SITE_VERSION, BASE } from '../../scripts/lib/site.mjs';
export function makeRoute(astro,entry,entries,headings=[],isFallback=false) {
 const pathname=astro.url.pathname;
 const locale=pathname.slice(BASE.length).startsWith('/ja')?'ja':undefined;
 const lang=locale||'en';
 const sidebar=buildSidebar(entries,{locale,pathname,version:SITE_VERSION,base:BASE});
 const flatten=items=>items.flatMap(x=>x.type==='group'?flatten(x.entries):[x]);
 const links=flatten(sidebar); const i=links.findIndex(x=>x.isCurrent||x.href===pathname);
 const configureLink=(link,value)=>{
   if(value===false)return undefined;
   if(typeof value==='string'&&link)return {...link,label:value};
   if(value&&typeof value==='object')return link?{...link,label:value.label??link.label,href:value.link??link.href,attrs:{}}:value.link&&value.label?{type:'link',label:value.label,href:value.link,attrs:{},isCurrent:false}:undefined;
   return link;
 };
 const prev=configureLink(links[i-1],entry.data.prev);
 const next=configureLink(i<0?undefined:links[i+1],entry.data.next);
 let lastUpdated=entry.data.lastUpdated;
 if(lastUpdated===true&&entry.filePath){
   try{const raw=execFileSync('git',['log','-1','--format=%cI','--',entry.filePath],{encoding:'utf8'}).trim();lastUpdated=raw?new Date(raw):undefined;}catch{lastUpdated=undefined;}
 }
 const tocItems=[{depth:2,slug:'_top',text:locale==='ja'?'概要':'Overview',children:[]}];
 for(const h of headings.filter(h=>h.depth>=2&&h.depth<=3)){
   const item={...h,children:[]};if(h.depth===3&&tocItems.length)tocItems.at(-1).children.push(item);else tocItems.push(item);
 }
 astro.locals.t=key=>t(locale,key);
 return {id:pathname.slice(BASE.length).replace(/^\//,'').replace(/\/$/,''),entry,locale,lang,dir:'ltr',isFallback,
  entryMeta:{lang:isFallback?'en':lang,dir:'ltr',locale:isFallback?undefined:locale},
  headings,sidebar,hasSidebar:entry.data.template!=='splash',
  toc:entry.data.template==='splash'?undefined:{items:tocItems,minHeadingLevel:2,maxHeadingLevel:3},
  pagination:{prev,next},lastUpdated:lastUpdated instanceof Date?lastUpdated:undefined,
  siteTitle:'ngx_mruby',siteTitleHref:BASE+(locale?'/ja/':'/')};
}
