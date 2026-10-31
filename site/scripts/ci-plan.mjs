// Read actual git endpoints, then bind the plan to this generated build.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { planBrowserScope, shouldMeasureScope } from './lib/ci-scope.mjs';
import { scopedPages } from './lib/ci-pages.mjs';
import { sameDocumentContract } from './lib/ci-markdown.mjs';
const git = (...args) => execFileSync('git',args,{encoding:'utf8'}).trim();
const repo = path.resolve('..');
const g = (...args) => execFileSync('git',['-C',repo,...args],{encoding:'utf8'});
let plan = {mode:'full',pages:[],reason:'event has no verified comparison'};
try {
  const event = process.env.EVENT_NAME;
  let base;
  const head = git('rev-parse','HEAD');
  if (event === 'pull_request') { git('rev-parse','--verify','HEAD^2'); base=git('rev-parse','HEAD^1'); }
  else if (event === 'push' && process.env.REF_TYPE === 'branch' && /^[0-9a-f]{40}$/.test(process.env.PUSH_BEFORE || '') && !/^0+$/.test(process.env.PUSH_BEFORE)) {
    base=process.env.PUSH_BEFORE;
    try {git('cat-file','-e',base+'^{commit}');} catch {git('fetch','--no-tags','origin',base);}
  }
  if (base) {
    const raw=g('diff','--raw','-z','--no-renames',base,head,'--').split('\0');
    if(raw.pop() !== '' || raw.length%2) throw new Error('bad raw diff');
    const changes=[];
    for(let i=0;i<raw.length;i+=2) {
      const [oldMode,newMode,,,status]=raw[i].slice(1).split(' ');
      const source=raw[i+1];
      const needsText = status === 'M' && source.startsWith('docs/') && source.endsWith('.md');
      // Unknown/build inputs select full without reading their contents.
      const text=(revision,mode)=>needsText && mode==='100644' ? g('show',`${revision}:${source}`) : '';
      changes.push({path:source,status,oldMode,newMode,oldText:text(base,oldMode),newText:text(head,newMode)});
    }
    plan=planBrowserScope({changes,manifest:JSON.parse(fs.readFileSync('generated/pages.json','utf8')),event,baselineKnown:true,manifestComplete:true});
    if(plan.mode==='targeted') {
      if(changes.some(change => change.path.startsWith('docs/') && !sameDocumentContract(change.oldText,change.newText))) plan={mode:'full',pages:[],reason:'generator-document-contract-changed'};
      else scopedPages('dist',JSON.stringify(plan.pages));
    }
    plan.measureScope=plan.mode === 'full' && shouldMeasureScope(changes,event);
    plan.base=base;
  }
} catch(error) {plan={mode:'full',pages:[],reason:`unavailable or invalid comparison: ${error.message.split('\n')[0]}`};}
fs.writeFileSync('generated/ci-scope.json',JSON.stringify(plan,null,2)+'\n');
console.log(JSON.stringify(plan));
if(process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY,'## Browser scope\n\n```json\n'+JSON.stringify(plan,null,2)+'\n```\n');

if(process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT,'mode='+plan.mode+'\nmeasure_scope='+String(plan.measureScope === true)+'\n');
