// Defense in depth: use the generator's actual parser, not just line patterns,
// before narrowing a document to local browser coverage.
import {parseMarkdown,plainText,titleHeading,isFirstBlock} from './markdown.mjs';
export function documentContract(source) {
  const tree=parseMarkdown(source), title=titleHeading(tree);
  const protectedNodes=[];
  function visit(node,ancestors=[]) {
    const parentTypes=[...ancestors,node.type];
    if(node.type==='heading') protectedNodes.push({parents:ancestors,depth:node.depth,text:plainText(node,source)});
    if(node.type==='code') protectedNodes.push({parents:ancestors,lang:node.lang??null,meta:node.meta??null,value:node.value});
    if(['inlineCode','html','yaml','toml','mdxjsEsm','mdxFlowExpression','mdxTextExpression'].includes(node.type)) protectedNodes.push({parents:ancestors,type:node.type,value:node.value});
    for(const child of node.children??[]) visit(child,parentTypes);
  }
  visit(tree);
  return {title:title?plainText(title,source):null,titleRemoved:title?isFirstBlock(tree,title):false,protectedNodes};
}
export function sameDocumentContract(before,after) {
  return JSON.stringify(documentContract(before))===JSON.stringify(documentContract(after));
}
