// HTML helpers for the checks of site/scripts. They parse the built pages
// with satteri's HTML parser and never run a script.
import fs from 'node:fs';
import { htmlToHast } from 'satteri';

export function readHtml(file) {
  return htmlToHast(fs.readFileSync(file, 'utf8'));
}

// Every element under a node, in document order.
export function elements(node) {
  const result = [];
  const walk = (n) => {
    for (const child of n.children ?? []) {
      if (child.type === 'element') {
        result.push(child);
        walk(child);
      }
    }
  };
  walk(node);
  return result;
}

export function findElement(node, test) {
  return elements(node).find(test);
}

export function hasClass(element, name) {
  const value = element.properties?.className ?? element.properties?.class;
  const list = Array.isArray(value) ? value : String(value ?? '').split(/\s+/);
  return list.includes(name);
}

export function textContent(node) {
  if (node.type === 'text') return node.value;
  return (node.children ?? []).map(textContent).join('');
}

// Elements whose content a reader of the page does not see as text, with
// or without JavaScript: scripts, styles, templates, the drawings of
// inline SVG, elements with the hidden attribute, and the site's sr-only
// text (heading anchor labels for screen readers).
function isUnseen(element) {
  if (['script', 'style', 'template', 'svg'].includes(element.tagName)) return true;
  const hidden = element.properties?.hidden;
  if (hidden !== undefined && hidden !== false && hidden !== null) return true;
  return hasClass(element, 'sr-only');
}

// Elements that do not end a word: text on both sides of them runs on.
export const INLINE = new Set([
  'a', 'abbr', 'b', 'bdi', 'bdo', 'cite', 'code', 'data', 'del', 'dfn', 'em', 'i', 'ins', 'kbd',
  'mark', 'q', 's', 'samp', 'small', 'span', 'strong', 'sub', 'sup', 'time', 'u', 'var', 'wbr',
]);

// The text that a reader sees in a node of the static HTML, without CSS
// and without running scripts. Elements that are not inline end a word.
export function visibleText(node) {
  if (node.type === 'text') return node.value;
  if (node.type !== 'element' && node.type !== 'root') return '';
  if (node.type === 'element' && isUnseen(node)) return '';
  const inner = (node.children ?? []).map(visibleText).join('');
  return node.type === 'element' && !INLINE.has(node.tagName) ? ` ${inner} ` : inner;
}
