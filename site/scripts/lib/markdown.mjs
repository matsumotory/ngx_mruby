// Markdown helpers shared by the generator and the checks of site/scripts.
// They parse with satteri, the parser that Astro 7 renders Markdown with,
// and turn on the features that Starlight turns on (GFM, front matter and
// ::: directives), so that they see the same headings, links and text as
// the build.
import { markdownToMdast } from 'satteri';
import { INLINE } from './html.mjs';

const FEATURES = { gfm: true, frontmatter: true, directive: true };

// An mdast tree whose positions are offsets into the JavaScript string.
export function parseMarkdown(source) {
  return markdownToMdast(source, { features: FEATURES, position: true });
}

// The heading that gives a page its title: the first heading at the top
// level of the file (docs/proposals/site.md, 5.2).
export function titleHeading(tree) {
  return tree.children.find((node) => node.type === 'heading');
}

// True when only HTML comments come before the heading. The generator then
// removes the heading from the body, since Starlight shows the title as the
// h1 of the page. A heading further down stays where it is.
export function isFirstBlock(tree, heading) {
  for (const node of tree.children) {
    if (node === heading) return true;
    if (node.type === 'html' && /^\s*<!--[\s\S]*-->\s*$/.test(node.value)) continue;
    return false;
  }
  return false;
}

export function containsHtml(node) {
  return node.type === 'html' || (node.children ?? []).some(containsHtml);
}

const raw = (node, source) => source.slice(node.position.start.offset, node.position.end.offset);

// The text that a reader sees of inline content. An inline HTML tag that
// HTML renders inline (<wbr>, <code>, <a>) joins the text on both sides, as
// in the built page; any other tag (<br>) and an image separate it. Text
// and leaf directives that Starlight does not claim stay as their source
// text (Starlight's directive restoration): "(14:50 JST)" is text, though
// the parser reads ":50" as a directive.
function inlineText(node, source) {
  switch (node.type) {
    case 'text':
    case 'inlineCode':
      return node.value;
    case 'break':
    case 'image':
    case 'imageReference':
      return ' ';
    case 'footnoteReference':
      return '';
    case 'html': {
      if (/^<!--/.test(node.value)) return '';
      const tag = /^<\/?([A-Za-z][A-Za-z0-9-]*)/.exec(node.value);
      return tag && INLINE.has(tag[1].toLowerCase()) ? '' : ' ';
    }
    case 'textDirective':
      return raw(node, source);
    default:
      return (node.children ?? []).map((child) => inlineText(child, source)).join('');
  }
}

// The text of a node in reading order, one piece per block (a paragraph,
// a heading, a table cell, a code block), each with its line in the source.
// It leaves out what a reader does not see as text: raw HTML blocks, link
// definitions, front matter and the URLs of links. Footnote definitions
// come last, where GFM renders them. `skip` is a node to leave out.
export function textPieces(tree, source, skip) {
  const pieces = [];
  const footnotes = [];
  const block = (node) => {
    if (node === skip) return;
    const line = node.position?.start.line;
    switch (node.type) {
      case 'paragraph':
      case 'heading':
      case 'tableCell':
        pieces.push({ text: inlineText(node, source), line });
        return;
      case 'code':
        // A diagram block shows its labels and caption, not its keys and
        // source lines; a sample block shows the files it names
        // (scripts/lib/diagrams.mjs, samples.mjs, 3.5).
        if (node.lang === 'sample') return;
        if (node.lang === 'diagram') {
          // The labels, in the order of the block, then the caption
          let caption = '';
          for (const l of node.value.split('\n').slice(1)) {
            const m = /^([a-z0-9-]+):\s*(.*)$/.exec(l);
            if (!m || ['source', 'nginx', 'at'].includes(m[1])) continue;
            const text = m[2].replace(/<wbr>/g, '').replace(/`/g, '');
            if (m[1] === 'caption') caption = text;
            else pieces.push({ text, line });
          }
          pieces.push({ text: caption, line });
          return;
        }
        pieces.push({ text: node.value, line });
        return;
      case 'leafDirective':
        pieces.push({ text: raw(node, source), line });
        return;
      case 'html':
      case 'definition':
      case 'yaml':
      case 'toml':
      case 'thematicBreak':
        return;
      case 'footnoteDefinition':
        footnotes.push(node);
        return;
      default:
        for (const child of node.children ?? []) block(child);
    }
  };
  block(tree);
  for (const footnote of footnotes) for (const child of footnote.children) block(child);
  return pieces;
}

// The plain text of a heading, as the title of a page or the text of a
// heading element: what a reader sees, with runs of white space made one
// space.
export function plainText(node, source) {
  return inlineText(node, source).replace(/\s+/g, ' ').trim();
}

// The headings of a tree in reading order, except `skip`.
export function headings(tree, skip) {
  const result = [];
  const walk = (n) => {
    if (n === skip) return;
    if (n.type === 'heading') result.push(n);
    for (const child of n.children ?? []) walk(child);
  };
  walk(tree);
  return result;
}

// The words of a text: runs of letters, marks and digits. Punctuation,
// white space and underscores separate them, so the words of a text do not
// depend on the quotes that smart punctuation puts in, or on Markdown's
// _emphasis_.
export function words(text) {
  return text.match(/[\p{L}\p{M}\p{N}]+/gu) ?? [];
}
