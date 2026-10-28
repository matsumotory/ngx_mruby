// Diagrams of docs/proposals/site.md, 3.5 ("Diagrams"): the lines, boxes
// and symbols are a drawing in SVG, site/src/diagrams/<name>.svg (and
// <name>.narrow.svg for the narrow arrangement), and the labels are HTML
// text from the page, in a fenced block with the language `diagram`:
//
//   ```diagram
//   request-phases
//   caption: What the diagram shows, as a sentence.
//   source: src/http/ngx_http_mruby_module.c 431 638-721
//   nginx: 1.31.6 src/http/ngx_http_core_module.h 111-128
//   at: 0c72e3970 2026-10-19
//   tls: TLS handshake
//   tls-h: `mruby_ssl_handshake_handler`
//   ```
//
// The first line names the drawing. caption, source, nginx and at are the
// caption's lines: what the diagram shows (also its aria-label), the files
// and lines of this repository that it describes, the lines of nginx's
// source, and the commit and date at which the lines were read. Every other
// line is a label, `key: text`; the keys are the ones that the drawings
// list in their data-labels attribute, and the generator stops on a block
// whose keys differ. In a label, `code` is set in the monospace face and
// <wbr> marks a phrase boundary (Japanese labels, 4.4).
import fs from 'node:fs';
import path from 'node:path';

export const CAPTION_KEYS = ['caption', 'source', 'nginx', 'at'];

export function diagramsDir(siteDir) {
  return path.join(siteDir, 'src', 'diagrams');
}

export function parseDiagramBlock(text, where) {
  const lines = text.split('\n');
  const name = (lines.shift() ?? '').trim();
  if (!/^[a-z0-9-]+$/.test(name)) throw new Error(`${where}: the first line of a diagram block names its drawing (a-z, 0-9 and "-"), not "${name}"`);
  const block = { name, caption: '', sources: [], nginx: [], at: null, labels: new Map() };
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue;
    const m = /^([a-z0-9-]+):\s*(.*\S)\s*$/.exec(line);
    if (!m) throw new Error(`${where}: line ${i + 2} of the diagram block ${name} is not "key: text": ${line}`);
    const [, key, value] = m;
    if (key === 'caption') {
      if (block.caption) throw new Error(`${where}: the diagram block ${name} gives caption twice`);
      block.caption = value;
    } else if (key === 'source') {
      block.sources.push(parseSource(value, `${where}: the diagram block ${name}, source`));
    } else if (key === 'nginx') {
      const [version, file, ...ranges] = value.split(/\s+/);
      if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) throw new Error(`${where}: the diagram block ${name}: "nginx:" starts with nginx's version, not "${version}"`);
      block.nginx.push({ version, ...parseSource([file, ...ranges].join(' '), `${where}: the diagram block ${name}, nginx`) });
    } else if (key === 'at') {
      const am = /^([0-9a-f]{7,40})\s+(\d{4}-\d{2}-\d{2})$/.exec(value);
      if (!am) throw new Error(`${where}: the diagram block ${name}: "at:" is a commit and its date (YYYY-MM-DD), not "${value}"`);
      block.at = { commit: am[1], date: am[2] };
    } else {
      if (block.labels.has(key)) throw new Error(`${where}: the diagram block ${name} gives the label ${key} twice`);
      block.labels.set(key, value);
    }
  }
  if (!block.caption) throw new Error(`${where}: the diagram block ${name} has no caption`);
  if (!block.sources.length) throw new Error(`${where}: the diagram block ${name} names no source in the repository`);
  if (!block.at) throw new Error(`${where}: the diagram block ${name} has no "at:" line`);
  return block;
}

function parseSource(value, where) {
  const [file, ...rest] = value.split(/\s+/);
  if (!file || !rest.length) throw new Error(`${where}: "${value}" is a file and its lines (431 or 638-721)`);
  const ranges = rest.map((r) => {
    const m = /^(\d+)(?:-(\d+))?$/.exec(r);
    if (!m) throw new Error(`${where}: "${r}" is not a line or a range of lines`);
    const a = Number(m[1]);
    const b = Number(m[2] ?? m[1]);
    if (a < 1 || b < a) throw new Error(`${where}: "${r}" is not a range of lines`);
    return [a, b];
  });
  return { file, ranges };
}

// The drawings of a diagram, with their keys. Throws on a missing drawing
// and on drawings whose keys differ.
export function loadDrawings(siteDir, name, where) {
  const dir = diagramsDir(siteDir);
  const wide = path.join(dir, `${name}.svg`);
  if (!fs.existsSync(wide)) throw new Error(`${where}: the diagram ${name} has no drawing site/src/diagrams/${name}.svg`);
  const drawings = [{ arrangement: 'wide', file: wide }];
  const narrow = path.join(dir, `${name}.narrow.svg`);
  if (fs.existsSync(narrow)) drawings.push({ arrangement: 'narrow', file: narrow });
  for (const d of drawings) {
    d.svg = fs.readFileSync(d.file, 'utf8');
    const m = /<svg\b[^>]*\bdata-labels="([^"]*)"/.exec(d.svg);
    if (!m) throw new Error(`${where}: site/src/diagrams/${path.basename(d.file)} has no data-labels attribute on <svg>`);
    d.keys = m[1].split(/\s+/).filter(Boolean);
  }
  if (drawings.length === 2 && drawings[0].keys.join(' ') !== drawings[1].keys.join(' ')) {
    throw new Error(`${where}: the two drawings of ${name} list different keys in data-labels`);
  }
  return drawings;
}

// Compares the label keys of a block with the keys of its drawing.
export function checkKeys(block, keys, where, against = 'its drawing') {
  const have = [...block.labels.keys()];
  const missing = keys.filter((k) => !block.labels.has(k));
  const extra = have.filter((k) => !keys.includes(k));
  if (missing.length || extra.length) {
    const parts = [];
    if (missing.length) parts.push(`it lacks ${missing.join(', ')}`);
    if (extra.length) parts.push(`it has ${extra.join(', ')}, which ${against} does not have`);
    throw new Error(`${where}: the keys of the diagram block ${block.name} differ from those of ${against}: ${parts.join('; ')}`);
  }
}

const escapeHtml = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

// Label text: HTML-escaped, `code` in <code>, <wbr> kept.
export function labelHtml(text) {
  return escapeHtml(text)
    .replace(/&lt;wbr&gt;/g, '<wbr>')
    .replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
}

export function plainLabel(text) {
  return text.replace(/<wbr>/g, '').replace(/`/g, '');
}

const joinList = (items, lang) => {
  if (lang === 'ja') return items.join('、');
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`;
};
const rangeText = ([a, b], lang) => (lang === 'ja' ? (a === b ? `${a}行` : `${a}行から${b}行`) : a === b ? `${a}` : `${a} to ${b}`);
const linesText = (ranges, lang) => {
  const list = joinList(ranges.map((r) => rangeText(r, lang)), lang);
  if (lang === 'ja') return list;
  return `${ranges.length === 1 && ranges[0][0] === ranges[0][1] ? 'line' : 'lines'} ${list}`;
};

// The figcaption: what the diagram shows, then the source it describes and
// when (3.5, "Keeping them true").
export function captionHtml(block, lang) {
  const nowrap = (s) => `<span class="nowrap">${s}</span>`;
  const code = (s) => `<code>${escapeHtml(s)}</code>`;
  const at = block.at;
  const repo = block.sources.map((s) => (lang === 'ja' ? `${code(s.file)}の${linesText(s.ranges, lang)}` : `${code(s.file)} ${linesText(s.ranges, lang)}`));
  let text;
  if (lang === 'ja') {
    // The files are joined with と, their lines with 、
    const files = repo.length > 1 ? `${repo.slice(0, -1).join('、')}と、${repo.at(-1)}` : repo[0];
    text = `${labelHtml(block.caption)}${files}を、${nowrap(at.date)}のコミット${code(at.commit)}で描きました。`;
    for (const n of block.nginx) text += `nginx ${nowrap(n.version)}では、${code(n.file)}の${linesText(n.ranges, lang)}を元に描きました。`;
  } else {
    text = `${labelHtml(block.caption)} Describes ${joinList(repo, lang)} at ${code(at.commit)}, ${nowrap(at.date)}`;
    for (const n of block.nginx) text += `, and ${code(n.file)} ${linesText(n.ranges, lang)} of nginx ${nowrap(n.version)}`;
    text += '.';
  }
  return text;
}

// The drawing, inlined: comments and line breaks removed, hidden from
// screen readers (3.5).
function inlineSvg(svg, arrangement) {
  return svg
    .replace(/<\?xml[^>]*>/, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\s*\n\s*/g, ' ')
    .replace(/<svg\b/, `<svg class="diagram-drawing diagram-drawing-${arrangement}" aria-hidden="true" focusable="false"`)
    .trim();
}

// The figure of 3.5: role="img" with the caption as its aria-label, the
// drawings inlined and hidden from screen readers, and each label as HTML
// text, which the diagram's CSS places on its grid. One line of HTML, so
// that Markdown keeps it as one HTML block.
export function diagramHtml(block, drawings, lang) {
  const labels = [...block.labels].map(([key, text]) => `<div class="diagram-label" data-key="${key}">${labelHtml(text)}</div>`).join('');
  const svgs = drawings.map((d) => inlineSvg(d.svg, d.arrangement)).join('');
  return `<figure class="diagram diagram-${block.name} not-content" role="img" aria-label="${escapeHtml(plainLabel(block.caption))}"><div class="diagram-grid">${svgs}${labels}</div><figcaption>${captionHtml(block, lang)}</figcaption></figure>`;
}
