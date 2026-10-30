// The checks of step 7 (docs/proposals/site.md, section 6; Q5 and Q6 of
// section 7) that can run on the built site before it is deployed:
//
// - the files of VERBATIM_FILES in scripts/lib/site.mjs (the Google site
//   verification file that Q5 keeps) are in the built site at the path
//   they had on the old site, with the size and the SHA-256 of the copy on
//   the gh-pages branch, and equal to their copy in public/;
// - no analytics script (Q6): no <script> of any HTML file loads a script
//   from another host, and no HTML or JavaScript file of the built site
//   names Google Analytics, Google Tag Manager or gtag.
//
// The checks on the live site after the switch are in check-live.mjs,
// which a session runs by hand ("The site" in AGENTS.md).
//
//   node scripts/check-deploy.mjs [--dist DIR]
//
// Exit status: 0 when every check passes, 1 otherwise (each problem is
// printed with its file), 2 on a usage error.
import { SHARE_IMAGE, V3_SHARE_IMAGE, shareImageForVersion } from './lib/brand.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { elements, readHtml } from './lib/html.mjs';
import { distDir, finish, siteDir, SITE_URL, VERBATIM_FILES } from './lib/site.mjs';

function args() {
  const a = process.argv.slice(2);
  const out = { dist: distDir };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--dist' && i + 1 < a.length) out.dist = path.resolve(a[++i]);
    else {
      console.error(`check-deploy.mjs: unknown argument ${a[i]}`);
      console.error('usage: node scripts/check-deploy.mjs [--dist DIR]');
      process.exit(2);
    }
  }
  if (!fs.existsSync(path.join(out.dist, 'index.html'))) {
    console.error(`check-deploy.mjs: ${out.dist} has no index.html: run npm run build first`);
    process.exit(2);
  }
  return out;
}

// Names of analytics and tag scripts, as they appear in a script URL or in
// the code that loads one: Google Analytics (ga.js, analytics.js, gtag.js),
// Google Tag Manager, and the global objects they define.
const ANALYTICS = /google-analytics\.com|googletagmanager\.com|\bgtag\s*\(|GoogleAnalyticsObject|\b_gaq\b|\bga\.js\b|\banalytics\.js\b|\bdataLayer\s*\.\s*push/i;

const { dist } = args();
const problems = [];

const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');
for (const { file, bytes, sha256: want } of VERBATIM_FILES) {
  const built = path.join(dist, file);
  if (!fs.existsSync(built)) {
    problems.push(`${file}: missing from the built site`);
    continue;
  }
  const data = fs.readFileSync(built);
  if (data.length !== bytes) problems.push(`${file}: ${data.length} bytes, not the ${bytes} of the gh-pages copy`);
  if (sha256(data) !== want) problems.push(`${file}: SHA-256 ${sha256(data)}, not ${want} of the gh-pages copy`);
  const source = path.join(siteDir, 'public', file);
  if (!fs.existsSync(source) || !data.equals(fs.readFileSync(source))) {
    problems.push(`${file}: differs from public/${file}`);
  }
}

const files = [];
const walk = (dir) => {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\.(html|js|mjs)$/.test(entry.name)) files.push(full);
  }
};
walk(dist);

const origin = new URL(SITE_URL).origin;
for (const SHARE_IMAGE of [shareImageForVersion(2), V3_SHARE_IMAGE]) {
const shareFile = path.join(dist, SHARE_IMAGE.file);
if (!fs.existsSync(shareFile)) problems.push('sharing image: missing');
else {
  const png = fs.readFileSync(shareFile);
  if (png.length < 24 || png.subarray(0, 8).toString('hex') !== '89504e470d0a1a0a' ||
      png.readUInt32BE(16) !== SHARE_IMAGE.width || png.readUInt32BE(20) !== SHARE_IMAGE.height) {
    problems.push('sharing image: PNG signature or dimensions differ from metadata');
  }
}
}
let scripts = 0, sharedPages = 0;
for (const full of files) {
  const rel = path.relative(dist, full).split(path.sep).join('/');
  const text = fs.readFileSync(full, 'utf8');
  const match = text.match(ANALYTICS);
  if (match) problems.push(`${rel}: names an analytics script ("${match[0]}")`);
  if (!rel.endsWith('.html')) continue;
  const nodes = [...elements(readHtml(full))];
  if (!VERBATIM_FILES.some(v => v.file === rel)) {
    const SHARE_IMAGE = shareImageForVersion(rel.startsWith('v2/') ? 2 : 3);
    const required = {
      'og:image': `${SITE_URL}/${SHARE_IMAGE.file}`,
      'og:image:width': String(SHARE_IMAGE.width),
      'og:image:height': String(SHARE_IMAGE.height),
      'og:image:type': SHARE_IMAGE.type,
      'og:image:alt': SHARE_IMAGE.alt,
      'twitter:image': `${SITE_URL}/${SHARE_IMAGE.file}`,
      'twitter:image:alt': SHARE_IMAGE.alt,
    };
    for (const [key, value] of Object.entries(required)) {
      const metas = nodes.filter(n => n.tagName === 'meta' && (n.properties?.property === key || n.properties?.name === key));
      if (metas.length !== 1 || metas[0].properties.content !== value) problems.push(`${rel}: wrong or duplicate ${key}`);
    }
    sharedPages++;
  }
  for (const element of nodes) {
    if (element.tagName !== 'script') continue;
    scripts++;
    const src = element.properties?.src;
    if (src === undefined) continue;
    const url = new URL(src, `${origin}/${rel}`);
    if (url.origin !== origin) problems.push(`${rel}: <script src="${src}"> loads a script from ${url.origin}`);
  }
}

finish(
  'check-deploy',
  problems,
  `${VERBATIM_FILES.map((v) => `${v.file} (${v.bytes} bytes)`).join(', ')} as on gh-pages; ${sharedPages} pages with sharing metadata; ${files.length} HTML and JavaScript files and ${scripts} <script> elements read for analytics and scripts from another host`,
);
