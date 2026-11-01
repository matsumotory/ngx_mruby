// Compare the base commit's default build with the current Astro site.
// Caller installs each checkout's locked dependencies. Both use one v2 tree.
// node scripts/check-shells.mjs --base-tree DIR --v2-tree DIR [--evidence NEW_DIR]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const site = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
const options = {};
for (let i = 0; i < args.length; i += 2) {
  if (!['--base-tree', '--v2-tree', '--evidence'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('usage: --base-tree DIR --v2-tree DIR [--evidence NEW_DIR]');
  options[args[i]] = path.resolve(args[i + 1]);
}
const baseSite = options['--base-tree'] && path.join(options['--base-tree'], 'site');
const v2Tree = options['--v2-tree'];
for (const dir of [baseSite, v2Tree]) if (!dir || !fs.statSync(dir, { throwIfNoEntry: false })?.isDirectory()) throw new Error('base-tree and v2-tree must exist');
if (fs.realpathSync(baseSite) === fs.realpathSync(site)) throw new Error('base checkout must be separate from head');
const evidence = options['--evidence'];
if (evidence && fs.existsSync(evidence)) throw new Error('evidence destination must not exist');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-base-head-'));
const outputs = ['dist', 'generated'];
let backupsReady = false, headBuilt = false;
const started = performance.now();
const env = { ...process.env };
// Old base commits support a shell flag. Their default is the comparison.
delete env.NGX_MRUBY_SITE_SHELL;
function save(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const name of outputs) if (fs.existsSync(path.join(from, name))) fs.cpSync(path.join(from, name), path.join(to, name), { recursive: true });
}
function restore(from, to) {
  for (const name of outputs) {
    fs.rmSync(path.join(to, name), { recursive: true, force: true });
    if (fs.existsSync(path.join(from, name))) fs.cpSync(path.join(from, name), path.join(to, name), { recursive: true });
  }
}
function run(cwd, command, commandArgs) {
  console.log(`check-shells: ${cwd}: ${command} ${commandArgs.join(' ')}`);
  const result = spawnSync(command, commandArgs, { cwd, env, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) throw new Error(`${command} ${commandArgs.join(' ')} failed (${result.signal ?? result.status})`);
}
function build(cwd, to) {
  run(cwd, 'npm', ['run', 'build']);
  run(cwd, 'npm', ['run', 'build:v2', '--', '--tree', v2Tree]);
  run(cwd, 'npm', ['run', 'check']);
  save(cwd, to);
}
try {
  save(baseSite, path.join(temp, 'original-base'));
  save(site, path.join(temp, 'original-head'));
  backupsReady = true;
  const base = path.join(temp, 'base'), head = path.join(temp, 'head');
  build(baseSite, base);
  build(site, head);
  headBuilt = true;
  for (const script of ['check-parity.mjs', 'check-search-parity.mjs']) run(site, process.execPath, [`scripts/${script}`, '--base', path.join(base, 'dist'), '--head', path.join(head, 'dist')]);
  if (evidence) {
    fs.mkdirSync(evidence);
    fs.cpSync(path.join(base, 'dist'), path.join(evidence, 'base'), { recursive: true });
    fs.cpSync(path.join(head, 'dist'), path.join(evidence, 'head'), { recursive: true });
    console.log(`check-shells: passing pair saved in ${evidence}`);
  }
  console.log(`check-shells: ok; base/head and both versions; ${((performance.now() - started) / 1000).toFixed(1)} s`);
} catch (error) {
  console.error(`check-shells: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (backupsReady) {
    restore(path.join(temp, 'original-base'), baseSite);
    if (!headBuilt) restore(path.join(temp, 'original-head'), site);
  }
  fs.rmSync(temp, { recursive: true, force: true });
  console.log(`check-shells: base output restored; head ${headBuilt ? 'build retained' : 'original output restored'}`);
}
