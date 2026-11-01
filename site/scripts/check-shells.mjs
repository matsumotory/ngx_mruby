// Build both shells from this checkout, including the same 2.x source,
// and compare their static output. Restore the verified default output
// even when the own-shell build/check fails: deployment stays Starlight.
// node scripts/check-shells.mjs --v2-tree DIR [--evidence NEW_DIR]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const site = fileURLToPath(new URL('../', import.meta.url));
const args = process.argv.slice(2);
if (![2, 4].includes(args.length) || (args.length === 4 && args[2] !== '--evidence') || args[0] !== '--v2-tree' || !fs.statSync(path.resolve(args[1]), { throwIfNoEntry: false })?.isDirectory()) {
  console.error('Usage: node scripts/check-shells.mjs --v2-tree DIR [--evidence NEW_DIR]');
  process.exit(2);
}
const v2Tree = path.resolve(args[1]);
const evidence = args[3] ? path.resolve(args[3]) : null;
if (evidence && fs.existsSync(evidence)) {
  console.error('check-shells: evidence destination must not exist');
  process.exit(2);
}
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngx-shells-'));
const outputs = ['dist', 'generated'];
let snapshotReady = false;
let restoreFrom = path.join(temp, 'original');
const started = performance.now();

function save(to) {
  fs.mkdirSync(to, { recursive: true });
  for (const name of outputs) {
    const from = path.join(site, name);
    if (fs.existsSync(from)) fs.cpSync(from, path.join(to, name), { recursive: true });
  }
}
function run(command, commandArgs, env) {
  console.log(`check-shells: ${command} ${commandArgs.join(' ')}`);
  const result = spawnSync(command, commandArgs, { cwd: site, env, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.signal || result.status !== 0) throw new Error(`${command} ${commandArgs.join(' ')} failed (${result.signal ?? result.status})`);
}
function build(shell, destination) {
  const env = { ...process.env };
  delete env.NGX_MRUBY_SITE_SHELL;
  if (shell === 'own') env.NGX_MRUBY_SITE_SHELL = 'own';
  run('npm', ['run', 'build'], env);
  run('npm', ['run', 'build:v2', '--', '--tree', v2Tree], env);
  run('npm', ['run', 'check'], env);
  save(destination);
}

try {
  save(restoreFrom);
  snapshotReady = true;
  const base = path.join(temp, 'starlight');
  build('starlight', base);
  restoreFrom = base;
  const head = path.join(temp, 'own');
  build('own', head);
  run(process.execPath, ['scripts/check-parity.mjs', '--base', path.join(base, 'dist'), '--head', path.join(head, 'dist')], process.env);
  if (evidence) {
    // Retain only static, public build output, not the generated working data.
    fs.mkdirSync(evidence);
    fs.cpSync(path.join(base, 'dist'), path.join(evidence, 'starlight'), { recursive: true });
    fs.cpSync(path.join(head, 'dist'), path.join(evidence, 'own'), { recursive: true });
    console.log(`check-shells: passing pair saved in ${evidence}`);
  }
  console.log(`check-shells: ok; both shells and versions; ${((performance.now() - started) / 1000).toFixed(1)} s`);
} catch (error) {
  console.error(`check-shells: ${error.message}`);
  process.exitCode = 1;
} finally {
  // Only these two generated outputs are replaced; never a checkout,
  // source tree, credentials or another session's preview directory.
  for (const name of snapshotReady ? outputs : []) {
    const target = path.join(site, name);
    fs.rmSync(target, { recursive: true, force: true });
    const saved = path.join(restoreFrom, name);
    if (fs.existsSync(saved)) fs.cpSync(saved, target, { recursive: true });
  }
  fs.rmSync(temp, { recursive: true, force: true });
  console.log('check-shells: restored default output (or original output if its build failed)');
}
