/**
 * Build script: bundles extension sources with esbuild into dist/ (Chrome MV3)
 * and dist-ff/ (Firefox). Copies static assets + local model weights if the
 * models/ directory exists (offline-first; see README "Local models").
 */
import esbuild from 'esbuild';
import { cpSync, mkdirSync, existsSync, copyFileSync, rmSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { writeIcon } from './gen-icon.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const entryPoints = {
  'background.bundle.js': 'extension/background/background.js',
  'content.bundle.js': 'extension/content/content.js',
  'offscreen.bundle.js': 'extension/offscreen/offscreen.js',
};

/** @type {import('esbuild').BuildOptions} */
const opts = {
  bundle: true,
  format: 'iife',
  target: ['chrome116', 'firefox115'],
  minify: false,
  sourcemap: 'inline',
  logLevel: 'info',
  define: { 'process.env.NODE_ENV': '"production"' },
  // Transformers.js ships as ESM with dynamic imports — mark as external-free;
  // esbuild resolves worker/node shims automatically with platform browser.
  platform: 'browser',
};

function build(outdir, { offscreen }) {
  mkdirSync(outdir, { recursive: true });
  for (const [out, entry] of Object.entries(entryPoints)) {
    if (out === 'offscreen.bundle.js' && offscreen) continue; // FF hosts vision in background page
    esbuild.buildSync({ ...opts, entryPoints: [path.join(root, entry)], outfile: path.join(outdir, out) });
  }
  // static assets
  cpSync(path.join(root, 'extension/popup'), path.join(outdir, 'popup'), { recursive: true });
  writeIcon(path.join(outdir, 'icons'));
  copyFileSync(
    path.join(root, offscreen ? 'extension/manifest.firefox.json' : 'extension/manifest.chrome.json'),
    path.join(outdir, 'manifest.json'),
  );
  if (offscreen) {
    // FF has no offscreen doc; vision-host.js is bundled into background.
    rmSync(path.join(outdir, 'offscreen.bundle.js'), { force: true });
    rmSync(path.join(outdir, 'offscreen.html'), { force: true });
  } else {
    copyFileSync(path.join(root, 'extension/offscreen/offscreen.html'), path.join(outdir, 'offscreen.html'));
  }
  // optional local model weights for fully offline use
  const modelsDir = path.join(root, 'models');
  if (existsSync(modelsDir)) cpSync(modelsDir, path.join(outdir, 'models'), { recursive: true });
  // vendor onnxruntime-web wasm binaries next to any vendored weights
  const ortDir = path.join(root, 'node_modules/onnxruntime-web/dist');
  if (existsSync(ortDir)) {
    const wasmOut = path.join(outdir, 'models/wasm');
    mkdirSync(wasmOut, { recursive: true });
    for (const f of readdirSync(ortDir)) if (f.endsWith('.wasm')) copyFileSync(path.join(ortDir, f), path.join(wasmOut, f));
  }
  console.log(`✔ built ${outdir}`);
}

build('dist', { offscreen: false });
build('dist-ff', { offscreen: true });
