/** Package dist/ and dist-ff/ into store-ready zips. */
import JSZip from 'jszip';
import { readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function addDir(zip, dir) {
  for (const f of readdirSync(dir)) {
    const full = path.join(dir, f);
    if (statSync(full).isDirectory()) addDir(zip.folder(f), full);
    else zip.file(f, statSync(full));
  }
}

for (const d of ['dist', 'dist-ff']) {
  const zip = new JSZip();
  addDir(zip, d);
  const buf = await zip.generateAsync({ type: 'nodebuffer' });
  writeFileSync(`${d}.zip`, buf);
  console.log(`✔ ${d}.zip`);
}
