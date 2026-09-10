/**
 * Zero-dependency PNG generator for the extension icon (128×128).
 * Draws a dark tile with a green shield-ish glyph. Run via build.js.
 */
import zlib from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

const W = 128, H = 128;

const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (const b of buf) c = crcTable[(c ^ b) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])));
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

function px(x, y) {
  // background tile
  let r = 0x0b, g = 0x0e, b = 0x14;
  const cx = 64, cy = 60;
  const d = Math.hypot(x - cx, y - cy);
  // shield: circle body + pointed bottom
  const inShield = (y <= cy && d < 42) || (y > cy && y < cy + 46 && Math.abs(x - cx) < Math.max(0, 42 - (y - cy) * 0.9));
  if (inShield) {
    r = 0x00; g = 0xe5; b = 0x9a; // accent green
    // inner check mark
    const onCheck =
      (y >= 46 && y <= 62 && Math.abs(x - (24 + (y - 46) * 1.2) - 14) < 4) ||
      (y >= 60 && y <= 84 && Math.abs(x - (104 - (y - 60) * 1.4)) < 4);
    if (onCheck) { r = 0x04; g = 0x12; b = 0x0c; }
  }
  return [r, g, b];
}

export function writeIcon(dir) {
  mkdirSync(dir, { recursive: true });
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 2;  // color type RGB
  const raw = Buffer.alloc(H * (1 + W * 3));
  let o = 0;
  for (let y = 0; y < H; y++) {
    raw[o++] = 0; // filter none
    for (let x = 0; x < W; x++) {
      const [r, g, b] = px(x, y);
      raw[o++] = r; raw[o++] = g; raw[o++] = b;
    }
  }
  const png = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  writeFileSync(path.join(dir, 'icon128.png'), png);
}
