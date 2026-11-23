// Renders src-tauri/icons/source/vaultpass.svg to a 1024px PNG (needs `sharp`).
// Usage: node scripts/render-icon.mjs [size] [out]
import { readFileSync } from "node:fs";
import sharp from "sharp";

const size = Number(process.argv[2] ?? 1024);
const out = process.argv[3] ?? "src-tauri/icons/source/vaultpass-1024.png";
const svg = readFileSync("src-tauri/icons/source/vaultpass.svg");

await sharp(svg, { density: 384 }).resize(size, size).png().toFile(out);
console.log(`wrote ${out} (${size}x${size})`);
