import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const srcTauriDir = join(rootDir, "src-tauri");

function detectTargetTriple() {
  if (process.env.TAURI_ENV_TARGET_TRIPLE) {
    return process.env.TAURI_ENV_TARGET_TRIPLE.trim();
  }
  const output = execFileSync("rustc", ["-vV"], { encoding: "utf8" });
  const match = output.match(/^host:\s+(\S+)/m);
  if (!match) {
    throw new Error("Unable to detect Rust host target triple from `rustc -vV`.");
  }
  return match[1];
}

const triple = detectTargetTriple();
const exeExt = process.platform === "win32" ? ".exe" : "";

console.log(`Building vaultpass-cli (${triple})...`);
execFileSync(
  "cargo",
  ["build", "--release", "--bin", "vaultpass-cli", "--target", triple],
  {
    cwd: srcTauriDir,
    stdio: "inherit",
  }
);

const builtCliPath = join(
  srcTauriDir,
  "target",
  triple,
  "release",
  `vaultpass-cli${exeExt}`
);
const binariesDir = join(srcTauriDir, "binaries");
const stagedSidecarPath = join(binariesDir, `vaultpass-cli-${triple}${exeExt}`);

mkdirSync(binariesDir, { recursive: true });
copyFileSync(builtCliPath, stagedSidecarPath);
console.log(`Staged sidecar binary at ${stagedSidecarPath}`);
