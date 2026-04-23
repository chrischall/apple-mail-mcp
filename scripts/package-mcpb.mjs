#!/usr/bin/env node
// Packages apple-mail-mcp into a .mcpb file using the official mcpb tool
import { readFileSync, mkdirSync, copyFileSync, rmSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const version = pkg.version;

const staging = join(root, ".mcpb-staging");
const outFile = join(root, "apple-mail-mcp.mcpb");

// Build staging directory
rmSync(staging, { recursive: true, force: true });
mkdirSync(staging, { recursive: true });
copyFileSync(join(root, "manifest.json"), join(staging, "manifest.json"));
copyFileSync(join(root, "README.md"), join(staging, "README.md"));
copyFileSync(join(root, "build", "bundle.mjs"), join(staging, "bundle.mjs"));

// Pack using official tool
execSync(`npx @anthropic-ai/mcpb pack "${staging}" "${outFile}"`, {
  stdio: "inherit",
  cwd: root,
});

rmSync(staging, { recursive: true, force: true });
console.log(`\nCreated: apple-mail-mcp.mcpb (v${version})`);
