#!/usr/bin/env node
// Bundles the MCP server with version inlined to avoid runtime require('../package.json')
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const { version } = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

execSync(
  `esbuild src/index.ts --bundle --platform=node --format=esm ` +
    `--define:__MCPB_VERSION__=\\"${version}\\" ` +
    `--outfile=build/bundle.mjs`,
  { stdio: "inherit", cwd: root }
);
