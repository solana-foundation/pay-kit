#!/usr/bin/env node
// Classify a PR's changed files without relying on GitHub's path-filter limit.
import { appendFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export const WORKFLOWS = [
  "typescript",
  "rust",
  "go",
  "python",
  "ruby",
  "lua",
  "php",
  "swift",
  "kotlin",
  "harness",
];

const LANGUAGE_PATHS = {
  typescript: ["typescript/", "html/"],
  rust: ["rust/"],
  go: [
    "go/",
    "harness/go-client/",
    "harness/go-server/",
    ".github/workflows/go.yml",
    ".github/workflows/go-consumer.yml",
  ],
  python: [
    "python/",
    "harness/python-server/",
    ".github/workflows/python.yml",
  ],
  ruby: ["ruby/", "harness/ruby-server/", ".github/workflows/ruby.yml"],
  lua: ["lua/", "harness/lua-server/", ".github/workflows/lua.yml"],
  php: ["php/", "harness/php-server/", ".github/workflows/php.yml"],
  swift: [
    "swift/",
    "Package.swift",
    "harness/swift-client/",
    "harness/swift-x402-client/",
    "harness/swift-x402-upto-client/",
    ".github/workflows/swift.yml",
  ],
  kotlin: [
    "kotlin/",
    "harness/kotlin-client/",
    "harness/kotlin-conformance/",
    "harness/kotlin-x402-client/",
    "harness/kotlin-x402-upto-client/",
    ".github/workflows/kotlin.yml",
  ],
};

const HARNESS_PATHS = [
  "harness/",
  ".github/actions/setup-harness/",
  ".github/actions/setup-harness-leg/",
  ".github/workflows/harness.yml",
];

function matches(path, prefixes) {
  return prefixes.some((prefix) => path === prefix || path.startsWith(prefix));
}

function isDocumentation(path) {
  return (
    path.startsWith("docs/") ||
    path.startsWith(".github/ISSUE_TEMPLATE/") ||
    path.endsWith(".md")
  );
}

function allWorkflows() {
  return Object.fromEntries(WORKFLOWS.map((name) => [name, true]));
}

export function selectWorkflows(files) {
  const selected = Object.fromEntries(WORKFLOWS.map((name) => [name, false]));

  if (files.length === 0) {
    return allWorkflows();
  }

  for (const changedPath of files) {
    if (isDocumentation(changedPath)) {
      continue;
    }

    const language = WORKFLOWS.find(
      (name) => name !== "harness" && matches(changedPath, LANGUAGE_PATHS[name]),
    );
    if (language) {
      selected[language] = true;
      continue;
    }

    if (matches(changedPath, HARNESS_PATHS)) {
      selected.harness = true;
      continue;
    }

    // An unclassified source or CI path must never silently skip verification.
    return allWorkflows();
  }

  return selected;
}

function main() {
  const files = readFileSync(0, "utf8")
    .split(/\r?\n/)
    .map((path) => path.trim())
    .filter(Boolean);
  const selected = selectWorkflows(files);
  const outputIndex = process.argv.indexOf("--github-output");

  if (outputIndex === -1) {
    process.stdout.write(`${JSON.stringify(selected)}\n`);
    return;
  }

  const outputPath = process.argv[outputIndex + 1];
  if (!outputPath) {
    throw new Error("--github-output requires a file path");
  }
  for (const [name, enabled] of Object.entries(selected)) {
    appendFileSync(outputPath, `${name}=${enabled}\n`);
  }
  process.stdout.write(`selected: ${Object.entries(selected)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name)
    .join(", ") || "none"}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
