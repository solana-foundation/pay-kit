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
  typescript: { directories: ["typescript", "html"] },
  rust: { directories: ["rust"] },
  go: {
    directories: ["go", "harness/go-client", "harness/go-server"],
    files: [".github/workflows/go.yml", ".github/workflows/go-consumer.yml"],
  },
  python: {
    directories: [
      "python",
      "harness/python-server",
      "harness/python-session-client",
      "harness/python-x402-client",
      "harness/python-x402-upto-client",
    ],
    files: [".github/workflows/python.yml"],
  },
  ruby: {
    directories: ["ruby", "harness/ruby-server"],
    files: [".github/workflows/ruby.yml"],
  },
  lua: {
    directories: ["lua", "harness/lua-server", "harness/lua-protocol-runner"],
    files: [".github/workflows/lua.yml"],
  },
  php: {
    directories: ["php", "harness/php-server"],
    files: [".github/workflows/php.yml"],
  },
  swift: {
    directories: [
      "swift",
      "harness/swift-client",
      "harness/swift-x402-client",
      "harness/swift-x402-upto-client",
    ],
    files: ["Package.swift", ".github/workflows/swift.yml"],
  },
  kotlin: {
    directories: [
      "kotlin",
      "harness/kotlin-client",
      "harness/kotlin-conformance",
      "harness/kotlin-x402-client",
      "harness/kotlin-x402-upto-client",
    ],
    files: [".github/workflows/kotlin.yml"],
  },
};

const SHARED_HARNESS_PATHS = {
  directories: [
    "harness",
    ".github/actions/setup-harness",
    ".github/actions/setup-harness-leg",
  ],
  files: [".github/workflows/harness.yml"],
};

function matchesDirectory(path, directory) {
  return path.startsWith(`${directory}/`);
}

function matches(path, { directories = [], files = [] }) {
  return (
    files.includes(path) ||
    directories.some((directory) => matchesDirectory(path, directory))
  );
}

function isDocumentation(path) {
  return (
    matchesDirectory(path, "docs") ||
    matchesDirectory(path, ".github/ISSUE_TEMPLATE") ||
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
      (name) =>
        name !== "harness" && matches(changedPath, LANGUAGE_PATHS[name]),
    );
    if (language) {
      selected[language] = true;
      continue;
    }

    if (matches(changedPath, SHARED_HARNESS_PATHS)) {
      return allWorkflows();
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
  const docsOnly = files.length > 0 && Object.values(selected).every((enabled) => !enabled);
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
  appendFileSync(outputPath, `docs_only=${docsOnly}\n`);
  process.stdout.write(
    `selected: ${
      Object.entries(selected)
        .filter(([, enabled]) => enabled)
        .map(([name]) => name)
        .join(", ") || "none"
    }\n`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
