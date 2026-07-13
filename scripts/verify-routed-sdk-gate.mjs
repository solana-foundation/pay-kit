#!/usr/bin/env node

const REQUIRED = {
  typescript: ["core"],
  rust: ["core"],
  go: ["go", "go_consumer"],
  python: ["python"],
  ruby: ["ruby"],
  lua: ["lua"],
  php: ["php"],
  swift: ["swift"],
  kotlin: ["kotlin"],
  harness: ["core", "harness"],
};

export function verifyRoutedSdkGate(needs) {
  if (needs.classify?.result !== "success") {
    throw new Error(`classifier did not pass: ${needs.classify?.result ?? "missing"}`);
  }

  const outputs = needs.classify.outputs ?? {};
  for (const name of [...Object.keys(REQUIRED), "docs_only"]) {
    if (outputs[name] !== "true" && outputs[name] !== "false") {
      throw new Error(`classifier output ${name} is missing or invalid`);
    }
  }

  const selected = Object.keys(REQUIRED).filter((name) => outputs[name] === "true");
  const docsOnly = outputs.docs_only === "true";
  if (docsOnly === (selected.length > 0)) {
    throw new Error("classifier must select at least one workflow or explicitly declare docs_only=true");
  }

  for (const surface of selected) {
    for (const job of REQUIRED[surface]) {
      if (needs[job]?.result !== "success") {
        throw new Error(`${surface} selected ${job}, which finished ${needs[job]?.result ?? "missing"}`);
      }
    }
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const needs = JSON.parse(process.env.NEEDS ?? "null");
  verifyRoutedSdkGate(needs);
  console.log("all selected SDK workflows passed");
}
