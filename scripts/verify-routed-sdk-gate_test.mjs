#!/usr/bin/env node
import assert from "node:assert/strict";
import { verifyRoutedSdkGate } from "./verify-routed-sdk-gate.mjs";

const surfaces = ["typescript", "rust", "go", "python", "ruby", "lua", "php", "swift", "kotlin", "harness"];

function needs(outputs, results = {}) {
  return {
    classify: { outputs, result: "success" },
    core: { result: "skipped" },
    go: { result: "skipped" },
    go_consumer: { result: "skipped" },
    python: { result: "skipped" },
    ruby: { result: "skipped" },
    lua: { result: "skipped" },
    php: { result: "skipped" },
    swift: { result: "skipped" },
    kotlin: { result: "skipped" },
    harness: { result: "skipped" },
    ...Object.fromEntries(Object.entries(results).map(([name, result]) => [name, { result }])),
  };
}

const none = Object.fromEntries(surfaces.map((name) => [name, "false"]));
assert.doesNotThrow(() => verifyRoutedSdkGate(needs({ ...none, docs_only: "true" })));
assert.doesNotThrow(() =>
  verifyRoutedSdkGate(needs({ ...none, docs_only: "false", python: "true" }, { python: "success" })),
);
assert.throws(() => verifyRoutedSdkGate(needs({})), /missing or invalid/);
assert.throws(() => verifyRoutedSdkGate(needs({ ...none, docs_only: "false" })), /select at least one/);
assert.throws(
  () => verifyRoutedSdkGate(needs({ ...none, docs_only: "true", python: "true" }, { python: "success" })),
  /select at least one/,
);
assert.throws(
  () => verifyRoutedSdkGate(needs({ ...none, docs_only: "false", go: "true" }, { go: "success" })),
  /go_consumer.*skipped/,
);

console.log("verify-routed-sdk-gate_test: PASS");
