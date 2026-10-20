//! `pkc scaffold --lang <template> [--sdk <name>] [--dir <path>]`: a testee
//! skeleton speaking the ABI (one-shot and `--serve`), a runner manifest and
//! an expectations file that claims nothing, so the ABI is never
//! hand-rolled. Every op answers `unsupported-mode`; the SDK author replaces
//! one handler at a time and claims intents as they pass.

use std::path::{Path, PathBuf};

pub const TEMPLATES: [&str; 6] = ["python", "typescript", "go", "ruby", "php", "lua"];

struct Template {
    /// Testee path relative to the SDK directory.
    file: &'static str,
    command: &'static [&'static str],
    body: &'static str,
}

const PYTHON: &str = r#"#!/usr/bin/env python3
"""Conformance testee for the {{SDK}} SDK (scaffolded by `pkc scaffold`).

ABI (harness/README.md "Testee ABI"):
  one-shot: one v1 vector on stdin, one RunnerResult line on stdout;
  --serve:  newline JSON {id, op, input} -> {id, ok, result | error}.
Diagnostics go to stderr only. Replace `run_vector` one mode at a time and
claim the intent in harness/expectations/{{SDK}}.toml once it passes.
"""
import json
import sys

INTENTS: list[str] = []  # claimed intents, must equal capabilities.vector in the toml
HONOURS_CLOCK = False


def run_vector(vector: dict) -> dict:
    return {
        "id": vector.get("id", ""),
        "outcome": "unsupported-mode",
        "error": f"unsupported-mode: {vector.get('intent')} {vector.get('mode')} is not implemented yet",
    }


def serve() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            print(json.dumps({"id": None, "ok": False, "error": "bad-request", "detail": str(exc)}), flush=True)
            continue
        rid, op = request.get("id"), request.get("op")
        if op == "capabilities":
            result = {"abi": 2, "language": "{{SDK}}", "intents": INTENTS, "honoursClock": HONOURS_CLOCK}
        elif op in ("build", "verify", "canonical-bytes"):
            result = run_vector(request.get("input") or {})
        else:
            print(json.dumps({"id": rid, "ok": False, "error": "unknown-op", "detail": str(op)}), flush=True)
            continue
        print(json.dumps({"id": rid, "ok": True, "result": result}), flush=True)


def main() -> None:
    if "--serve" in sys.argv[1:]:
        serve()
        return
    vector = json.loads(sys.stdin.read())
    print(json.dumps(run_vector(vector)))


if __name__ == "__main__":
    main()
"#;

const TYPESCRIPT: &str = r#"// Conformance testee for the {{SDK}} SDK (scaffolded by `pkc scaffold`).
//
// ABI (harness/README.md "Testee ABI"): one-shot reads one v1 vector on
// stdin and writes one RunnerResult line; `--serve` speaks newline JSON
// {id, op, input} -> {id, ok, result | error}. Diagnostics go to stderr.
import { createInterface } from "node:readline";

const INTENTS = []; // must equal capabilities.vector in harness/expectations/{{SDK}}.toml
const HONOURS_CLOCK = false;

async function runVector(vector) {
  return {
    id: vector.id ?? "",
    outcome: "unsupported-mode",
    error: `unsupported-mode: ${vector.intent} ${vector.mode} is not implemented yet`,
  };
}

async function serve() {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    let request;
    try {
      request = JSON.parse(line);
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ id: null, ok: false, error: "bad-request", detail: String(error) })}\n`);
      continue;
    }
    const { id, op, input } = request;
    let result;
    if (op === "capabilities") {
      result = { abi: 2, language: "{{SDK}}", intents: INTENTS, honoursClock: HONOURS_CLOCK };
    } else if (op === "build" || op === "verify" || op === "canonical-bytes") {
      result = await runVector(input ?? {});
    } else {
      process.stdout.write(`${JSON.stringify({ id, ok: false, error: "unknown-op", detail: String(op) })}\n`);
      continue;
    }
    process.stdout.write(`${JSON.stringify({ id, ok: true, result })}\n`);
  }
}

if (process.argv.includes("--serve")) {
  await serve();
} else {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const vector = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  process.stdout.write(`${JSON.stringify(await runVector(vector))}\n`);
}
"#;

const GO: &str = r#"// Command conformance is the {{SDK}} SDK's conformance testee (scaffolded by
// `pkc scaffold`). One-shot: one v1 vector on stdin, one RunnerResult line on
// stdout. --serve: newline JSON {id, op, input} -> {id, ok, result | error}.
// Diagnostics go to stderr.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// intents must equal capabilities.vector in harness/expectations/{{SDK}}.toml.
var intents = []string{}

const honoursClock = false

type vector struct {
	ID     string          `json:"id"`
	Intent string          `json:"intent"`
	Mode   string          `json:"mode"`
	Input  json.RawMessage `json:"input"`
}

func runVector(v vector) map[string]any {
	return map[string]any{
		"id":      v.ID,
		"outcome": "unsupported-mode",
		"error":   fmt.Sprintf("unsupported-mode: %s %s is not implemented yet", v.Intent, v.Mode),
	}
}

func serve() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	out := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var request struct {
			ID    json.RawMessage `json:"id"`
			Op    string          `json:"op"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal([]byte(line), &request); err != nil {
			_ = out.Encode(map[string]any{"id": nil, "ok": false, "error": "bad-request", "detail": err.Error()})
			continue
		}
		switch request.Op {
		case "capabilities":
			_ = out.Encode(map[string]any{"id": request.ID, "ok": true, "result": map[string]any{
				"abi": 2, "language": "{{SDK}}", "intents": intents, "honoursClock": honoursClock,
			}})
		case "build", "verify", "canonical-bytes":
			var v vector
			if err := json.Unmarshal(request.Input, &v); err != nil {
				_ = out.Encode(map[string]any{"id": request.ID, "ok": false, "error": "bad-request", "detail": err.Error()})
				continue
			}
			_ = out.Encode(map[string]any{"id": request.ID, "ok": true, "result": runVector(v)})
		default:
			_ = out.Encode(map[string]any{"id": request.ID, "ok": false, "error": "unknown-op", "detail": request.Op})
		}
	}
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--serve" {
			serve()
			return
		}
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(runVector(v))
}
"#;

const RUBY: &str = r#"#!/usr/bin/env ruby
# frozen_string_literal: true

# Conformance testee for the {{SDK}} SDK (scaffolded by `pkc scaffold`).
# One-shot: one v1 vector on stdin, one RunnerResult line on stdout.
# --serve: newline JSON {id, op, input} -> {id, ok, result | error}.
# Diagnostics go to stderr.
require "json"

INTENTS = [].freeze # must equal capabilities.vector in harness/expectations/{{SDK}}.toml
HONOURS_CLOCK = false

def run_vector(vector)
  {
    "id" => vector["id"].to_s,
    "outcome" => "unsupported-mode",
    "error" => "unsupported-mode: #{vector["intent"]} #{vector["mode"]} is not implemented yet"
  }
end

def serve
  $stdout.sync = true
  $stdin.each_line do |line|
    next if line.strip.empty?

    begin
      request = JSON.parse(line)
    rescue JSON::ParserError => e
      puts JSON.generate("id" => nil, "ok" => false, "error" => "bad-request", "detail" => e.message)
      next
    end
    case request["op"]
    when "capabilities"
      result = {"abi" => 2, "language" => "{{SDK}}", "intents" => INTENTS, "honoursClock" => HONOURS_CLOCK}
    when "build", "verify", "canonical-bytes"
      result = run_vector(request["input"] || {})
    else
      puts JSON.generate("id" => request["id"], "ok" => false, "error" => "unknown-op", "detail" => request["op"].to_s)
      next
    end
    puts JSON.generate("id" => request["id"], "ok" => true, "result" => result)
  end
end

if ARGV.include?("--serve")
  serve
else
  puts JSON.generate(run_vector(JSON.parse($stdin.read)))
end
"#;

const PHP: &str = r#"<?php
// Conformance testee for the {{SDK}} SDK (scaffolded by `pkc scaffold`).
// One-shot: one v1 vector on stdin, one RunnerResult line on stdout.
// --serve: newline JSON {id, op, input} -> {id, ok, result | error}.
// Diagnostics go to stderr.

declare(strict_types=1);

const INTENTS = []; // must equal capabilities.vector in harness/expectations/{{SDK}}.toml
const HONOURS_CLOCK = false;

function run_vector(array $vector): array
{
    return [
        'id' => (string) ($vector['id'] ?? ''),
        'outcome' => 'unsupported-mode',
        'error' => sprintf('unsupported-mode: %s %s is not implemented yet', $vector['intent'] ?? '', $vector['mode'] ?? ''),
    ];
}

function emit(array $value): void
{
    fwrite(STDOUT, json_encode($value, JSON_UNESCAPED_SLASHES) . "\n");
    fflush(STDOUT);
}

if (in_array('--serve', $argv, true)) {
    while (($line = fgets(STDIN)) !== false) {
        if (trim($line) === '') {
            continue;
        }
        $request = json_decode($line, true);
        if (!is_array($request)) {
            emit(['id' => null, 'ok' => false, 'error' => 'bad-request', 'detail' => json_last_error_msg()]);
            continue;
        }
        $op = $request['op'] ?? '';
        if ($op === 'capabilities') {
            $result = ['abi' => 2, 'language' => '{{SDK}}', 'intents' => INTENTS, 'honoursClock' => HONOURS_CLOCK];
        } elseif (in_array($op, ['build', 'verify', 'canonical-bytes'], true)) {
            $result = run_vector($request['input'] ?? []);
        } else {
            emit(['id' => $request['id'] ?? null, 'ok' => false, 'error' => 'unknown-op', 'detail' => (string) $op]);
            continue;
        }
        emit(['id' => $request['id'] ?? null, 'ok' => true, 'result' => $result]);
    }
    exit(0);
}

emit(run_vector(json_decode((string) stream_get_contents(STDIN), true) ?? []));
"#;

const LUA: &str = r#"-- Conformance testee for the {{SDK}} SDK (scaffolded by `pkc scaffold`).
-- One-shot: one v1 vector on stdin, one RunnerResult line on stdout.
-- --serve: newline JSON {id, op, input} -> {id, ok, result | error}.
-- Diagnostics go to stderr. Needs lua-cjson.
local json = require('cjson')

-- must equal capabilities.vector in harness/expectations/{{SDK}}.toml
local INTENTS = setmetatable({}, json.array_mt)
local HONOURS_CLOCK = false

local function run_vector(vector)
  return {
    id = vector.id or '',
    outcome = 'unsupported-mode',
    error = 'unsupported-mode: ' .. tostring(vector.intent) .. ' ' .. tostring(vector.mode) .. ' is not implemented yet',
  }
end

local function emit(value)
  io.stdout:write(json.encode(value), '\n')
  io.stdout:flush()
end

local serve = false
for _, a in ipairs(arg or {}) do
  if a == '--serve' then serve = true end
end

if serve then
  for line in io.stdin:lines() do
    if line:match('%S') then
      local ok, request = pcall(json.decode, line)
      if not ok or type(request) ~= 'table' then
        emit({ id = json.null, ok = false, error = 'bad-request', detail = tostring(request) })
      elseif request.op == 'capabilities' then
        emit({ id = request.id, ok = true, result = { abi = 2, language = '{{SDK}}', intents = INTENTS, honoursClock = HONOURS_CLOCK } })
      elseif request.op == 'build' or request.op == 'verify' or request.op == 'canonical-bytes' then
        emit({ id = request.id, ok = true, result = run_vector(request.input or {}) })
      else
        emit({ id = request.id, ok = false, error = 'unknown-op', detail = tostring(request.op) })
      end
    end
  end
else
  emit(run_vector(json.decode(io.stdin:read('*a'))))
end
"#;

fn template(lang: &str) -> Option<Template> {
    Some(match lang {
        "python" => Template {
            file: "conformance_runner.py",
            command: &["python3", "conformance_runner.py"],
            body: PYTHON,
        },
        "typescript" => Template {
            file: "conformance-runner.mjs",
            command: &["node", "conformance-runner.mjs"],
            body: TYPESCRIPT,
        },
        "go" => Template {
            file: "cmd/conformance/main.go",
            command: &["go", "run", "./cmd/conformance"],
            body: GO,
        },
        "ruby" => Template {
            file: "exe/conformance",
            command: &["ruby", "exe/conformance"],
            body: RUBY,
        },
        "php" => Template {
            file: "conformance/runner.php",
            command: &["php", "conformance/runner.php"],
            body: PHP,
        },
        "lua" => Template {
            file: "cmd/conformance/main.lua",
            command: &["luajit", "cmd/conformance/main.lua"],
            body: LUA,
        },
        _ => return None,
    })
}

/// The files `scaffold` writes, relative to the repository root.
pub fn files(lang: &str, sdk: &str, dir: &str) -> Result<Vec<(PathBuf, String)>, String> {
    let t = template(lang).ok_or_else(|| {
        format!(
            "no scaffold template for {lang:?}; templates: {}",
            TEMPLATES.join(", ")
        )
    })?;
    let valid = !sdk.is_empty()
        && sdk
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return Err(format!("sdk name {sdk:?} must be [a-z0-9-]+"));
    }
    let command: Vec<String> = t.command.iter().map(|s| s.to_string()).collect();
    let mut serve = command.clone();
    serve.push("--serve".into());
    let manifest = serde_json::json!({
        "language": sdk,
        "command": command,
        "serve": serve,
        "cwd": dir,
    });
    let toml = format!(
        r#"language = "{sdk}"

# Scaffolded by `pkc scaffold --lang {lang}`. The testee claims nothing yet,
# so every vector is `unclaimed`. To start:
#
#   pkc run --sdk {sdk} --tier offline --discover   # every vector, nothing judged
#
# then implement one mode in {dir}/{file}, claim its intent below (and in the
# testee's INTENTS), and list what it cannot express under [[unsupported]]
# with a reason. `pkc next --sdk {sdk}` prints the next class to fix.
[capabilities]
vector = []
protocol = false
flow = false
"#,
        file = t.file
    );
    let just = format!(
        "# Add to the Justfile of {dir}:\nconformance:\n    cd {up}rust && cargo run -q -p paykit-conformance --bin pkc -- run --sdk {sdk} --tier offline\n",
        up = "../".repeat(dir.split('/').filter(|s| !s.is_empty()).count())
    );
    Ok(vec![
        (
            PathBuf::from(dir).join(t.file),
            t.body.replace("{{SDK}}", sdk),
        ),
        (
            PathBuf::from(format!("harness/runners/{sdk}.json")),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&manifest).unwrap_or_default()
            ),
        ),
        (
            PathBuf::from(format!("harness/expectations/{sdk}.toml")),
            toml,
        ),
        (PathBuf::from(dir).join("conformance.just"), just),
    ])
}

/// Write the scaffold under `root`, refusing to overwrite anything.
pub fn write(root: &Path, lang: &str, sdk: &str, dir: &str) -> Result<Vec<PathBuf>, String> {
    let files = files(lang, sdk, dir)?;
    for (path, _) in &files {
        if root.join(path).exists() {
            return Err(format!(
                "{} already exists; scaffold never overwrites (pick another --sdk / --dir)",
                path.display()
            ));
        }
    }
    let mut written = Vec::new();
    for (path, content) in files {
        let full = root.join(&path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&full, content).map_err(|e| format!("{}: {e}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::expectations::Expectations;
    use crate::run::judge::{judge_expect, Verdict};
    use crate::run::testee::{Abi, Manifest, Testee};
    use std::time::Duration;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pkc-scaffold-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn every_template_renders_a_valid_manifest_and_toml() {
        for lang in TEMPLATES {
            let files = files(lang, "newsdk", "newsdk").unwrap();
            let manifest: Manifest = serde_json::from_str(&files[1].1).unwrap();
            assert_eq!(manifest.serve.as_ref().unwrap().last().unwrap(), "--serve");
            let exp = Expectations::parse(&files[2].1, "newsdk.toml").unwrap();
            assert_eq!(exp.language, "newsdk");
            assert!(files[0].1.contains("honoursClock") || files[0].1.contains("HONOURS_CLOCK"));
        }
        assert!(files("cobol", "x", "x").is_err());
    }

    #[test]
    fn scaffold_never_overwrites() {
        let root = temp_root("overwrite");
        write(&root, "python", "newsdk", "newsdk").unwrap();
        assert!(write(&root, "python", "newsdk", "newsdk")
            .unwrap_err()
            .contains("already exists"));
    }

    // `pkc scaffold --lang python` output runs and reports every case as
    // unsupported, not as an error (PLAN phase 2b success criterion).
    #[test]
    fn the_python_scaffold_reports_every_vector_unsupported() {
        let root = temp_root("python");
        write(&root, "python", "newsdk", "newsdk").unwrap();
        let manifest = Manifest::load(&root.join("harness/runners/newsdk.json")).unwrap();
        let mut testee = Testee::new(
            &manifest,
            &root,
            Abi::Serve,
            None,
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .unwrap();
        let caps = testee.capabilities().unwrap().unwrap();
        assert_eq!(caps["intents"], serde_json::json!([]));
        let vectors =
            crate::run::vectors::load(&crate::repo_root().join("harness/vectors")).unwrap();
        for v in &vectors {
            let ex = testee.run(v.op(), &v.for_testee(None));
            let result = ex.result.unwrap_or_else(|e| panic!("{}: {e}", v.id));
            crate::run::result::validate(&result).unwrap();
            assert!(
                matches!(judge_expect(v, &result), Ok(Verdict::Unsupported(_))),
                "{}",
                v.id
            );
        }
    }
}
