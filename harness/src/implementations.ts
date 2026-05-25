export type ImplementationDefinition = {
  id: string;
  label: string;
  role: "client" | "server";
  command: string[];
  enabled: boolean;
};

function isEnabled(id: string, envName: string, defaultEnabled: boolean): boolean {
  const selected = process.env[envName];
  if (!selected || selected.trim() === "") {
    return defaultEnabled;
  }

  return selected
    .split(",")
    .map(value => value.trim())
    .filter(Boolean)
    .includes(id);
}

export const clientImplementations: ImplementationDefinition[] = [
  {
    id: "typescript",
    label: "TypeScript HTTP client",
    role: "client",
    command: [
      "pnpm",
      "exec",
      "node",
      "--import",
      "tsx",
      "src/fixtures/typescript/charge-client.ts",
    ],
    enabled: isEnabled("typescript", "MPP_INTEROP_CLIENTS", true),
  },
  {
    id: "rust",
    label: "Rust HTTP client",
    role: "client",
    command: [
      "cargo",
      "run",
      "--quiet",
      "--manifest-path",
      "../rust/Cargo.toml",
      "-p",
      "solana-mpp",
      "--bin",
      "interop_client",
    ],
    enabled: isEnabled("rust", "MPP_INTEROP_CLIENTS", true),
  },
  {
    id: "go",
    label: "Go HTTP client",
    role: "client",
    command: ["sh", "-c", "cd go-client && go run ."],
    enabled: isEnabled("go", "MPP_INTEROP_CLIENTS", false),
  },
  {
    id: "swift",
    label: "Swift HTTP client",
    role: "client",
    command: [
      "sh",
      "-c",
      "cd swift-client && swift run --quiet SwiftInteropClient",
    ],
    enabled: isEnabled("swift", "MPP_INTEROP_CLIENTS", false),
  },
  {
    id: "kotlin",
    label: "Kotlin HTTP client",
    role: "client",
    command: [
      "sh",
      "-c",
      "cd kotlin-client && gradle --quiet run --no-daemon",
    ],
    enabled: isEnabled("kotlin", "MPP_INTEROP_CLIENTS", true),
  },
];

export const serverImplementations: ImplementationDefinition[] = [
  {
    id: "typescript",
    label: "TypeScript HTTP server",
    role: "server",
    command: [
      "pnpm",
      "exec",
      "node",
      "--import",
      "tsx",
      "src/fixtures/typescript/charge-server.ts",
    ],
    enabled: isEnabled("typescript", "MPP_INTEROP_SERVERS", true),
  },
  {
    id: "rust",
    label: "Rust HTTP server",
    role: "server",
    command: [
      "cargo",
      "run",
      "--quiet",
      "--manifest-path",
      "../rust/Cargo.toml",
      "-p",
      "solana-mpp",
      "--bin",
      "interop_server",
    ],
    enabled: isEnabled("rust", "MPP_INTEROP_SERVERS", true),
  },
  {
    id: "php",
    label: "PHP HTTP server",
    role: "server",
    command: ["php", "php-server/server.php"],
    // Enabled by default so the charge-push scenario runs in the
    // canonical matrix. PHP runs against the scenarios whose
    // `serverIds` includes "php"; scenarios without an explicit
    // `serverIds` filter still iterate every enabled server, so this
    // also exposes PHP to charge-basic, charge-split-ata, etc.
    enabled: isEnabled("php", "MPP_INTEROP_SERVERS", true),
  },
  {
    id: "ruby",
    label: "Ruby HTTP server",
    role: "server",
    command: [
      "sh",
      "-c",
      "cd ../ruby && bundle exec ruby ../harness/ruby-server/server.rb",
    ],
    enabled: isEnabled("ruby", "MPP_INTEROP_SERVERS", false),
  },
  {
    id: "lua",
    label: "Lua HTTP server",
    role: "server",
    command: [
      "sh",
      "-c",
      "cd ../lua && eval \"$(luarocks --lua-version=5.1 --tree lua_modules path)\" && luajit ../harness/lua-server/server.lua",
    ],
    // Lua defaults off to match php/ruby: the harness requires a
    // luarocks-installed lua_modules tree under lua/ and a working
    // luajit, neither of which the default local interop run sets up.
    // CI and the focused matrix opt in via MPP_INTEROP_SERVERS=lua.
    // Codex PR #103 review (P2).
    enabled: isEnabled("lua", "MPP_INTEROP_SERVERS", false),
  },
  {
    id: "python",
    label: "Python HTTP server",
    role: "server",
    // Default OFF to match the other newly-landed adapters (PHP, Ruby, Go).
    // The default interop matrix should not require a Python toolchain on
    // every contributor's machine; opt-in via
    // ``MPP_INTEROP_SERVERS=python`` (or the dedicated focused-matrix CI
    // jobs in .github/workflows/python.yml).
    command: ["python3", "python-server/main.py"],
    enabled: isEnabled("python", "MPP_INTEROP_SERVERS", false),
  },
  {
    id: "go",
    label: "Go HTTP server",
    role: "server",
    command: ["sh", "-c", "cd go-server && go run ."],
    enabled: isEnabled("go", "MPP_INTEROP_SERVERS", true),
  },
];
