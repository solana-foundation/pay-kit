export type ImplementationDefinition = {
  id: string;
  label: string;
  role: "client" | "server";
  command: string[];
  enabled: boolean;
  // Optional. When set, this adapter only participates in scenarios whose
  // `intent` is in this list. Defaults to "charge" only for back-compat
  // with the existing MPP charge matrix.
  intents?: string[];
  // The value the adapter is REQUIRED to emit in the `implementation`
  // field of its ready/result JSON. The harness asserts this on every
  // adapter message and fails loudly on mismatch, so an adapter that is
  // accidentally wired to a different language's binary (e.g. an x402
  // adapter that reuses the wrong charge client) cannot green-skip.
  //
  // Several adapter ids carry a protocol suffix (`ts-x402`, `go-x402`,
  // `ruby-x402-server`) while the underlying fixture reports the bare
  // language (`typescript`, `go`, `ruby`). `reportsAs` records the
  // language id the fixture actually prints; when omitted it defaults to
  // the adapter `id`.
  reportsAs?: string;
};

// The `implementation` id an adapter is expected to emit. Defaults to the
// adapter id; adapters whose fixture reports the bare language override via
// `reportsAs`.
export function expectedReportedImplementation(
  implementation: ImplementationDefinition,
): string {
  return implementation.reportsAs ?? implementation.id;
}

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
    // Pre-warmed by `gradle installDist` in `.github/workflows/kotlin.yml`
    // (the `interop-kotlin` job) so the script lands at this path. Local
    // runs can prime it with `(cd harness/kotlin-client && gradle installDist)`.
    command: [
      "sh",
      "-c",
      "kotlin-client/build/install/mpp-kotlin-interop-client/bin/mpp-kotlin-interop-client",
    ],
    // Defaults off to match swift/php/ruby/go: opt-in via
    // `MPP_INTEROP_CLIENTS=kotlin` (the interop-kotlin CI job sets this).
    enabled: isEnabled("kotlin", "MPP_INTEROP_CLIENTS", false),
  },
  {
    id: "ts-x402",
    label: "TypeScript x402 exact client",
    role: "client",
    command: [
      "pnpm",
      "exec",
      "node",
      "--import",
      "tsx",
      "src/fixtures/typescript/exact-client.ts",
    ],
    enabled: isEnabled("ts-x402", "X402_INTEROP_CLIENTS", true),
    intents: ["x402-exact"],
    reportsAs: "typescript",
  },
  {
    id: "rust-x402",
    label: "Rust x402 exact client",
    role: "client",
    command: [
      "cargo",
      "run",
      "--quiet",
      "--manifest-path",
      "../rust/Cargo.toml",
      "-p",
      "solana-x402",
      "--bin",
      "interop_client",
    ],
    enabled: isEnabled("rust-x402", "X402_INTEROP_CLIENTS", true),
    intents: ["x402-exact"],
    reportsAs: "rust",
  },
  {
    id: "go-x402",
    label: "Go x402 exact client",
    role: "client",
    command: ["sh", "-c", "cd go-client && go run ."],
    enabled: isEnabled("go-x402", "X402_INTEROP_CLIENTS", false),
    intents: ["x402-exact"],
    reportsAs: "go",
  },
  {
    id: "python-x402",
    label: "Python pay_kit x402 exact client",
    role: "client",
    // Drives the pay_kit x402 exact client (parse challenge -> build a signed
    // v0 VersionedTransaction -> PAYMENT-SIGNATURE -> retry). Inserts python/src
    // on sys.path like harness/python-server/server.py. Default OFF to match the
    // go/swift/kotlin/ruby adapters: the default matrix should not require a
    // Python toolchain on every contributor's machine. Opt in via
    // `X402_INTEROP_CLIENTS=python-x402` (the focused python-x402 CI job sets
    // this). Carries a real signed Solana transaction, so it settles end-to-end
    // against the rust/ts/python x402 servers (see test/x402-exact.e2e.test.ts).
    command: ["python3", "python-x402-client/main.py"],
    enabled: isEnabled("python-x402", "X402_INTEROP_CLIENTS", false),
    intents: ["x402-exact"],
    reportsAs: "python",
  },
  {
    id: "swift-x402",
    label: "Swift x402 exact client",
    role: "client",
    command: [
      "sh",
      "-c",
      "cd swift-x402-client && swift run --quiet SwiftX402Client",
    ],
    enabled: isEnabled("swift-x402", "X402_INTEROP_CLIENTS", false),
    intents: ["x402-exact"],
  },
  {
    id: "kotlin-x402",
    label: "Kotlin x402 exact client",
    role: "client",
    // Pre-warmed by `gradle installDist` in `.github/workflows/kotlin.yml`
    // (the `interop-kotlin-x402` job) so the script lands at this path. Local
    // runs can prime it with `(cd harness/kotlin-x402-client && gradle installDist)`.
    command: [
      "sh",
      "-c",
      "kotlin-x402-client/build/install/mpp-kotlin-x402-interop-client/bin/mpp-kotlin-x402-interop-client",
    ],
    // Defaults off to match swift/go/etc: opt-in via `X402_INTEROP_CLIENTS=kotlin-x402`.
    enabled: isEnabled("kotlin-x402", "X402_INTEROP_CLIENTS", false),
    intents: ["x402-exact"],
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
    label: "PHP PayKit server (dual protocol)",
    role: "server",
    // One adapter binary, two settle paths. The dual-protocol PHP
    // server (harness/php-server/server.php) reads either
    // X402_INTEROP_* or MPP_INTEROP_* (or PAY_KIT_INTEROP_PROTOCOL
    // for the matrix's both-namespaces shape) and routes through
    // the umbrella's X402 adapter (x402) or the lower-level
    // SolanaChargeHandler (mpp). Mirrors the Lua + Ruby
    // pay-kit-server pattern.
    command: ["php", "php-server/server.php"],
    enabled: isEnabled("php", "MPP_INTEROP_SERVERS", true),
    intents: ["charge", "x402-exact"],
  },
  {
    id: "ruby",
    label: "Ruby PayKit server (dual protocol)",
    role: "server",
    // One adapter binary, two settle paths. The harness orchestrator
    // sets either `X402_INTEROP_*` (x402-exact intent) or `MPP_INTEROP_*`
    // (charge intent); the adapter detects which one is active (via
    // PAY_KIT_INTEROP_PROTOCOL hint or namespace probe) and routes
    // through PayKit::Rack::Dispatcher (x402) or Mpp::Server::Charge
    // directly (mpp).
    command: [
      "sh",
      "-c",
      "cd ../ruby && bundle exec ruby ../harness/ruby-server/server.rb",
    ],
    enabled: isEnabled("ruby", "MPP_INTEROP_SERVERS", false),
    intents: ["charge", "x402-exact"],
  },
  {
    id: "lua",
    label: "Lua PayKit server (dual protocol)",
    role: "server",
    // One adapter binary, two settle paths. The dual-protocol Lua
    // server (lua/harness/lua-server/server.lua) reads either
    // X402_INTEROP_* or MPP_INTEROP_* (or PAY_KIT_INTEROP_PROTOCOL
    // for the matrix's both-namespaces shape) and routes through
    // resty.pay_kit. Mirrors the Ruby pay-kit-server pattern.
    command: [
      "sh",
      "-c",
      "cd ../lua && eval \"$(luarocks --lua-version=5.1 --tree lua_modules path)\" && luajit ../harness/lua-server/server.lua",
    ],
    enabled: isEnabled("lua", "MPP_INTEROP_SERVERS", false),
    intents: ["charge", "x402-exact"],
  },
  {
    id: "python",
    label: "Python pay_kit server (dual protocol)",
    role: "server",
    // One adapter binary, two settle paths. The dual-protocol Python
    // pay_kit server (harness/python-server/server.py) reads either
    // X402_INTEROP_* or MPP_INTEROP_* (or PAY_KIT_INTEROP_PROTOCOL for the
    // matrix's both-namespaces shape) and routes x402 through the umbrella's
    // X402Adapter and MPP charge through the lower-level
    // pay_kit.protocols.mpp handler (the umbrella's ticker-based currency
    // model fits x402's resolved-mint asset, but the pubkey-mode MPP charge
    // matrix needs the literal mint as currency). Same split as the PHP
    // adapter. Default OFF to match the other newly-landed adapters (PHP,
    // Ruby): the default interop matrix should not require a Python toolchain
    // on every contributor's machine; opt in via
    // ``MPP_INTEROP_SERVERS=python`` (charge) /
    // ``MPP_INTEROP_SERVERS=python X402_INTEROP_CLIENTS=rust-x402`` with
    // ``MPP_INTEROP_INTENTS=x402-exact`` (x402-exact), or the dedicated
    // focused-matrix CI jobs in .github/workflows/python.yml.
    command: ["python3", "python-server/server.py"],
    enabled: isEnabled("python", "MPP_INTEROP_SERVERS", false),
    intents: ["charge", "x402-exact"],
  },
  {
    id: "go",
    label: "Go PayKit umbrella server (dual protocol)",
    role: "server",
    command: ["sh", "-c", "cd go-server && ./paykit-server"],
    enabled: isEnabled("go", "MPP_INTEROP_SERVERS", true),
    intents: ["charge", "x402-exact"],
    // The Go umbrella server fixture reports the bare language tag
    // `go-paykit`, not the adapter id `go`.
    reportsAs: "go-paykit",
  },
  {
    id: "ts-x402",
    label: "TypeScript x402 exact server",
    role: "server",
    command: [
      "pnpm",
      "exec",
      "node",
      "--import",
      "tsx",
      "src/fixtures/typescript/exact-server.ts",
    ],
    enabled: isEnabled("ts-x402", "X402_INTEROP_SERVERS", true),
    intents: ["x402-exact"],
    reportsAs: "typescript",
  },
  {
    id: "rust-x402",
    label: "Rust x402 exact server",
    role: "server",
    command: [
      "cargo",
      "run",
      "--quiet",
      "--manifest-path",
      "../rust/Cargo.toml",
      "-p",
      "solana-x402",
      "--bin",
      "interop_server",
    ],
    enabled: isEnabled("rust-x402", "X402_INTEROP_SERVERS", true),
    intents: ["x402-exact"],
    reportsAs: "rust",
  },
  {
    id: "ruby-x402-server",
    label: "Ruby x402 exact server",
    role: "server",
    command: [
      "sh",
      "-c",
      "cd ../ruby && bundle exec ruby ../harness/ruby-x402-server/server.rb",
    ],
    enabled: isEnabled("ruby-x402-server", "X402_INTEROP_SERVERS", false),
    intents: ["x402-exact"],
    reportsAs: "ruby",
  },
];
