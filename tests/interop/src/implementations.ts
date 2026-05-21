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
      "../../rust/Cargo.toml",
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
      "../../rust/Cargo.toml",
      "--bin",
      "interop_server",
    ],
    enabled: isEnabled("rust", "MPP_INTEROP_SERVERS", true),
  },
  {
    id: "php",
    label: "PHP HTTP server",
    role: "server",
    command: [
      "pnpm",
      "exec",
      "node",
      "--import",
      "tsx",
      "src/fixtures/php/charge-server.ts",
    ],
    enabled: isEnabled("php", "MPP_INTEROP_SERVERS", false),
  },
];
