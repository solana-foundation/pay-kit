import type { VectorMode } from "./conformance/schema";
import type { HarnessIntent } from "./contracts";

export const harnessCapabilityProtocols = [
  "charge",
  "x402-exact",
  "x402-upto",
  "session",
] as const satisfies readonly HarnessIntent[];

export type HarnessCapabilityProtocol =
  (typeof harnessCapabilityProtocols)[number];

export type HarnessCapabilityRole =
  | "client"
  | "server"
  | "verifier"
  | "settlement";

export type HarnessRoleCapability = {
  implementationIds?: readonly string[];
  runnerLanguages?: readonly string[];
  vectorModes?: readonly VectorMode[];
  requiredByDefault?: boolean;
};

export type HarnessCapability = {
  language: string;
  protocol: HarnessCapabilityProtocol;
  roles: Partial<Record<HarnessCapabilityRole, HarnessRoleCapability>>;
  notes?: string;
};

const chargeVerifierModes = ["verify-transaction"] as const;
const x402EnvelopeVerifierModes = ["verify-transaction"] as const;
const x402ExactVerifierModes = [
  "verify-transaction",
  "verify-x402-transaction",
] as const;
const sessionVerifierModes = ["canonical-bytes"] as const;

export const harnessCapabilityRegistry: readonly HarnessCapability[] = [
  {
    language: "typescript",
    protocol: "charge",
    roles: {
      client: {
        implementationIds: ["typescript"],
        requiredByDefault: true,
      },
      server: {
        implementationIds: ["typescript"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["typescript"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["typescript"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "rust",
    protocol: "charge",
    roles: {
      client: {
        implementationIds: ["rust"],
        requiredByDefault: true,
      },
      server: {
        implementationIds: ["rust"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["rust"],
        requiredByDefault: true,
      },
    },
  },
  {
    language: "go",
    protocol: "charge",
    roles: {
      client: {
        implementationIds: ["go"],
        requiredByDefault: true,
      },
      server: {
        implementationIds: ["go"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["go"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["go"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "swift",
    protocol: "charge",
    roles: {
      client: {
        implementationIds: ["swift"],
        requiredByDefault: true,
      },
    },
    notes: "Client-only process adapter; verify-transaction vectors are unsupported.",
  },
  {
    language: "kotlin",
    protocol: "charge",
    roles: {
      client: {
        implementationIds: ["kotlin"],
        requiredByDefault: true,
      },
    },
    notes: "Client-only process adapter; no charge conformance runner is registered.",
  },
  {
    language: "php",
    protocol: "charge",
    roles: {
      server: {
        implementationIds: ["php"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["php"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["php"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "ruby",
    protocol: "charge",
    roles: {
      server: {
        implementationIds: ["ruby"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["ruby"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["ruby"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "lua",
    protocol: "charge",
    roles: {
      server: {
        implementationIds: ["lua"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["lua"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["lua"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "python",
    protocol: "charge",
    roles: {
      server: {
        implementationIds: ["python"],
        requiredByDefault: true,
      },
      settlement: {
        implementationIds: ["python"],
        requiredByDefault: true,
      },
      verifier: {
        runnerLanguages: ["python"],
        vectorModes: chargeVerifierModes,
      },
    },
  },
  {
    language: "typescript",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["ts-x402"] },
      server: { implementationIds: ["ts-x402"] },
      settlement: { implementationIds: ["ts-x402"] },
      verifier: {
        runnerLanguages: ["typescript"],
        vectorModes: x402ExactVerifierModes,
      },
    },
    notes: "The process adapters are the TypeScript reference fixtures; cross-language settlement remains intentionally limited.",
  },
  {
    language: "rust",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["rust-x402"] },
      server: { implementationIds: ["rust-x402"] },
      settlement: { implementationIds: ["rust-x402"] },
    },
  },
  {
    language: "go",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["go-x402"] },
      server: { implementationIds: ["go"] },
      settlement: { implementationIds: ["go"] },
      verifier: {
        runnerLanguages: ["go"],
        vectorModes: x402EnvelopeVerifierModes,
      },
    },
  },
  {
    language: "python",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["python-x402"] },
      server: { implementationIds: ["python"] },
      settlement: { implementationIds: ["python"] },
      verifier: {
        runnerLanguages: ["python"],
        vectorModes: x402EnvelopeVerifierModes,
      },
    },
  },
  {
    language: "swift",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["swift-x402"] },
    },
    notes: "Client-only x402 exact process adapter.",
  },
  {
    language: "kotlin",
    protocol: "x402-exact",
    roles: {
      client: { implementationIds: ["kotlin-x402"] },
    },
    notes: "Client-only x402 exact process adapter.",
  },
  {
    language: "php",
    protocol: "x402-exact",
    roles: {
      server: { implementationIds: ["php"] },
      settlement: { implementationIds: ["php"] },
      verifier: {
        runnerLanguages: ["php"],
        vectorModes: x402EnvelopeVerifierModes,
      },
    },
  },
  {
    language: "ruby",
    protocol: "x402-exact",
    roles: {
      server: { implementationIds: ["ruby", "ruby-x402-server"] },
      settlement: { implementationIds: ["ruby", "ruby-x402-server"] },
      verifier: {
        runnerLanguages: ["ruby"],
        vectorModes: x402EnvelopeVerifierModes,
      },
    },
  },
  {
    language: "lua",
    protocol: "x402-exact",
    roles: {
      server: { implementationIds: ["lua"] },
      settlement: { implementationIds: ["lua"] },
      verifier: {
        runnerLanguages: ["lua"],
        vectorModes: x402EnvelopeVerifierModes,
      },
    },
  },
  {
    language: "rust",
    protocol: "x402-upto",
    roles: {
      client: { implementationIds: ["rust-x402-upto"] },
      server: { implementationIds: ["rust-x402-upto"] },
      settlement: { implementationIds: ["rust-x402-upto"] },
    },
  },
  {
    language: "go",
    protocol: "x402-upto",
    roles: {
      client: { implementationIds: ["go-x402-upto"] },
      server: { implementationIds: ["go-x402-upto"] },
      settlement: { implementationIds: ["go-x402-upto"] },
    },
  },
  {
    language: "python",
    protocol: "x402-upto",
    roles: {
      client: { implementationIds: ["python-x402-upto"] },
      server: { implementationIds: ["python-x402-upto"] },
      settlement: { implementationIds: ["python-x402-upto"] },
    },
  },
  {
    language: "python",
    protocol: "session",
    roles: {
      client: { implementationIds: ["python-session"] },
      server: { implementationIds: ["python"] },
      verifier: {
        runnerLanguages: ["python"],
        vectorModes: sessionVerifierModes,
      },
    },
    notes: "Live session scenario is intentionally limited to Python client and server.",
  },
  {
    language: "go",
    protocol: "session",
    roles: {
      verifier: {
        runnerLanguages: ["go"],
        vectorModes: sessionVerifierModes,
      },
    },
  },
  {
    language: "swift",
    protocol: "session",
    roles: {
      verifier: {
        runnerLanguages: ["swift"],
        vectorModes: sessionVerifierModes,
      },
    },
  },
  {
    language: "kotlin",
    protocol: "session",
    roles: {
      verifier: {
        runnerLanguages: ["kotlin"],
        vectorModes: sessionVerifierModes,
      },
    },
  },
];

export function protocolsForImplementation(implementation: {
  intents?: readonly string[];
}): HarnessCapabilityProtocol[] {
  const rawProtocols = implementation.intents ?? ["charge"];
  return rawProtocols.map((protocol) => {
    if (isHarnessCapabilityProtocol(protocol)) {
      return protocol;
    }
    throw new Error(`Unsupported harness capability protocol: ${protocol}`);
  });
}

export function isHarnessCapabilityProtocol(
  value: string,
): value is HarnessCapabilityProtocol {
  return harnessCapabilityProtocols.includes(
    value as HarnessCapabilityProtocol,
  );
}

export function capabilitiesForRole(
  role: HarnessCapabilityRole,
): HarnessCapability[] {
  return harnessCapabilityRegistry.filter(
    (capability) => capability.roles[role],
  );
}

export function verifierLanguagesForProtocol(
  protocol: HarnessCapabilityProtocol,
  mode?: VectorMode,
): string[] {
  const languages = new Set<string>();
  for (const capability of harnessCapabilityRegistry) {
    const verifier = capability.roles.verifier;
    if (!verifier || capability.protocol !== protocol) continue;
    if (mode && !verifier.vectorModes?.includes(mode)) continue;
    for (const language of verifier.runnerLanguages ?? []) {
      languages.add(language);
    }
  }
  return [...languages].sort();
}
