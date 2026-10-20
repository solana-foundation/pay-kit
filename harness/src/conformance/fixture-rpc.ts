// Deterministic Solana JSON-RPC server for offline conformance vectors.
//
// The driver starts one per vector from `input.rpcFixtures` and passes its
// URL to the runner as `input.rpcUrl`. Runners hand that URL to their SDK
// unchanged, so SDK code paths that read the chain (mint owner and decimals
// lookups, blockhash fetches) run for real instead of being replaced by
// defaults in runner code. A method the fixture does not serve returns a
// JSON-RPC error naming the method, so a builder that unexpectedly reaches
// for the network fails loudly. Every call is recorded for diagnostics.

import { createServer, type IncomingMessage, type Server } from "node:http";
import { getBase58Decoder } from "@solana/kit";

export const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

export type FixtureMint = {
  // Owning program. Normally a token program; anything else lets a vector
  // pin the "unexpected owner" rejection.
  owner: string;
  decimals: number;
};

export type RpcFixtures = {
  recentBlockhash?: string;
  lastValidBlockHeight?: number;
  slot?: number;
  // mint address -> account. A mint absent here does not exist.
  mints?: Record<string, FixtureMint>;
};

export type FixtureRpc = {
  url: string;
  calls: string[];
  close: () => Promise<void>;
};

const DEFAULT_BLOCKHASH = "11111111111111111111111111111111";
const MINT_SIZE = 82;

// SPL Token mint layout: COption<Pubkey> mint_authority (36), u64 supply,
// u8 decimals @44, bool is_initialized @45, COption<Pubkey> freeze (36).
function mintAccountData(decimals: number): Buffer {
  const data = Buffer.alloc(MINT_SIZE);
  data[44] = decimals;
  data[45] = 1;
  return data;
}

function rentExempt(size: number): number {
  // lamports_per_byte_year (3480) * exemption threshold (2 years) over
  // the 128-byte account storage overhead plus data.
  return (128 + size) * 3480 * 2;
}

function accountValue(fixtures: RpcFixtures, address: string, encoding: string | undefined) {
  const mint = fixtures.mints?.[address];
  if (!mint) return null;
  const common = {
    executable: false,
    lamports: rentExempt(MINT_SIZE),
    owner: mint.owner,
    rentEpoch: 0,
    space: MINT_SIZE,
  };
  if (encoding === "jsonParsed" && (mint.owner === TOKEN_PROGRAM || mint.owner === TOKEN_2022_PROGRAM)) {
    return {
      ...common,
      data: {
        program: mint.owner === TOKEN_PROGRAM ? "spl-token" : "spl-token-2022",
        parsed: {
          type: "mint",
          info: {
            decimals: mint.decimals,
            freezeAuthority: null,
            isInitialized: true,
            mintAuthority: null,
            supply: "0",
          },
        },
        space: MINT_SIZE,
      },
    };
  }
  const data = mintAccountData(mint.decimals);
  if (encoding === "base58") {
    return { ...common, data: [getBase58Decoder().decode(data), "base58"] };
  }
  return { ...common, data: [data.toString("base64"), "base64"] };
}

type Request = { jsonrpc?: string; id?: unknown; method?: string; params?: unknown[] };

function handle(fixtures: RpcFixtures, req: Request, calls: string[]): unknown {
  const method = String(req.method ?? "");
  calls.push(method);
  const slot = fixtures.slot ?? 100;
  const context = { context: { apiVersion: "2.0.0", slot } };
  const params = Array.isArray(req.params) ? req.params : [];
  const options = (params.find((p) => typeof p === "object" && p !== null && !Array.isArray(p)) ?? {}) as {
    encoding?: string;
  };
  const ok = (result: unknown) => ({ jsonrpc: "2.0", id: req.id ?? null, result });
  switch (method) {
    case "getLatestBlockhash":
      return ok({
        ...context,
        value: {
          blockhash: fixtures.recentBlockhash ?? DEFAULT_BLOCKHASH,
          lastValidBlockHeight: fixtures.lastValidBlockHeight ?? 1_000,
        },
      });
    case "getAccountInfo":
      return ok({ ...context, value: accountValue(fixtures, String(params[0]), options.encoding) });
    case "getMultipleAccounts":
      return ok({
        ...context,
        value: (Array.isArray(params[0]) ? params[0] : []).map((a) =>
          accountValue(fixtures, String(a), options.encoding),
        ),
      });
    case "getMinimumBalanceForRentExemption":
      return ok(rentExempt(Number(params[0] ?? 0)));
    case "getSlot":
      return ok(slot);
    case "getHealth":
      return ok("ok");
    default:
      return {
        jsonrpc: "2.0",
        id: req.id ?? null,
        error: { code: -32601, message: `method ${method} is not served by the conformance fixture RPC` },
      };
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export async function startFixtureRpc(fixtures: RpcFixtures = {}): Promise<FixtureRpc> {
  const calls: string[] = [];
  const server: Server = createServer(async (req, res) => {
    let payload: unknown;
    try {
      const body = JSON.parse(await readBody(req)) as Request | Request[];
      payload = Array.isArray(body) ? body.map((r) => handle(fixtures, r, calls)) : handle(fixtures, body, calls);
    } catch (error) {
      payload = { jsonrpc: "2.0", id: null, error: { code: -32700, message: `parse error: ${String(error)}` } };
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(payload));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture RPC did not bind");
  return {
    url: `http://127.0.0.1:${address.port}`,
    calls,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
