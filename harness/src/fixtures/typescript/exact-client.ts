// ts-x402 client adapter: @solana/pay-kit's `createPayKitClient`.
//
// Env in (X402_HARNESS_*, same as the Rust adapter), JSON out: prints one
// `result` line. The pay-kit client does the whole x402 flow itself: it
// reads the 402, builds and signs the exact transfer against
// X402_HARNESS_RPC_URL and retries with PAYMENT-SIGNATURE.
//
// The client talks to the server through a loopback proxy so the adapter can
// report the payment header it sent (`payment-signature-sent`) and, for the
// scenarios that need it, steer one leg of the flow:
//   - cross-route replay (MPP_HARNESS_REPLAY_SOURCE_PATH): the unpaid probe
//     goes to the cheaper source route, the paid retry to the target route;
//   - cross-server resubmit (MPP_HARNESS_RESUBMIT_URL): after paying the
//     target, the captured header is re-sent unchanged to the second server.

import http from "node:http";
import type { AddressInfo } from "node:net";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import {
  AssetPermission,
  ClientPermissions,
  createPayKitClient,
  type SolanaNetwork,
} from "@solana/pay-kit/client";
import { PAYMENT_SIGNATURE_HEADER, readX402ClientEnvironment } from "./exact-shared";

const HOP_BY_HOP = new Set(["connection", "content-length", "host", "keep-alive", "transfer-encoding"]);

type Proxy = { url: string; sentHeader: () => string | undefined; close: () => void };

// Forward every request to `upstreamFor(paid)` and remember the payment
// header the client attached.
async function startProxy(upstreamFor: (paid: boolean) => string): Promise<Proxy> {
  let sent: string | undefined;
  const server = http.createServer((req, res) => {
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === undefined || HOP_BY_HOP.has(name)) continue;
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
    const paid = headers.get(PAYMENT_SIGNATURE_HEADER) ?? headers.get("x-payment");
    if (paid) sent = paid;
    fetch(upstreamFor(paid !== null), { headers, method: req.method ?? "GET" })
      .then(async (upstream) => {
        const out: Record<string, string> = {};
        upstream.headers.forEach((value, name) => {
          if (!HOP_BY_HOP.has(name) && name !== "content-encoding") out[name] = value;
        });
        const body = Buffer.from(await upstream.arrayBuffer());
        res.writeHead(upstream.status, out);
        res.end(body);
      })
      .catch((error: unknown) => {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
      });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { close: () => server.close(), sentHeader: () => sent, url: `http://127.0.0.1:${port}/` };
}

async function readBody(response: Response): Promise<unknown> {
  const raw = await response.text();
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function emit(result: Record<string, unknown>): void {
  console.log(JSON.stringify({ type: "result", implementation: "typescript", role: "client", ...result }));
}

async function main(): Promise<void> {
  const env = readX402ClientEnvironment();
  const signer = await createKeyPairSignerFromBytes(env.clientSecretKey);
  const network = env.network === "mainnet-beta" ? "mainnet" : (env.network as SolanaNetwork);
  // The policy a pay-kit integrator would set: this network, this asset.
  const permissions = ClientPermissions.builder()
    .onlyNetwork(network)
    .allowAsset(AssetPermission.allow(network, env.mint))
    .build();
  const client = await createPayKitClient({
    accept: ["x402"],
    network,
    permissions,
    rpcUrl: env.rpcUrl,
    signer,
  });

  const source = env.replaySource ? new URL(env.replaySource.resourcePath, env.targetUrl).toString() : undefined;
  const proxy = await startProxy((paid) => (!paid && source ? source : env.targetUrl));
  try {
    const response = await client.fetch(proxy.url);
    const sent = proxy.sentHeader();
    const headers = Object.fromEntries(response.headers.entries());
    if (sent) headers[`${PAYMENT_SIGNATURE_HEADER}-sent`] = sent;
    const body = await readBody(response);

    if (!env.resubmitUrl) {
      emit({
        ok: response.ok,
        status: response.status,
        responseHeaders: headers,
        responseBody: body,
        settlement: response.headers.get(env.settlementHeader),
      });
      return;
    }

    if (!sent) throw new Error("client did not pay the first server, nothing to resubmit");
    const second = await fetch(env.resubmitUrl, { headers: { [PAYMENT_SIGNATURE_HEADER]: sent } });
    emit({
      ok: second.ok,
      status: second.status,
      responseHeaders: Object.fromEntries(second.headers.entries()),
      responseBody: await readBody(second),
      settlement: second.headers.get(env.settlementHeader),
      firstStatus: response.status,
      firstBody: body,
    });
  } finally {
    proxy.close();
  }
}

main().catch((error: unknown) => {
  emit({
    ok: false,
    status: 0,
    responseHeaders: {},
    responseBody: null,
    settlement: null,
    error: error instanceof Error ? error.message : String(error),
  });
});
