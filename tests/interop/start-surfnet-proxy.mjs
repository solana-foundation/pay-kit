import http from "node:http";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { Surfnet } from "surfpool-sdk";

const rpcPort = Number(process.env.SURFPOOL_PROXY_RPC_PORT ?? 8899);
const wsPort = Number(process.env.SURFPOOL_PROXY_WS_PORT ?? 8900);
const faultControlPort = Number(
  process.env.SURFPOOL_PROXY_FAULT_PORT ?? 8898,
);
const surfnet = Surfnet.start();
const rpcTarget = new URL(surfnet.rpcUrl);
const wsTarget = new URL(surfnet.wsUrl);

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MINT_ACCOUNT_SIZE = 82;
const STABLECOIN_MINTS = [
  {
    mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
    tokenProgram: TOKEN_2022_PROGRAM,
  },
];

function createSplMintAccountData(decimals) {
  const data = new Uint8Array(MINT_ACCOUNT_SIZE);
  const view = new DataView(data.buffer);
  view.setBigUint64(36, 0n, true);
  data[44] = decimals;
  data[45] = 1;
  return data;
}

for (const { mint, tokenProgram } of STABLECOIN_MINTS) {
  surfnet.setAccount(
    mint,
    1_461_600,
    createSplMintAccountData(6),
    tokenProgram,
  );
}

// Fault-injection state. Each rule entry: { method, returnNull, count }.
// `count` decrements on each match; the rule is removed when count reaches
// zero. Cleared by a POST to /reset on the fault control endpoint between
// tests so state never leaks across scenarios.
//
// Audit v2 L8 / G09. Used by the charge-confirmation-timeout interop
// scenario to prove the L8 broadcast-then-consume-then-await ordering:
// the SDK must reserve the signature in the replay store BEFORE the
// confirmation poll, so when this proxy stalls getSignatureStatuses
// (returning null until timeout), a retry of the same credential is
// rejected as signature_consumed instead of double-broadcasting.
const faultRules = [];

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const body = Buffer.concat(chunks).toString("utf8");
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function findRule(method) {
  for (let i = 0; i < faultRules.length; i += 1) {
    if (faultRules[i].method === method) {
      const rule = faultRules[i];
      rule.count -= 1;
      if (rule.count <= 0) {
        faultRules.splice(i, 1);
      }
      return rule;
    }
  }
  return null;
}

async function forwardRpc(req, res) {
  let raw;
  try {
    raw = await readJson(req);
  } catch (e) {
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `bad rpc body: ${e.message}` }));
    return;
  }

  // Apply fault rules per request. For a batch we apply per item.
  const apply = (item) => {
    if (!item || typeof item !== "object" || typeof item.method !== "string") {
      return null;
    }
    const rule = findRule(item.method);
    if (!rule) {
      return null;
    }
    if (rule.returnNull) {
      return {
        jsonrpc: "2.0",
        id: item.id ?? 1,
        result: {
          context: { slot: 0 },
          value: rule.method === "getSignatureStatuses" ? [null] : null,
        },
      };
    }
    return null;
  };

  if (Array.isArray(raw)) {
    const intercepted = raw.map((item) => apply(item));
    if (intercepted.every((entry) => entry !== null)) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(intercepted));
      return;
    }
  } else {
    const intercepted = apply(raw);
    if (intercepted !== null) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(intercepted));
      return;
    }
  }

  // No applicable rule: forward to upstream surfnet RPC.
  try {
    const upstream = await fetch(surfnet.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(raw),
    });
    const body = await upstream.text();
    res.writeHead(upstream.status, {
      "content-type":
        upstream.headers.get("content-type") ?? "application/json",
    });
    res.end(body);
  } catch (e) {
    res.writeHead(502, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: `upstream rpc failure: ${e.message}` }));
  }
}

const rpcServer = http.createServer((req, res) => {
  if (req.method === "POST") {
    forwardRpc(req, res).catch((err) => {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: String(err) }));
    });
    return;
  }
  res.writeHead(405, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "method_not_allowed" }));
});

// WS proxy stays at the TCP layer; surfpool websockets do not need fault
// injection for L8 (the signature replay store reservation guard is
// exercised purely through the HTTP RPC confirmation poll).
const wsServer = net.createServer((inbound) => {
  const upstream = net.connect({
    host: wsTarget.hostname,
    port: Number(wsTarget.port),
  });
  inbound.pipe(upstream);
  upstream.pipe(inbound);
  inbound.on("error", () => upstream.destroy());
  upstream.on("error", () => inbound.destroy());
});

// Out-of-band fault control endpoint. Tests POST a rule to /add and the
// proxy intercepts matching RPC methods for the next `count` calls.
// /reset clears all rules so state never leaks across scenarios. /rules
// returns the currently active rule set so tests can confirm reset.
const faultControl = http.createServer(async (req, res) => {
  try {
    if (req.method === "POST" && req.url === "/add") {
      const body = await readJson(req);
      if (typeof body.method !== "string" || !body.method) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "method is required" }));
        return;
      }
      const count = typeof body.count === "number" ? body.count : 1;
      faultRules.push({
        method: body.method,
        returnNull: body.returnNull === true,
        count,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, rules: faultRules.length }));
      return;
    }
    if (req.method === "POST" && req.url === "/reset") {
      faultRules.length = 0;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (req.method === "GET" && req.url === "/rules") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ rules: faultRules }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  } catch (err) {
    res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: String(err) }));
  }
});

await new Promise((resolve, reject) => {
  rpcServer.once("error", reject);
  rpcServer.listen({ host: "::", port: rpcPort }, () => {
    rpcServer.off("error", reject);
    resolve();
  });
});

await new Promise((resolve, reject) => {
  wsServer.once("error", reject);
  wsServer.listen({ host: "::", port: wsPort }, () => {
    wsServer.off("error", reject);
    resolve();
  });
});

await new Promise((resolve, reject) => {
  faultControl.once("error", reject);
  faultControl.listen({ host: "127.0.0.1", port: faultControlPort }, () => {
    faultControl.off("error", reject);
    resolve();
  });
});

for (let attempt = 0; attempt < 50; attempt++) {
  try {
    const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getHealth",
        params: [],
      }),
    });
    const body = await response.json();
    if (body.result === "ok") {
      console.log(
        `Surfnet ready at http://127.0.0.1:${rpcPort} -> ${surfnet.rpcUrl}, ws://127.0.0.1:${wsPort} -> ${surfnet.wsUrl}, fault control http://127.0.0.1:${faultControlPort}`,
      );
      break;
    }
  } catch {
    // Keep waiting until the proxy and embedded RPC are accepting requests.
  }
  await delay(100);
}

process.on("SIGTERM", () => {
  rpcServer.close(() => {
    wsServer.close(() => {
      faultControl.close(() => process.exit(0));
    });
  });
});

process.on("SIGINT", () => {
  rpcServer.close(() => {
    wsServer.close(() => {
      faultControl.close(() => process.exit(0));
    });
  });
});

setInterval(() => {
  surfnet.drainEvents();
}, 1_000);
