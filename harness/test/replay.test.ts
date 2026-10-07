import { createServer, type RequestListener } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { CANONICAL_CODES } from "../src/canonical-codes";
import { replaySuccessfulPayment } from "../src/replay";

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    });
  }
});

async function serve(listener: RequestListener): Promise<string> {
  const server = createServer(listener);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No listener");
  return `http://127.0.0.1:${address.port}/protected?query=1`;
}

describe("language-independent payment capture", () => {
  it("forwards challenges and replays identical credentials, headers, method and body", async () => {
    const requests: { authorization?: string; body: string; method?: string; header?: string; url?: string }[] = [];
    const target = await serve(async (request, response) => {
      const chunks = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      requests.push({
        authorization: request.headers.authorization,
        body: Buffer.concat(chunks).toString(),
        method: request.method,
        header: request.headers["x-custom"] as string | undefined,
        url: request.url,
      });
      if (!request.headers.authorization) {
        response.writeHead(402, { "www-authenticate": "Payment challenge" });
        response.end("challenge");
      } else {
        response.writeHead(requests.length === 2 ? 200 : 402);
        response.end(JSON.stringify({ code: "signature_consumed", echo: request.headers.authorization }));
      }
    });
    let proxyUrl = "";
    const result = await replaySuccessfulPayment(target, async (url) => {
      proxyUrl = url;
      const challenge = await fetch(url);
      expect(challenge.status).toBe(402);
      expect(challenge.headers.get("www-authenticate")).toBe("Payment challenge");
      await challenge.text();
      const paid = await fetch(url, {
        method: "POST",
        headers: { Authorization: "Payment private-credential", "x-custom": "preserved" },
        body: "exact body",
      });
      expect(paid.status).toBe(200);
      await paid.text();
    });
    expect(result).toEqual({ firstStatus: 200, status: 402, responseBody: { code: "signature_consumed" } });
    expect(requests).toHaveLength(3);
    expect(requests[2]).toEqual(requests[1]);
    expect(JSON.stringify(result)).not.toContain("private-credential");
    await expect(fetch(proxyUrl)).rejects.toThrow();
  });

  it("replays x402 without requiring a client-side resubmit hook", async () => {
    const credentials: (string | string[] | undefined)[] = [];
    const target = await serve((request, response) => {
      credentials.push(request.headers["payment-signature"]);
      expect(request.headers.authorization).toBeUndefined();
      response.writeHead(credentials.length === 1 ? 200 : 402);
      response.end(JSON.stringify({ code: "signature_consumed" }));
    });
    const result = await replaySuccessfulPayment(
      target,
      async (url) => {
        const response = await fetch(url, {
          headers: { "payment-signature": "private-x402-credential" },
        });
        await response.text();
      },
      "payment-signature",
    );
    expect(credentials).toEqual(["private-x402-credential", "private-x402-credential"]);
    expect(result).toEqual({
      firstStatus: 200,
      status: 402,
      responseBody: { code: "signature_consumed" },
    });
    expect(JSON.stringify(result)).not.toContain("private-x402-credential");
  });

  it.each([200, 402])("rejects missing successful Payment capture (status %i)", async (status) => {
    let requests = 0;
    const target = await serve((_request, response) => {
      requests++;
      response.writeHead(status);
      response.end();
    });
    await expect(replaySuccessfulPayment(target, async (url) => {
      await fetch(url, { headers: status === 402 ? { authorization: "Payment secret" } : {} });
    })).rejects.toThrow("requires a captured first 200");
    expect(requests).toBe(1);
  });

  it("cleans up and redacts client errors without replaying", async () => {
    let proxyUrl = "";
    const target = await serve((_request, response) => response.end());
    await expect(replaySuccessfulPayment(target, async (url) => {
      proxyUrl = url;
      throw new Error("Payment secret");
    })).rejects.toThrow("Replay client failed; observed payment status: none");
    await expect(fetch(proxyUrl)).rejects.toThrow();
  });

  it.each([...CANONICAL_CODES, "Payment private-credential"])(
    "preserves only allowlisted diagnostic codes: %s",
    async (code) => {
      let requests = 0;
      const target = await serve((_request, response) => {
        requests++;
        response.writeHead(requests === 1 ? 200 : 402);
        response.end(JSON.stringify({ code, detail: "Payment private-credential" }));
      });
      const result = await replaySuccessfulPayment(target, async (url) => {
        const response = await fetch(url, {
          headers: { authorization: "Payment private-credential" },
        });
        await response.text();
      });
      expect(result).toEqual({
        firstStatus: 200,
        status: 402,
        responseBody: { code: code.startsWith("Payment ") ? undefined : code },
      });
      expect(JSON.stringify(result)).not.toContain("private-credential");
    },
  );

  it("does not follow replay redirects", async () => {
    let requests = 0;
    const target = await serve((_request, response) => {
      requests++;
      response.writeHead(requests === 1 ? 200 : 307, { location: "/leak" });
      response.end();
    });
    const result = await replaySuccessfulPayment(target, async (url) => {
      await fetch(url, { headers: { authorization: "Payment secret" } });
    });
    expect(result.status).toBe(307);
    expect(requests).toBe(2);
  });
});
