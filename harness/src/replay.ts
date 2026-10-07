import { createServer, request, type IncomingHttpHeaders } from "node:http";
import { CANONICAL_CODES, type CanonicalErrorCode } from "./canonical-codes";

function forwardedHeaders(source: IncomingHttpHeaders): IncomingHttpHeaders {
  const excluded = new Set([
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    ...(source.connection ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase()),
  ]);
  return Object.fromEntries(
    Object.entries(source).filter(
      ([key, value]) => !excluded.has(key) && value !== undefined,
    ),
  );
}

/**
 * Runs an unmodified client through a loopback forwarding endpoint, then replays
 * its successful credential-bearing request. Supports MPP Authorization and
 * x402 Payment-Signature headers; credentials stay private.
 */
export async function replaySuccessfulPayment(
  target: string,
  runClient: (url: string) => Promise<unknown>,
  credentialHeader: "authorization" | "payment-signature" = "authorization",
): Promise<{ firstStatus: number; status: number; responseBody: unknown }> {
  const url = new URL(target);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1") {
    throw new Error("Replay capture requires a loopback HTTP server");
  }
  type Capture = {
    method: string;
    headers: IncomingHttpHeaders;
    body: Buffer;
  };
  let capture: Capture | undefined;
  let failure: string | undefined;
  let paymentStatus: number | undefined;
  const upstreamRequests = new Set<ReturnType<typeof request>>();
  const proxy = createServer(async (incoming, outgoing) => {
    try {
      // Pin the destination; never forward credentials to a client-selected URL.
      if (incoming.url !== `${url.pathname}${url.search}`) {
        throw new Error("Unexpected capture path");
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of incoming) {
        const bytes = Buffer.from(chunk);
        size += bytes.length;
        if (size > 1024 * 1024) throw new Error("Capture request too large");
        chunks.push(bytes);
      }
      const body = Buffer.concat(chunks);
      const headers = forwardedHeaders(incoming.headers);
      const method = incoming.method ?? "GET";
      const upstream = request(url, { method, headers }, (response) => {
        const status = response.statusCode ?? 502;
        const credential = headers[credentialHeader];
        if (
          typeof credential === "string" &&
          credential.length > 0 &&
          (credentialHeader !== "authorization" || /^Payment\s/i.test(credential))
        ) {
          paymentStatus = status;
          if (status === 200 && !capture) capture = { method, headers, body };
        }
        outgoing.writeHead(status, forwardedHeaders(response.headers));
        response.on("error", () => {
          failure = "Capture upstream response failed";
          outgoing.destroy();
        });
        response.pipe(outgoing);
      });
      upstreamRequests.add(upstream);
      upstream.on("close", () => upstreamRequests.delete(upstream));
      upstream.on("error", () => {
        failure = "Capture upstream request failed";
        outgoing.destroy();
      });
      upstream.setTimeout(30_000, () => upstream.destroy());
      upstream.end(body);
    } catch {
      failure = "Capture forwarding failed";
      outgoing.writeHead(502);
      outgoing.end();
    }
  });
  try {
    await new Promise<void>((resolve, reject) => {
      proxy.once("error", reject);
      proxy.listen(0, "127.0.0.1", resolve);
    });
    const address = proxy.address();
    if (!address || typeof address === "string") {
      throw new Error("Capture did not bind");
    }
    try {
      await runClient(`http://127.0.0.1:${address.port}${url.pathname}${url.search}`);
    } catch {
      // Adapter output/errors can contain Authorization. Keep these private.
      throw new Error(
        `Replay client failed; observed payment status: ${paymentStatus ?? "none"}`,
      );
    }
    if (failure) throw new Error(failure);
    if (!capture) {
      throw new Error(
        `Replay requires a captured first 200 Payment response; observed: ${paymentStatus ?? "none"}`,
      );
    }
    const headers = new Headers();
    for (const [key, value] of Object.entries(capture.headers)) {
      const values = Array.isArray(value) ? value : value === undefined ? [] : [value];
      for (const item of values) {
        headers.append(key, item);
      }
    }
    let response: Response;
    let text: string;
    try {
      response = await fetch(url, {
        method: capture.method,
        headers,
        body:
          capture.method === "GET" || capture.method === "HEAD"
            ? undefined
            : new Uint8Array(capture.body),
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
      });
      text = await response.text();
    } catch {
      throw new Error("Raw payment replay failed after first 200");
    }
    let responseBody: unknown;
    try {
      responseBody = JSON.parse(text);
    } catch {
      responseBody = undefined;
    }
    // Do not expose a server echo of Authorization in diagnostics.
    const code =
      responseBody &&
      typeof responseBody === "object" &&
      "code" in responseBody &&
      typeof responseBody.code === "string" &&
      CANONICAL_CODES.includes(responseBody.code as CanonicalErrorCode)
        ? responseBody.code
        : undefined;
    return { firstStatus: 200, status: response.status, responseBody: { code } };
  } finally {
    capture = undefined;
    for (const upstream of upstreamRequests) upstream.destroy();
    await new Promise<void>((resolve) => {
      proxy.close(() => resolve());
      proxy.closeAllConnections();
    });
  }
}
