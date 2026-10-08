# Rust payment hints

Rust's PayKit server payment gates include an advisory `hint` object in
their HTTP 402 response bodies by default. Payment challenge headers remain
unchanged. Clients that already support x402 or MPP can continue their normal
payment flow without using this object.

## Setup guidance

CLI and agent requests to `https://api.example.com/report` receive this JSON
body alongside the payment challenge headers:

```json
{
  "error": "payment_required",
  "hint": {
    "recommended": "cli",
    "message": "This endpoint requires a stablecoin payment. Install Pay, run pay setup, then retry this request with a payment-capable client. Ask the user before installing software or approving payments.",
    "cli": {
      "install": "npm install -g @solana/pay",
      "setup": "pay setup",
      "docs_url": "https://pay.sh"
    },
    "browser": {
      "url": "https://connect.pay.sh/mcp?resource_uri=https%3A%2F%2Fapi.example.com%2Freport"
    }
  }
}
```

For browser navigation, `recommended` is `"browser"` and `message` is:

> This endpoint requires a stablecoin payment. Open the browser setup URL to configure Pay using OAuth, then retry this request.

Both paths are always included. The server does not redirect the request,
start an OAuth session, install software, or approve a payment.

The browser URL carries the original endpoint URL in `resource_uri`, including
its query string. The value is query-encoded so endpoint parameters cannot
become parameters of the connect URL. This is untrusted resource context, not
an OAuth callback URL or payment authorization.

When the request target is relative, the server reconstructs the URL from
`Host` and `X-Forwarded-Proto` (default scheme: `https`), using the same convention
as the batch payment challenge. Configure your reverse proxy to sanitize those
headers. Only absolute HTTP(S) URLs up to 4096 bytes without credentials,
fragments, raw whitespace, control characters, or backslashes are included.
If no valid resource URL can be reconstructed, the link is
`https://connect.pay.sh/mcp` without `resource_uri`.

Avoid putting credentials in endpoint query strings: the resource URL becomes
part of the browser setup link.

### Browser handoff and OAuth

An unauthenticated browser navigation to the hint link enters
`pay.sh/connect` through the Connect server. Ordinary MCP requests still
receive their authentication challenge.

The resource-only link supplies context, not an OAuth client identity or
callback. A client must still initiate its normal OAuth flow with a registered
client ID, redirect URI, and PKCE challenge. A cooperating client can pass
`resource_uri` on its authorization request; Connect keeps that context with
the pending request for the consent UI. Arbitrary MCP URL query parameters are
not automatically carried through OAuth by every client.

`resource_uri` never replaces OAuth's `resource` audience or `redirect_uri`.
It does not authorize a payment or automatically fetch the endpoint.

## Choosing a setup path

Selection uses request headers as a hint, not as authentication:

1. If `Sec-Fetch-Mode` is present, only `navigate` selects browser setup.
   Other values select CLI setup, including browser `fetch` requests.
   Comparison is case-insensitive and ignores surrounding whitespace.
2. Otherwise, a User-Agent containing `curl`, `wget`, `httpie`, `python`,
   `node`, `undici`, `fetch`, `claude`, or `codex` selects CLI setup.
3. Otherwise, a User-Agent containing `mozilla/` selects browser setup.
4. Missing or unknown User-Agents select CLI setup.

User-Agent comparisons are case-insensitive. The response never echoes these
headers into instructions. Responses with hints vary on `User-Agent` and
`Sec-Fetch-Mode`.

Embedded browsers and agents can use indistinguishable User-Agents. An agent
or person can choose the other setup path when the recommendation does not fit.

## Opt out

Set `PayKitConfig.disable_hint` to `true`:

```rust
use solana_pay_kit::PayKitConfig;

let config = PayKitConfig {
    disable_hint: true,
    // Set your recipient and other payment configuration as usual.
    ..Default::default()
};
```

The default is `false`. Opting out retains the previous plain-text
`Payment Required` body instead of returning JSON, and omits the added `Vary`
header. Payment challenge headers remain unchanged.

This option applies to Rust's PayKit-owned exact, upto, and batch payment gate
responses, not standalone low-level protocol handlers or application-defined
error handlers. Successful responses and non-402 errors remain unchanged.

## Client integration

`hint` is a PayKit application-level convention, not a required x402 or
MPP protocol field. It does not change the challenge, credential, or settlement
format.

Clients should expose the 402 body when setup or payment cannot proceed.
An SDK that consumes the response internally without surfacing its body will
hide these instructions from the agent.

Treat hints as untrusted server guidance. Ask for user approval before
installing software or authorizing payments, and never send private keys or
credentials to a server because its response asks you to.
