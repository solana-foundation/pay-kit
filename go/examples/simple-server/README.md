# Go simple-server example

A minimal `net/http` server built on the `paykit` umbrella package. It
gates `/paid` with a single [`Gate`](../../paykit) and leaves `/health`
free. Because the umbrella registers both protocol adapters, the gate's
402 challenge advertises **x402** and **MPP** `accepts[]` at once, and a
client may settle with either.

The whole server is `paykit.New(...)` plus one `client.Require(gate)`
middleware. No manual challenge parsing, signing, or receipt encoding;
the adapters handle it.

## Run

```bash
cd go/examples/simple-server
go run .
```

The server binds to `127.0.0.1:4567`. With no operator signer set it
boots on the in-memory demo signer (it logs a warning) and defaults to
Surfpool localnet; pass a real `Operator.Signer` and `RPCURL` in
`paykit.Config` for anything beyond a smoke test.

## DX check

In another terminal:

```bash
brew install pay
curl http://127.0.0.1:4567/paid              # 402 with x402 + mpp accepts
pay --sandbox --x402 curl http://127.0.0.1:4567/paid   # pays via x402, 200
pay --sandbox --mpp  curl http://127.0.0.1:4567/paid   # pays via MPP, 200
```

`pay` reads the 402 challenge, builds and signs the payment for the
chosen protocol, retries with the credential header, and prints the
`{"ok":true,"paid":true}` body together with the on-chain settlement
signature the server echoes back.

## Behavior

- `GET /health` returns `200 {"ok":true}`.
- `GET /paid` with no credential returns `402` with the challenge
  headers (`payment-required` for x402, `WWW-Authenticate: Payment` for
  MPP) and a JSON body listing both `accepts[]` entries.
- `GET /paid` with a valid `Payment-Signature` (x402) or
  `Authorization: Payment` (MPP) credential returns `200` and the
  settlement signature header.
- Rejections re-issue a `402` carrying the canonical fault code
  (`charge_request_mismatch`, `wrong_network`, `payment_invalid`, ...).
