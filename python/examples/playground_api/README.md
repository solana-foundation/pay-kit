# Playground API (Python)

A FastAPI server gated with the unified `pay_kit` surface, aligned with the
TypeScript playground (`typescript/examples/playground-api`). Zero-config:
`pay_kit.configure(network="solana_localnet")` boots against the hosted Surfpool
sandbox with the shipped demo signer.

Routes:

- `GET  /api/v1/fortune`        fixed charge, settled over MPP or x402 (client's choice).
- `GET  /api/v1/quote/{symbol}` fixed charge, MPP or x402; `via` reports the rail used.
- `GET  /api/v1/joke`           MPP charge with a platform split (x402 auto-disabled).
- `GET  /api/v1/stream`         MPP session: open a channel, stream metered SSE deliveries.
- `GET  /sessions/receipt/{id}` poll a session channel's settle status (out-of-band settlement).
- `GET  /api/v1/docs[...]`      unpaid SDK reference markdown (when generated).
- `POST /api/v1/faucet/airdrop` localnet-only USDC faucet for client wallets.
- `GET  /openapi.json`          OpenAPI 3.1 discovery with `x-payment-info` offers per route.
- `GET  /api/v1/health`         free liveness probe + operator / network info.

The session side-channel (`POST /__402/session/deliveries` and `/commit`) is
mounted for the metered-voucher flow.

The x402 `upto` (usage) and MPP `subscription` gates the TS playground also
shows are intentionally left out: the Python SDK does not ship those gate kinds
yet (a follow-up), so they are not hand-rolled here.

Run:

```sh
cd python
uvicorn examples.playground_api.app:app --port 3000
# Optional: seed operator/recipient/platform on the local sandbox at boot.
PAY_KIT_PLAYGROUND_FUND=1 uvicorn examples.playground_api.app:app --port 3000
```

Drive it:

```sh
curl -i http://127.0.0.1:3000/api/v1/fortune     # 402 payment required
pay curl http://127.0.0.1:3000/api/v1/fortune    # pays and succeeds
```
