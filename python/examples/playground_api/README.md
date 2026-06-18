# Playground API (Python)

A FastAPI server gated with the unified `pay_kit` surface, the same idioms as
`examples/fastapi/app.py`. Zero-config: `pay_kit.configure(network="solana_localnet")`
boots against the hosted Surfpool sandbox with the shipped demo signer.

Routes:

- `GET  /health`  free liveness probe.
- `GET  /report`  charge-gated via `RequirePayment` (both protocols).
- `POST /compute` session-gated, metered (see `sessions.py`).

Run:

```sh
cd python
uvicorn examples.playground_api.app:app --port 3000
```

Drive it:

```sh
curl -i http://127.0.0.1:3000/report     # 402 payment required
pay curl http://127.0.0.1:3000/report    # pays and succeeds
```
