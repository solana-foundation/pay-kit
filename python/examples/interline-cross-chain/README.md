# pay-kit on Solana + Interline for Base/EVM

> One service, agents on either chain pay it.

pay-kit gives you Solana-native agent payments (x402 + MPP). That's exactly what
you want when your buyers are on Solana. But an agent paying from **Base or
another EVM chain** can't settle against a Solana gate.

[**Interline**](https://github.com/Choppaaahh/interline-routes) is a neutral,
non-custodial **cross-chain x402 router** (`pip install interline`). Put it in
front of the same capability and your endpoint *also* accepts Base/EVM x402 — the
chain pay-kit doesn't cover — and you still hold no funds (each rail settles
buyer → your wallet directly).

This example serves the **same** "premium report" two ways so the difference is
obvious:

| Route | Gated by | Accepts |
|---|---|---|
| `GET /solana/report` | pay-kit | Solana USDC |
| `GET /crosschain/report` | Interline | Base/EVM USDC *(add the Solana rail for both)* |
| `GET /health` | — | free |

## Run

```bash
# pay-kit installs from this repo (the FastAPI extra) — run from the pay-kit python/ dir:
pip install -e ".[fastapi]"
# Interline — the cross-chain router (on PyPI):
pip install interline
# then, from this example folder:
uvicorn server:app --port 8000
```

Both routes are **zero-config**: pay-kit boots against its hosted Surfpool
sandbox, and Interline wires mock facilitators (no wallet / keys / chain), so the
402 dance runs out of the box.

```bash
curl -i http://127.0.0.1:8000/solana/report        # 402 — Solana challenge
curl -i http://127.0.0.1:8000/crosschain/report    # 402 — Base/EVM challenge
```

## How it composes

- **pay-kit** owns the Solana side: idiomatic `Gate.build(...)` + the
  `RequirePayment` FastAPI dependency, exactly as in pay-kit's own examples.
- **Interline** adds the EVM side: one `Paywall(rails=[X402Rail(...)])` whose
  402 advertises a Base/EVM x402 offer. Adding another chain (e.g. x402 on
  Solana, so the *single* Interline route covers both) is one more list entry —
  the route never changes.

## Going live

Swap the mocks for real facilitators:

- pay-kit: `pay_kit.configure(network="solana_mainnet", ...)` with your recipient.
- Interline: give each `X402Rail` its live facilitator (a Base x402 facilitator,
  and a Solana facilitator for the Solana rail). The same `.gate()` code path
  then settles on-chain.

Replace the placeholder `EVM_PAY_TO` (and pay-kit's recipient) with your own
receiving wallets first. Neither library ever custodies funds.
