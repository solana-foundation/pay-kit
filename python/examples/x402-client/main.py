# examples/x402-client/main.py
"""Pay an x402-gated endpoint with the pay_kit x402 ``exact`` client.

The auto-pay transport mirrors the Go ``NewClient`` ergonomics: give it a payer
signer and an RPC, get back an ``httpx.AsyncClient`` that turns any ``402`` into
a signed ``PAYMENT-SIGNATURE`` payment and replays the request.

Run a server first (see examples/fastapi), then:

    pip install -e ".[fastapi]"
    uvicorn app:app --app-dir examples/fastapi --port 8000   # the gated server
    python examples/x402-client/main.py http://127.0.0.1:8000/report

Env:
    X402_PAYER_KEY   path to the payer's Solana keypair JSON (default: demo signer)
    X402_RPC_URL     Solana RPC for the blockhash fallback (default: devnet)
"""

from __future__ import annotations

import asyncio
import os
import sys

from pay_kit import Signer
from pay_kit._paycore.rpc import SolanaRpc
from pay_kit.protocols.x402.client import x402_async_client


async def main(url: str) -> int:
    key_path = os.environ.get("X402_PAYER_KEY")
    signer = Signer.file(key_path) if key_path else Signer.demo()
    rpc = SolanaRpc(os.environ.get("X402_RPC_URL", "https://api.devnet.solana.com"))

    # High-level: one client that auto-pays the 402 and returns the paid response.
    async with x402_async_client(signer, rpc) as http:
        resp = await http.get(url)
        settlement = resp.headers.get("payment-response") or resp.headers.get("x-payment-settlement-signature")
        print(f"status      : {resp.status_code}")
        print(f"settlement  : {settlement}")
        print(f"body        : {resp.text[:200]}")

    # Low-level equivalent (drive your own HTTP): parse the offer, build the header.
    # async with httpx.AsyncClient() as raw:
    #     first = await raw.get(url)
    #     offer = parse_x402_challenge(dict(first.headers), first.text, ChallengeSelection())
    #     header = await build_payment_header(signer, rpc, offer)
    #     paid = await raw.get(url, headers={"PAYMENT-SIGNATURE": header})

    return 0 if resp.is_success else 1


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/report"
    raise SystemExit(asyncio.run(main(target)))
