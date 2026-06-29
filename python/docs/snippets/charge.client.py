# Client-side charge: pay an x402-gated endpoint in one retry.
#
# Mirrors examples/x402-client/main.py. See ../../../docs/snippets-convention.md.
import asyncio

from solana_pay_kit import Signer
from solana_pay_kit.protocols.x402.client import SolanaRpc, x402_async_client


async def main() -> None:
    signer = Signer.demo()  # or Signer.file("payer.json")
    rpc = SolanaRpc("https://api.devnet.solana.com")
    # snippet:start
    # x402_async_client returns an httpx.AsyncClient that turns any 402 into a
    # signed PAYMENT-SIGNATURE payment and replays the request — transparently.
    async with x402_async_client(signer, rpc) as http:
        resp = await http.get("${URL}")
        print(resp.status_code, resp.headers.get("payment-response"))
    # snippet:end


asyncio.run(main())
