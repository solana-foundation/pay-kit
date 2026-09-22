# Client-side subscription: the first call activates on-chain, the rest are free.
#
# Mirrors harness/python-subscription-client/main.py. See
# ../../../docs/snippets-convention.md for the snippet:start/end convention.
import asyncio

import httpx

from solana_pay_kit import Signer
from solana_pay_kit._paycore.rpc import SolanaRpc
from solana_pay_kit.protocols.mpp.client.subscription import (
    build_subscription_access_credential,
    build_subscription_activation,
)
from solana_pay_kit.protocols.mpp.core.headers import format_authorization, parse_www_authenticate


async def main() -> None:
    signer = Signer.demo().keypair  # or Signer.file("payer.json").keypair
    rpc = SolanaRpc("https://api.devnet.solana.com")
    # snippet:start
    async with httpx.AsyncClient() as http:
        denied = await http.get("${URL}")  # 402 with the subscription challenge
        challenge = parse_www_authenticate(denied.headers["www-authenticate"])

        # The activation checks the on-chain Plan against the challenge, then
        # signs one transaction: authority init (only when missing), subscribe,
        # and the first period's transfer.
        activation = await build_subscription_activation(signer, rpc, challenge)
        first = await http.get("${URL}", headers={"authorization": format_authorization(activation.credential)})

        # Every later call inside the period presents the reusable bearer proof:
        # no signature, no charge, same subscription.
        access = build_subscription_access_credential(
            challenge.to_echo(), activation.subscription_delegation, activation.authentication
        )
        again = await http.get("${URL}", headers={"authorization": format_authorization(access)})
        print(first.status_code, again.status_code, again.headers["payment-receipt"])
    # snippet:end
    await rpc.aclose()


asyncio.run(main())
