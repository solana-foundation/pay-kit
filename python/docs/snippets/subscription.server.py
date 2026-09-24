# Server-side subscription: one recurring on-chain authorization gates a route.
#
# Mirrors examples/playground_api/subscriptions.py. See
# ../../../docs/snippets-convention.md for the snippet:start/end convention.
import solana_pay_kit
from fastapi import APIRouter, Depends
from solana_pay_kit._paycore.solana import resolve_mint
from solana_pay_kit._paycore.store import MemoryStore
from solana_pay_kit.fastapi import RequireSubscription
from solana_pay_kit.protocols.mpp.server.subscription import (
    SubscriptionChallengeOptions,
    SubscriptionConfig,
    SubscriptionServer,
)

router = APIRouter()
cfg = solana_pay_kit.config()
PLAN_ID = "<on-chain Plan PDA>"  # created ahead of time with the subscriptions program

# snippet:start
# One subscription plan, built from the shared config. The server signs the
# renewal itself, so the puller is the operator signer.
server = SubscriptionServer(
    SubscriptionConfig(
        plan=PLAN_ID,
        mint=resolve_mint("USDC", cfg.network.mints_label()),
        recipient=cfg.effective_recipient(),
        amount=100_000,  # 0.10 USDC per period
        period_unit="day",
        period_count=1,
        puller_signer=cfg.operator.signer,
        store=MemoryStore(),  # or FileReplayStore(path) across restarts
        network=cfg.network.mints_label(),
        rpc_url=cfg.effective_rpc_url(),
        secret_key=cfg.mpp.challenge_binding_secret or "",
    )
)

# RequireSubscription is the 402 gate: the first call activates the plan
# on-chain, later calls in the period present a bearer proof, and an unpaid
# period is collected on access.
gate = Depends(RequireSubscription(server, SubscriptionChallengeOptions(description="Feed subscription")))


@router.get("${PATH}")
async def feed(_=gate) -> dict[str, object]:
    return {"headlines": [...]}  # the subscriber's content for this period


# snippet:end
