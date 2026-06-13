# examples/playground_api/main.py
"""Entrypoint: boot the playground API with best-effort surfnet funding, then
serve it with uvicorn.

    cd python
    python -m examples.playground_api.main

Environment knobs are documented in README.md and resolved in
:func:`app.state_from_env`.
"""

from __future__ import annotations

import asyncio
import logging

from . import constants
from .app import AppState, create_app, state_from_env
from .utils import rpc_call

logger = logging.getLogger("playground-api")


async def bootstrap_funding(state: AppState) -> None:
    """Fund the fee payer and recipient on the local surfnet so the demo works
    zero-config.

    Best-effort: a warning is logged when the sandbox is unreachable.
    """
    try:
        await rpc_call(
            state.rpc_url,
            "surfnet_setAccount",
            [
                state.fee_payer_pubkey,
                {
                    "lamports": constants.SOL_FUND_LAMPORTS,
                    "data": "",
                    "executable": False,
                    "owner": constants.SYSTEM_PROGRAM_ID,
                    "rentEpoch": 0,
                },
            ],
        )
        await rpc_call(
            state.rpc_url,
            "surfnet_setTokenAccount",
            [
                state.recipient,
                constants.USDC_MAINNET_MINT,
                {"amount": constants.USDC_FUND_AMOUNT, "state": "initialized"},
                constants.TOKEN_PROGRAM_ID,
            ],
        )
    except Exception:
        logger.warning("Surfpool not reachable; fee payer may not have SOL for fees.")


def _log_boot(state: AppState) -> None:
    """Print the boot banner mirroring the Go example's startup log."""
    logger.info("PayKit Playground (Python)  http://localhost:%d", state.port)
    logger.info("  Network    %s", state.network)
    logger.info("  RPC        %s", state.rpc_url)
    logger.info("  Recipient  %s", state.recipient)
    logger.info("  Fee payer  %s", state.fee_payer_pubkey)
    logger.info("  Plan       not bootstrapped (subscriptions are not implemented in the Python SDK)")
    logger.info("  Sessions   enabled (in-process)")


def main() -> None:
    """Build state, fund the sandbox, and serve the app."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    state = state_from_env()
    asyncio.run(bootstrap_funding(state))
    app = create_app(state)
    _log_boot(state)
    uvicorn.run(app, host="0.0.0.0", port=state.port, log_level="info")


if __name__ == "__main__":
    main()
