"""One-shot boot probe for the Python high-level MPP adapter's fail-closed gate.

The cross-SDK boot-policy conformance suite (`harness/test/boot-policy.test.ts`)
asserts that, off-localnet with NO shared replay store and WITHOUT the
`PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE` opt-in, each covered SDK's high-level
server adapter fails CLOSED at construction rather than silently defaulting to a
process-local in-memory store (which loses double-spend protection on a
multi-replica deploy — fail-OPEN).

The regular `python-server/server.py` MPP fixture cannot exercise that gate: it
constructs the lower-level `charge.Mpp` with an explicit `store=MemoryStore()`,
so the adapter never reaches its default-store guard. This script drives the
guard directly — it constructs `solana_pay_kit.protocols.mpp.MppAdapter` with
NO `replay_store`, so its `_default_replay_store()` fail-closed check runs:

  * no opt-in (fail-closed run): `MppAdapter(...)` raises the public
    `ConfigurationError` ("MPP requires an injected ProductionReplayStore
    outside localnet …"). We print that message to stderr and exit non-zero;
    `startServer` surfaces it as the boot failure the harness matches against
    the canonical fail-closed signature.
  * with the opt-in (`PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1`): the guard permits
    the default in-memory store, construction succeeds, and we print the `ready`
    JSON line + idle so the harness observes a `ready` boot — proving the opt-in
    (not a broken boot) is what gates the store.

Stdout discipline mirrors `server.py`: ONLY the `ready` JSON line is written to
stdout; every diagnostic (including the fail-closed rejection) goes to stderr.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from pathlib import Path


def _find_repo_root(start: Path) -> Path:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists() or (candidate / "python" / "pyproject.toml").is_file():
            return candidate
    return start.parents[-1]


_repo_root = _find_repo_root(Path(__file__).resolve())
_python_src = _repo_root / "python" / "src"
if _python_src.is_dir():
    sys.path.insert(0, str(_python_src))

from solana_pay_kit import Config, Network, Operator, Signer, Stablecoin  # noqa: E402
from solana_pay_kit.errors import ConfigurationError  # noqa: E402
from solana_pay_kit._paycore.network import SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2  # noqa: E402
from solana_pay_kit._paycore.solana import _canonical_network, validate_network  # noqa: E402
from solana_pay_kit.protocols.mpp import MppAdapter  # noqa: E402


def _resolve_network(raw: str) -> Network:
    """Map a supported harness slug or CAIP-2 id to a Network enum."""
    if raw == SOLANA_MAINNET_CAIP2:
        raw = "mainnet"
    elif raw == SOLANA_DEVNET_CAIP2:
        raw = "devnet"
    validate_network(raw)
    return Network(f"solana_{_canonical_network(raw)}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    network_raw = os.environ.get("MPP_HARNESS_NETWORK", "mainnet")
    try:
        network = _resolve_network(network_raw)
    except ValueError as exc:
        print(f"mpp-adapter-boot: unsupported MPP_HARNESS_NETWORK: {exc}", file=sys.stderr)
        sys.exit(2)
    pay_to = os.environ.get("MPP_HARNESS_PAY_TO")
    rpc_url = os.environ.get("MPP_HARNESS_RPC_URL", "http://127.0.0.1:1")
    signer_json = os.environ.get("MPP_HARNESS_FEE_PAYER_SECRET_KEY") or os.environ.get(
        "MPP_HARNESS_CLIENT_SECRET_KEY"
    )
    if not pay_to or not signer_json:
        print(
            "mpp-adapter-boot: MPP_HARNESS_PAY_TO and a signer secret key are required",
            file=sys.stderr,
        )
        sys.exit(2)

    # Umbrella Config for the high-level adapter. `preflight=False` keeps
    # construction offline (no RPC dial); the fail-closed store gate runs purely
    # off `network` + the opt-in env var. The stablecoin set is irrelevant to the
    # gate (pubkey-mode currency lives on the wire request), so USDC is a fine
    # placeholder here.
    config = Config(
        network=network,
        stablecoins=(Stablecoin.USDC,),
        rpc_url=rpc_url,
        operator=Operator(recipient=pay_to, signer=Signer.json(signer_json), fee_payer=True),
        preflight=False,
    )

    # Drive the high-level adapter constructor with NO replay_store: its
    # `_default_replay_store()` gate is exactly what we are probing.
    try:
        MppAdapter(config)
    except ConfigurationError as err:
        # Fail-closed: surface the canonical rejection on stderr and exit
        # non-zero so the harness records a boot failure carrying the signature.
        # MppAdapter re-raises the store policy violation as the public
        # ConfigurationError (a PayKitError, not a PaymentError), so catch that
        # exact type rather than letting a bare traceback carry the message.
        print(f"mpp-adapter-boot: fail-closed: {err}", file=sys.stderr)
        sys.exit(1)

    # Reached only with the opt-in set: construction succeeded (defaulted to the
    # in-memory store). Announce readiness and idle so the harness sees `ready`.
    port = _free_port()
    ready = {
        "type": "ready",
        "implementation": "python",
        "role": "server",
        "port": port,
        "capabilities": ["mpp"],
    }
    sys.stdout.write(json.dumps(ready) + "\n")
    sys.stdout.flush()

    # Block until the harness kills us (SIGTERM from stopServer).
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
