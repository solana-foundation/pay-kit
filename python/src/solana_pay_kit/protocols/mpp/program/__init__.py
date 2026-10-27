"""Hand-written helpers for the on-chain programs the MPP intents drive.

:mod:`solana_pay_kit.protocols.mpp.program.subscriptions` carries the
subscriptions program (the ``subscription`` intent): program id, PDA
derivations, instruction data encoders, instruction builders and the account
decoders the client and server read.
"""

from __future__ import annotations
