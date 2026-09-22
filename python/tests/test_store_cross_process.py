"""FileReplayStore is the fence two processes share, so test it across processes.

The replay keys and the subscription renewal claims both stand on
``put_if_absent`` being atomic for everyone on one path: two workers that both
win it settle the same credential twice, or charge the same period twice. These
tests run the real race, not a simulated one.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path

import pytest

from solana_pay_kit._paycore.store import FileReplayStore

pytestmark = pytest.mark.asyncio

# Claim the key in a fresh interpreter and print the outcome. Run through
# subprocess rather than multiprocessing: the spawn start method re-imports the
# worker's module, which a pytest test module is not importable as.
_WORKER = """
import asyncio, json, sys
from solana_pay_kit._paycore.store import FileReplayStore

store = FileReplayStore(sys.argv[1])
print(json.dumps(asyncio.run(store.put_if_absent("claim", {"winner": sys.argv[2]}))))
"""


async def test_only_one_instance_wins_put_if_absent(tmp_path: Path) -> None:
    first, second = FileReplayStore(tmp_path / "replay.json"), FileReplayStore(tmp_path / "replay.json")
    assert await first.put_if_absent("claim", {"winner": "first"}) is True
    assert await second.put_if_absent("claim", {"winner": "second"}) is False
    assert await second.get("claim") == {"winner": "first"}


async def test_a_write_in_one_instance_is_visible_in_another(tmp_path: Path) -> None:
    writer, reader = FileReplayStore(tmp_path / "replay.json"), FileReplayStore(tmp_path / "replay.json")
    await writer.put("signature", {"challengeId": "ch-1"})
    assert await reader.get("signature") == {"challengeId": "ch-1"}
    # A second key from the reader must not erase the writer's.
    assert await reader.put_if_absent("other", {"challengeId": "ch-2"}) is True
    assert await writer.get("signature") == {"challengeId": "ch-1"}
    await writer.delete("signature")
    assert await reader.get("signature") is None and await reader.get("other") == {"challengeId": "ch-2"}


async def test_processes_racing_one_key_produce_one_winner(tmp_path: Path) -> None:
    path = str(tmp_path / "replay.json")
    FileReplayStore(path)  # create the file the racers share

    def claim(index: int) -> subprocess.Popen[str]:
        return subprocess.Popen([sys.executable, "-c", _WORKER, path, str(index)], stdout=subprocess.PIPE, text=True)

    racers = [claim(index) for index in range(8)]
    outcomes = [json.loads(racer.communicate()[0].strip()) for racer in racers]
    assert outcomes.count(True) == 1

    store = FileReplayStore(path)
    claimed = await store.get("claim")
    assert claimed is not None and claimed["winner"] in {str(index) for index in range(8)}


async def test_concurrent_coroutines_in_one_process_still_serialize(tmp_path: Path) -> None:
    store = FileReplayStore(tmp_path / "replay.json")
    results = await asyncio.gather(*(store.put_if_absent("claim", {"winner": n}) for n in range(8)))
    assert results.count(True) == 1
