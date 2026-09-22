"""FileReplayStore is the fence two processes share, so test it across processes.

The replay keys and the subscription renewal claims both stand on
``put_if_absent`` being atomic for everyone on one path: two workers that both
win it settle the same credential twice, or charge the same period twice. These
tests run the real race, not a simulated one.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from solana_pay_kit._paycore.store import FileReplayStore, MemoryStore

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


async def test_a_write_fsyncs_the_directory_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The rename has to reach disk too, or a crash can restore the file without
    # the key the caller was told was stored.
    store = FileReplayStore(tmp_path / "replay.json")
    synced: list[bool] = []
    real_fsync = os.fsync

    def record(fd: int) -> None:
        synced.append(os.fstat(fd).st_mode & 0o170000 == 0o040000)  # S_IFDIR
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", record)
    await store.put("signature", {"challengeId": "ch-1"})
    assert synced == [False, True]  # the temp file, then its directory


@pytest.mark.parametrize("kind", ["memory", "file"])
def test_threads_with_their_own_event_loops_do_not_deadlock(tmp_path: Path, kind: str) -> None:
    # The Flask and Django shims run one asyncio.run per request, so one store
    # is driven from several loops at once. A lock bound to a loop would raise
    # or hang here; the timeout turns a hang into a failure instead of a stall.
    store: Any = MemoryStore() if kind == "memory" else FileReplayStore(tmp_path / "replay.json")

    start = threading.Barrier(8)

    async def claims(index: int) -> bool:
        # Contend inside each loop first: an uncontended asyncio.Lock never binds
        # itself to a loop, so a single quick call would not show the break.
        await asyncio.gather(*(store.put_if_absent(f"key-{n}", {"winner": index}) for n in range(50)))
        return await store.put_if_absent("claim", {"winner": index})

    def claim(index: int) -> bool:
        start.wait(timeout=30)
        return asyncio.run(claims(index))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(claim, index) for index in range(8)]
        results = [future.result(timeout=60) for future in futures]
    assert results.count(True) == 1
