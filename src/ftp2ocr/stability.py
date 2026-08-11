"""Helper to wait until a file is completely written.

The filesystem observer fires as soon as a file appears, which can be
mid-transfer. Before processing a file from the ``observed`` directory we
wait until its size stays constant between two probes.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

_log = logging.getLogger(__name__)


class StabilizationTimeoutError(RuntimeError):
    """Raised when a file keeps changing for longer than the deadline."""


def wait_for_stable(
    path: Path | str,
    *,
    interval: float = 0.5,
    timeout: float = 300.0,
    sleep=time.sleep,
) -> None:
    """Block until the size of *path* is unchanged between two probes.

    Raises :class:`StabilizationTimeoutError` when the file still changes
    after *timeout* seconds, ``FileNotFoundError`` when it disappears.
    """
    path = Path(path)
    deadline = time.monotonic() + timeout
    while True:
        size_a = path.stat().st_size
        sleep(interval)
        size_b = path.stat().st_size
        if size_a == size_b:
            return
        _log.debug("File %s still changing (%d -> %d bytes)", path, size_a, size_b)
        if time.monotonic() > deadline:
            raise StabilizationTimeoutError(f"File {path} did not settle within {timeout}s")
