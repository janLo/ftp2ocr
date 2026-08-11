"""Tests for the file stabilization helper."""

import threading
import time
from pathlib import Path

import pytest

from ftp2ocr.stability import StabilizationTimeoutError, wait_for_stable


def test_stable_file_returns_immediately(tmp_path: Path) -> None:
    file = tmp_path / "scan.pdf"
    file.write_bytes(b"data")

    calls = []
    wait_for_stable(file, interval=0.01, sleep=lambda s: calls.append(s))
    assert len(calls) == 1  # one probe was enough


def test_growing_file_waits(tmp_path: Path) -> None:
    file = tmp_path / "scan.pdf"
    file.write_bytes(b"a")

    stop = threading.Event()

    def grow():
        while not stop.is_set():
            with file.open("ab") as fh:
                fh.write(b"x")
            time.sleep(0.005)

    writer = threading.Thread(target=grow, daemon=True)
    writer.start()
    try:
        with pytest.raises(StabilizationTimeoutError):
            wait_for_stable(file, interval=0.01, timeout=0.2)
    finally:
        stop.set()
        writer.join(timeout=2)


def test_settles_after_write_stops(tmp_path: Path) -> None:
    file = tmp_path / "scan.pdf"
    file.write_bytes(b"start")

    def finish_later():
        time.sleep(0.05)
        file.write_bytes(b"start" + b"finished")

    writer = threading.Thread(target=finish_later, daemon=True)
    writer.start()
    wait_for_stable(file, interval=0.02, timeout=5)
    writer.join(timeout=2)
    assert file.read_bytes() == b"startfinished"
