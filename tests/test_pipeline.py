"""Tests for the processing pipeline (synchronous parts, no OCR)."""

import logging
from pathlib import Path
from unittest.mock import Mock

import pytest

from ftp2ocr.ocr import OcrConfig
from ftp2ocr.paths import PathFactory
from ftp2ocr.pipeline import (
    Mode,
    PdfProcessor,
    Task,
    _unique_destination,
    _write_error,
    process_file_task,
    route,
)


@pytest.fixture
def factory(tmp_path: Path) -> PathFactory:
    f = PathFactory(tmp_path)
    f.ensure_user_dirs("alice")
    return f


def test_route_modes(factory: PathFactory) -> None:
    assert route(factory.new_duplex("alice") / "x.pdf", "alice", factory) is Mode.DUPLEX
    assert route(factory.new_simplex("alice") / "x.pdf", "alice", factory) is Mode.OCR
    assert route(factory.observed("alice") / "x.pdf", "alice", factory) is Mode.OCR
    assert route(factory.new_raw("alice") / "x.pdf", "alice", factory) is Mode.RAW
    assert route(factory.backup("alice") / "x.pdf", "alice", factory) is None
    assert route(factory.home("alice") / "x.pdf", "alice", factory) is None


def test_unique_destination_no_collision(factory: PathFactory) -> None:
    dest = _unique_destination(factory.processed("alice"), "scan.pdf")
    assert dest == factory.processed("alice") / "scan.pdf"


def test_unique_destination_with_collision(factory: PathFactory) -> None:
    processed = factory.processed("alice")
    processed.mkdir(parents=True, exist_ok=True)
    (processed / "scan.pdf").write_text("existing")

    dest = _unique_destination(processed, "scan.pdf")
    assert dest != processed / "scan.pdf"
    assert dest.name.startswith("scan.")
    assert dest.name.endswith(".pdf")
    assert not dest.exists()


def test_write_error(factory: PathFactory) -> None:
    source = factory.new_simplex("alice") / "bad.pdf"
    source.write_text("broken")

    _write_error(factory, "alice", source, "it exploded")

    assert not source.exists()
    moved = factory.error("alice") / "bad.pdf"
    assert moved.exists()
    assert (factory.error("alice") / "bad.pdf.error.txt").read_text() == "it exploded"


def test_task_raw_mode(factory: PathFactory) -> None:
    source = factory.new_raw("alice") / "document.pdf"
    source.write_text("raw content")

    task = Task(
        file=source,
        user="alice",
        base_path=factory.base_path,
        mode=Mode.RAW,
        ocr=OcrConfig(),
    )
    process_file_task(task)

    # Published to processed and original moved to backup.
    assert (factory.processed("alice") / "document.pdf").read_text() == "raw content"
    assert (factory.backup("alice") / "document.pdf").read_text() == "raw content"
    assert not source.exists()


def test_task_raw_mode_no_temp_files_left(factory: PathFactory) -> None:
    source = factory.new_raw("alice") / "doc.pdf"
    source.write_text("x")
    task = Task(source, "alice", factory.base_path, Mode.RAW, OcrConfig())
    process_file_task(task)

    leftovers = [p.name for p in factory.new_raw("alice").iterdir() if ".ftp2ocr-" in p.name]
    assert leftovers == []


def test_task_missing_source_goes_to_error(factory: PathFactory) -> None:
    source = factory.new_raw("alice") / "ghost.pdf"
    # The file never exists. RAW mode tries to copy it and fails.
    task = Task(source, "alice", factory.base_path, Mode.RAW, OcrConfig())
    process_file_task(task)

    # Nothing published, nothing in backup.
    assert not (factory.processed("alice") / "ghost.pdf").exists()
    assert not (factory.backup("alice") / "ghost.pdf").exists()


def test_task_collision_does_not_overwrite(factory: PathFactory) -> None:
    # Pre-existing processed file.
    processed = factory.processed("alice")
    processed.mkdir(parents=True, exist_ok=True)
    (processed / "dup.pdf").write_text("old")

    source = factory.new_raw("alice") / "dup.pdf"
    source.write_text("new")
    task = Task(source, "alice", factory.base_path, Mode.RAW, OcrConfig())
    process_file_task(task)

    assert (processed / "dup.pdf").read_text() == "old"
    others = [p for p in processed.iterdir() if p.name != "dup.pdf"]
    assert len(others) == 1
    assert others[0].read_text() == "new"


@pytest.fixture
def ocr_handler_cls(tmp_path: Path):
    """The OcrFtpHandler class built by make_handler, without a live worker pool."""
    processor = PdfProcessor.__new__(PdfProcessor)
    return processor.make_handler(
        authorizer=Mock(),
        passv_range=None,
        passv_host=None,
        certfile=tmp_path / "cert.pem",
        keyfile=tmp_path / "key.pem",
    )


def _fake_handler(handler_cls, *, remote_ip: str, authenticated: bool):
    handler = object.__new__(handler_cls)
    handler.remote_ip = remote_ip
    handler.remote_port = 1234
    handler.username = "alice" if authenticated else ""
    handler.authenticated = authenticated
    return handler


def test_healthcheck_session_line_logged_at_debug(ocr_handler_cls, caplog) -> None:
    handler = _fake_handler(ocr_handler_cls, remote_ip="127.0.0.1", authenticated=False)
    with caplog.at_level(logging.DEBUG, logger="pyftpdlib"):
        handler.log("FTP session opened (connect)")
    assert caplog.records[-1].levelno == logging.DEBUG


def test_authenticated_session_line_logged_at_info(ocr_handler_cls, caplog) -> None:
    handler = _fake_handler(ocr_handler_cls, remote_ip="127.0.0.1", authenticated=True)
    with caplog.at_level(logging.DEBUG, logger="pyftpdlib"):
        handler.log("FTP session opened (connect)")
    assert caplog.records[-1].levelno == logging.INFO


def test_remote_session_line_logged_at_info(ocr_handler_cls, caplog) -> None:
    handler = _fake_handler(ocr_handler_cls, remote_ip="10.0.0.5", authenticated=False)
    with caplog.at_level(logging.DEBUG, logger="pyftpdlib"):
        handler.log("FTP session opened (connect)")
    assert caplog.records[-1].levelno == logging.INFO


def test_other_messages_logged_at_info_from_loopback(ocr_handler_cls, caplog) -> None:
    handler = _fake_handler(ocr_handler_cls, remote_ip="127.0.0.1", authenticated=False)
    with caplog.at_level(logging.DEBUG, logger="pyftpdlib"):
        handler.log("something else entirely")
    assert caplog.records[-1].levelno == logging.INFO
