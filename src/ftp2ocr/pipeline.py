"""The processing pipeline.

An uploaded PDF is routed by the directory it landed in. Each file is handled
by a single, self-contained worker task so the whole pipeline for that file
(reorder → OCR → publish → backup) is atomic and easy to reason about, unlike
the previous chain of ``apply_async`` callbacks.
"""

from __future__ import annotations

import enum
import logging
import multiprocessing
import os
import shutil
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.log import logger as _ftpd_logger
from watchdog.events import FileCreatedEvent, FileMovedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ftp2ocr.certs import ensure_cert
from ftp2ocr.ocr import OcrConfig, copy_file, reorder_duplex, run_ocr
from ftp2ocr.paths import PathFactory, is_subpath
from ftp2ocr.stability import StabilizationTimeoutError, wait_for_stable

_log = logging.getLogger(__name__)

# The container HEALTHCHECK opens a loopback control connection every 30s and
# never logs in; log its session lines at DEBUG instead of INFO to avoid
# drowning out real scanner sessions.
_SESSION_LOG_LINES = frozenset({"FTP session opened (connect)", "FTP session closed (disconnect)."})
_LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1"})


class Mode(enum.Enum):
    """What should happen with an uploaded file."""

    DUPLEX = "duplex"
    OCR = "ocr"
    RAW = "raw"


@dataclass(frozen=True)
class Task:
    """Everything a worker needs to process one file (picklable)."""

    file: Path
    user: str
    base_path: Path
    mode: Mode
    ocr: OcrConfig


def route(file: Path, user: str, path_factory: PathFactory) -> Mode | None:
    """Decide what should happen with *file* based on the directory it is in."""
    if is_subpath(file, path_factory.new_duplex(user)):
        return Mode.DUPLEX
    if is_subpath(file, path_factory.new_simplex(user)):
        return Mode.OCR
    if is_subpath(file, path_factory.observed(user)):
        return Mode.OCR
    if is_subpath(file, path_factory.new_raw(user)):
        return Mode.RAW
    return None


def _unique_destination(directory: Path, name: str) -> Path:
    """Return a path in *directory* that does not collide with an existing file."""
    directory.mkdir(parents=True, exist_ok=True)
    candidate = directory / name
    if not candidate.exists():
        return candidate

    stem = candidate.stem
    suffix = candidate.suffix
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    candidate = directory / f"{stem}.{stamp}{suffix}"
    counter = 1
    while candidate.exists():
        candidate = directory / f"{stem}.{stamp}-{counter}{suffix}"
        counter += 1
    return candidate


def _write_error(path_factory: PathFactory, user: str, source: Path, error: str) -> None:
    """Move a failed file to the error directory and record the reason."""
    try:
        target = _unique_destination(path_factory.error(user), source.name)
        shutil.move(str(source), str(target))
        (target.with_suffix(target.suffix + ".error.txt")).write_text(error, encoding="utf-8")
        _log.error("file %s failed: %s", source, error)
    except OSError:
        _log.exception("could not move failed file %s to error directory", source)


def process_file_task(task: Task) -> None:
    """Process one uploaded file end-to-end. Runs in a worker process."""
    path_factory = PathFactory(task.base_path)
    source = task.file
    suffix = f".ftp2ocr-{os.getpid()}-{uuid.uuid4().hex}"
    temp_files: list[Path] = []

    def tmp(name_suffix: str) -> Path:
        path = source.with_name(source.name + name_suffix + suffix)
        temp_files.append(path)
        return path

    try:
        if task.mode is Mode.DUPLEX:
            reordered = tmp(".reordered.pdf")
            reorder_duplex(source, reordered)
            ocr_output = tmp(".ocr.pdf")
            run_ocr(reordered, ocr_output, task.ocr)
            final_source = ocr_output
        elif task.mode is Mode.OCR:
            ocr_output = tmp(".ocr.pdf")
            run_ocr(source, ocr_output, task.ocr)
            final_source = ocr_output
        else:  # RAW
            final_source = source

        destination = _unique_destination(path_factory.processed(task.user), source.name)
        copy_file(final_source, destination)
        _log.info("published %s -> %s", source, destination)

        backup_target = _unique_destination(path_factory.backup(task.user), source.name)
        shutil.move(str(source), str(backup_target))
    except Exception as exc:
        _write_error(path_factory, task.user, source, f"processing failed\n\n{exc!r}")
    finally:
        for path in temp_files:
            try:
                if path.exists():
                    path.unlink()
            except OSError:
                _log.warning("could not remove temp file %s", path)


class PdfProcessor:
    """Owns the worker pool and the filesystem observer."""

    def __init__(self, path_factory: PathFactory, ocr: OcrConfig, workers: int = 2):
        self._path_factory = path_factory
        self._ocr = ocr
        self._context = multiprocessing.get_context("spawn")
        self._pool = self._context.Pool(processes=workers, maxtasksperchild=10)
        self._observer = Observer()

    def process(self, file: str | Path) -> None:
        """Route an uploaded file into the processing pipeline."""
        file = Path(file)

        if file.suffix.lower() != ".pdf":
            user = self._safe_user(file)
            _log.error("Unrecognized file (not a PDF): %s", file.name)
            if user:
                _write_error(
                    self._path_factory,
                    user,
                    file,
                    "not a PDF file; only .pdf uploads are processed",
                )
            return

        user = self._safe_user(file)
        if user is None:
            _log.error("File %s is not inside the base directory", file)
            return
        mode = self._route(file, user)
        if mode is None:
            _log.error("No known input dir for %s", file)
            _write_error(self._path_factory, user, file, "uploaded into an unknown directory")
            return

        _log.info("process file %s for user %s (mode=%s)", file, user, mode.value)
        task = Task(
            file=file,
            user=user,
            base_path=self._path_factory.base_path,
            mode=mode,
            ocr=self._ocr,
        )
        self._pool.apply_async(
            process_file_task,
            args=(task,),
            error_callback=lambda ex: _log.exception("worker crashed for %s: %s", file, ex),
        )

    def _safe_user(self, file: Path) -> str | None:
        try:
            return self._path_factory.get_user(file)
        except (ValueError, IndexError):
            return None

    def _route(self, file: Path, user: str) -> Mode | None:
        return route(file, user, self._path_factory)

    def make_handler(
        self,
        authorizer,
        passv_range: str | None,
        passv_host: str | None,
        certfile: Path | str,
        keyfile: Path | str,
        hostname: str | None = None,
        tls_control_required: bool = False,
        tls_data_required: bool = False,
    ) -> type[TLS_FTPHandler]:
        outer_self = self

        class OcrFtpHandler(TLS_FTPHandler):
            def on_file_received(self, file: str) -> None:
                outer_self.process(file)

            def log(self, msg, logfun=_ftpd_logger.info) -> None:
                if (
                    msg in _SESSION_LOG_LINES
                    and not self.authenticated
                    and self.remote_ip in _LOOPBACK_ADDRESSES
                ):
                    logfun = _ftpd_logger.debug
                super().log(msg, logfun=logfun)

        OcrFtpHandler.authorizer = authorizer

        cert_hostname = hostname or passv_host or "localhost"
        cert, key = ensure_cert(cert_hostname, keyfile, certfile)
        OcrFtpHandler.certfile = str(cert)
        OcrFtpHandler.keyfile = str(key)

        if passv_range:
            start, end = passv_range.split("-", maxsplit=1)
            OcrFtpHandler.passive_ports = range(int(start), int(end) + 1)

        if passv_host:
            OcrFtpHandler.masquerade_address = passv_host

        OcrFtpHandler.tls_control_required = tls_control_required
        OcrFtpHandler.tls_data_required = tls_data_required

        return OcrFtpHandler

    def make_observer(self, user_manager) -> None:
        for entry in user_manager.users():
            self._observer.schedule(
                ObserveHandler(self),
                str(self._path_factory.observed(entry.username)),
                recursive=True,
            )
        self._observer.start()

    def shutdown(self) -> None:
        """Stop the observer and the worker pool gracefully."""
        try:
            self._observer.stop()
            self._observer.join(timeout=5)
        except Exception:
            _log.exception("stopping observer failed")
        self._pool.close()
        self._pool.join()


class ObserveHandler(FileSystemEventHandler):
    """Watches the ``observed`` directory so files dropped in (not via FTP)
    are processed too. Waits until a file stops changing before acting."""

    def __init__(self, processor: PdfProcessor, settle_seconds: float = 1.0):
        super().__init__()
        self._processor = processor
        self._settle_seconds = settle_seconds

    def do_process(self, filename: str | Path) -> None:
        filename = str(filename)
        # Ignore our own temp files and anything that is not a PDF.
        if ".ftp2ocr-" in filename or not filename.lower().endswith(".pdf"):
            _log.info("Ignore observed file %s", filename)
            return
        threading.Thread(target=self._process_when_stable, args=(filename,), daemon=True).start()

    def _process_when_stable(self, filename: str) -> None:
        try:
            wait_for_stable(filename, interval=self._settle_seconds)
        except FileNotFoundError:
            return  # file vanished
        except StabilizationTimeoutError:
            _log.warning("observed file %s did not stabilize in time", filename)
            return
        self._processor.process(filename)

    def on_created(self, event) -> None:
        if isinstance(event, FileCreatedEvent):
            self.do_process(event.src_path)

    def on_moved(self, event) -> None:
        if isinstance(event, FileMovedEvent):
            self.do_process(event.dest_path)
