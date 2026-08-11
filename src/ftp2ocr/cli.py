"""Command line interface.

Subcommands:

- ``serve``       run the FTP server (what the container does)
- ``mkpasswd``    generate a password hash for the user list
- ``healthcheck`` probe the control port (used by the container HEALTHCHECK)

All options can also be provided via ``FTP2OCR_*`` environment variables,
which is the preferred way to configure the Docker container.
"""

from __future__ import annotations

import logging
import signal
import socket
import sys
from pathlib import Path

import click
from pyftpdlib.servers import FTPServer

from ftp2ocr import __version__
from ftp2ocr.ocr import OcrConfig
from ftp2ocr.paths import PathFactory
from ftp2ocr.pipeline import PdfProcessor
from ftp2ocr.users import UserManager, hash_password, read_user_list

_log = logging.getLogger(__name__)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="ftp2ocr")
def main() -> None:
    """ftp2ocr — FTPS server that OCRs PDF scans for pickup by Nextcloud."""


@main.command()
@click.option(
    "-d",
    "--base-dir",
    type=click.Path(file_okay=False),
    required=True,
    envvar="FTP2OCR_BASE_DIR",
    help="Base directory for the per-user data directories.",
)
@click.option(
    "-u",
    "--user-list",
    type=click.Path(dir_okay=False),
    required=True,
    envvar="FTP2OCR_USER_LIST",
    help="Path to the user list file ([default] section with user: hash pairs).",
)
@click.option(
    "-p",
    "--port",
    type=int,
    default=21,
    show_default=True,
    envvar="FTP2OCR_PORT",
    help="FTP port to listen on.",
)
@click.option(
    "-H",
    "--passv-host",
    default=None,
    envvar="FTP2OCR_PASSV_HOST",
    help="Public hostname announced for PASV connections (NAT/masquerade address).",
)
@click.option(
    "-r",
    "--passv-range",
    default=None,
    envvar="FTP2OCR_PASSV_RANGE",
    help="PASV port range, e.g. 60000-60100.",
)
@click.option(
    "-c",
    "--certfile",
    type=click.Path(dir_okay=False),
    default="cert.pem",
    show_default=True,
    envvar="FTP2OCR_CERTFILE",
    help="TLS certificate (relative paths resolve against --base-dir). "
    "An existing file is used as-is; otherwise a self-signed one is generated.",
)
@click.option(
    "-k",
    "--keyfile",
    type=click.Path(dir_okay=False),
    default="key.pem",
    show_default=True,
    envvar="FTP2OCR_KEYFILE",
    help="TLS private key (relative paths resolve against --base-dir).",
)
@click.option(
    "--hostname",
    default=None,
    envvar="FTP2OCR_HOSTNAME",
    help="Common name for generated self-signed certificates "
    "(defaults to --passv-host or 'localhost').",
)
@click.option(
    "--workers",
    type=int,
    default=2,
    show_default=True,
    envvar="FTP2OCR_WORKERS",
    help="Number of parallel OCR worker processes.",
)
@click.option(
    "--ocr-timeout",
    type=int,
    default=300,
    show_default=True,
    envvar="FTP2OCR_OCR_TIMEOUT",
    help="Per-page OCR engine timeout in seconds.",
)
@click.option(
    "--ocr-language",
    default="deu",
    show_default=True,
    envvar="FTP2OCR_OCR_LANGUAGE",
    help="Tesseract language for OCR.",
)
@click.option(
    "--tls-control-required",
    is_flag=True,
    default=False,
    envvar="FTP2OCR_TLS_CONTROL_REQUIRED",
    help="Require TLS on the control channel (AUTH TLS before login).",
)
@click.option(
    "--tls-data-required",
    is_flag=True,
    default=False,
    envvar="FTP2OCR_TLS_DATA_REQUIRED",
    help="Require TLS on data connections (PROT P).",
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    envvar="FTP2OCR_VERBOSE",
    help="Enable debug logging.",
)
def serve(
    base_dir: str,
    user_list: str,
    port: int,
    passv_host: str | None,
    passv_range: str | None,
    certfile: str,
    keyfile: str,
    hostname: str | None,
    workers: int,
    ocr_timeout: int,
    ocr_language: str,
    tls_control_required: bool,
    tls_data_required: bool,
    verbose: bool,
) -> None:
    """Run the FTP(S) server and the OCR pipeline."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    user_list_path = Path(user_list)
    _ensure_user_list(user_list_path)

    base_path = Path(base_dir)
    base_path.mkdir(parents=True, exist_ok=True)

    cert_path = _resolve_data_path(base_path, certfile)
    key_path = _resolve_data_path(base_path, keyfile)

    path_factory = PathFactory(base_path)
    user_manager = UserManager(path_factory, read_user_list(user_list_path))

    if not user_manager.users():
        _log.warning(
            "No users configured in %s — the server will not accept any login.", user_list_path
        )

    ocr = OcrConfig(language=ocr_language, timeout=ocr_timeout)
    processor = PdfProcessor(path_factory, ocr, workers=workers)

    handler = processor.make_handler(
        user_manager,
        passv_range,
        passv_host,
        cert_path,
        key_path,
        hostname=hostname,
        tls_control_required=tls_control_required,
        tls_data_required=tls_data_required,
    )
    processor.make_observer(user_manager)

    server = FTPServer(("", port), handler)
    cert_hostname = hostname or passv_host or "localhost"
    _log.info(
        "ftp2ocr %s listening on port %d (base dir: %s, TLS cert for %r, TLS enforced: "
        "control=%s data=%s)",
        __version__,
        port,
        base_path,
        cert_hostname,
        tls_control_required,
        tls_data_required,
    )

    def _shutdown(signum, _frame):
        _log.info("received signal %s, shutting down", signum)
        server.close_all()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever()
    finally:
        processor.shutdown()
        _log.info("shutdown complete")


@main.command()
@click.option(
    "--iterations",
    type=int,
    default=None,
    help="PBKDF2 iteration count (default: built-in secure default).",
)
def mkpasswd(iterations: int | None) -> None:
    """Generate a password hash for the user list file."""
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    kwargs = {"iterations": iterations} if iterations else {}
    click.echo(hash_password(password, **kwargs))


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to probe.")
@click.option(
    "--port",
    type=int,
    default=None,
    envvar="FTP2OCR_PORT",
    help="Port to probe (defaults to $FTP2OCR_PORT or 21).",
)
@click.option("--timeout", type=float, default=5.0, show_default=True, help="Probe timeout.")
def healthcheck(host: str, port: int | None, timeout: float) -> None:
    """Check that the FTP control port answers with a greeting."""
    port = port if port is not None else 21
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = sock.recv(1024)
    except OSError as exc:
        click.echo(f"healthcheck failed: {exc}", err=True)
        sys.exit(1)

    if not banner.startswith(b"2"):
        click.echo(f"healthcheck failed: unexpected banner {banner[:80]!r}", err=True)
        sys.exit(1)

    click.echo("ok")


def _resolve_data_path(base_path: Path, path: str) -> Path:
    """Resolve *path* against *base_path* when it is relative."""
    candidate = Path(path)
    return candidate if candidate.is_absolute() else base_path / candidate


def _ensure_user_list(user_list_path: Path) -> None:
    """Create an empty user list file when it does not exist yet."""
    if user_list_path.exists():
        return
    user_list_path.parent.mkdir(parents=True, exist_ok=True)
    user_list_path.write_text("[default]\n", encoding="utf-8")
    _log.warning("Created empty user list at %s — no users can log in yet.", user_list_path)


if __name__ == "__main__":
    main()
