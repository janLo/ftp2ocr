"""CLI smoke tests."""

from pathlib import Path

from click.testing import CliRunner

from ftp2ocr import __version__
from ftp2ocr.cli import main
from ftp2ocr.users import verify_password


def test_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_top_level_help_lists_commands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    for command in ("serve", "mkpasswd", "healthcheck"):
        assert command in result.output


def test_serve_help_has_no_duplicate_short_options() -> None:
    result = CliRunner().invoke(main, ["serve", "--help"])
    assert result.exit_code == 0
    # -r is the PASV range only; -H is the PASV host. The old duplicate -r bug is gone.
    assert "--passv-range" in result.output
    assert "--passv-host" in result.output
    assert result.output.count("-r,") == 1
    assert result.output.count("-H,") == 1


def test_mkpasswd_roundtrip() -> None:
    result = CliRunner().invoke(main, ["mkpasswd"], input="secret1\nsecret1\n")
    assert result.exit_code == 0
    hashed = result.output.strip().splitlines()[-1]
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password("secret1", hashed)


def test_mkpasswd_mismatch_fails() -> None:
    result = CliRunner().invoke(main, ["mkpasswd"], input="secret1\nother\n")
    assert result.exit_code != 0


def test_healthcheck_fails_without_server() -> None:
    result = CliRunner().invoke(main, ["healthcheck", "--port", "1", "--timeout", "1"])
    assert result.exit_code == 1


def test_serve_creates_empty_user_list(tmp_path: Path) -> None:
    """serve bails out when the user list file is missing instead of crashing."""
    runner = CliRunner()
    user_list = tmp_path / "users.txt"
    # Invoke with a free port; serve would block forever, so we only check that
    # the user list gets created before that by using a broken --base-dir path
    # pointing at a file (forces an early error after user list creation).
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    result = runner.invoke(
        main,
        [
            "serve",
            "-d",
            str(blocker / "nested"),  # fails: blocker is a file
            "-u",
            str(user_list),
            "-p",
            "0",
        ],
        catch_exceptions=True,
    )
    assert result.exit_code != 0
    assert user_list.exists()
    assert "[default]" in user_list.read_text()
