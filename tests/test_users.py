"""Tests for user management and password hashing."""

from pathlib import Path

import pytest

from ftp2ocr.paths import PathFactory
from ftp2ocr.users import (
    UserEntry,
    UserManager,
    hash_password,
    read_user_list,
    verify_password,
)


def test_hash_password_roundtrip() -> None:
    stored = hash_password("s3cret")
    assert stored.startswith("pbkdf2_sha256$")
    assert verify_password("s3cret", stored)
    assert not verify_password("wrong", stored)


def test_hash_password_unique_salt() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_pbkdf2_malformed() -> None:
    assert not verify_password("x", "pbkdf2_sha256$not-a-number$a$b")
    assert not verify_password("x", "pbkdf2_sha256$only$three")


def test_verify_legacy_crypt_hash() -> None:
    """Pre-v2 crypt(3) hashes must keep working (migration path)."""
    pytest.importorskip("legacycrypt")
    import legacycrypt as crypt

    stored = crypt.crypt("oldpassword", crypt.mksalt(crypt.METHOD_MD5))
    assert not stored.startswith("pbkdf2_sha256$")
    assert verify_password("oldpassword", stored)
    assert not verify_password("wrong", stored)


def test_user_manager_accepts_legacy_hash(tmp_path: Path) -> None:
    pytest.importorskip("legacycrypt")
    import legacycrypt as crypt
    from pyftpdlib.authorizers import AuthenticationFailed

    factory = PathFactory(tmp_path)
    stored = crypt.crypt("legacy", crypt.mksalt(crypt.METHOD_MD5))
    manager = UserManager(factory, [UserEntry("old_user", stored)])

    manager.validate_authentication("old_user", "legacy", None)
    with pytest.raises(AuthenticationFailed):
        manager.validate_authentication("old_user", "nope", None)


def test_read_user_list(tmp_path: Path) -> None:
    user_file = tmp_path / "users.txt"
    user_file.write_text(
        "[default]\nalice: pbkdf2_sha256$1$x$y\nbob: pbkdf2_sha256$1$a$b\n",
        encoding="utf-8",
    )
    users = read_user_list(user_file)
    assert [u.username for u in users] == ["alice", "bob"]
    assert all(isinstance(u, UserEntry) for u in users)


def test_user_manager_creates_dirs_and_auth(tmp_path: Path) -> None:
    factory = PathFactory(tmp_path)
    stored = hash_password("topsecret")
    manager = UserManager(factory, [UserEntry("alice", stored)])

    # Directory tree exists.
    assert factory.home("alice").is_dir()
    assert factory.processed("alice").is_dir()

    # Correct password passes, wrong raises.
    from pyftpdlib.authorizers import AuthenticationFailed

    manager.validate_authentication("alice", "topsecret", None)
    with pytest.raises(AuthenticationFailed):
        manager.validate_authentication("alice", "nope", None)
    with pytest.raises(AuthenticationFailed):
        manager.validate_authentication("ghost", "whatever", None)


def test_user_manager_users_returns_list(tmp_path: Path) -> None:
    factory = PathFactory(tmp_path)
    stored = hash_password("pw")
    manager = UserManager(factory, [UserEntry("u1", stored), UserEntry("u2", stored)])
    users = manager.users()
    assert isinstance(users, list)
    assert len(users) == 2


def test_user_manager_grants_write_to_input_dirs(tmp_path: Path) -> None:
    factory = PathFactory(tmp_path)
    stored = hash_password("pw")
    manager = UserManager(factory, [UserEntry("alice", stored)])

    for path in (
        factory.new_raw("alice"),
        factory.new_duplex("alice"),
        factory.new_simplex("alice"),
        factory.observed("alice"),
    ):
        assert manager.has_perm("alice", "w", str(path))
    # backup/processed/error are not writable.
    assert not manager.has_perm("alice", "w", str(factory.backup("alice")))
