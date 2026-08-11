"""Tests for the data directory layout helpers."""

from pathlib import Path

import pytest

from ftp2ocr.paths import PathFactory, is_subpath


@pytest.fixture
def factory(tmp_path: Path) -> PathFactory:
    return PathFactory(tmp_path)


def test_home(factory: PathFactory, tmp_path: Path) -> None:
    assert factory.home("alice") == tmp_path / "alice"


def test_all_subdirs(factory: PathFactory) -> None:
    names = {
        "new_raw": factory.new_raw("u"),
        "new_simplex": factory.new_simplex("u"),
        "new_duplex": factory.new_duplex("u"),
        "backup": factory.backup("u"),
        "error": factory.error("u"),
        "processed": factory.processed("u"),
        "observed": factory.observed("u"),
    }
    for name, path in names.items():
        assert path.name == name
        assert path.parent.name == "u"


def test_iter_paths_yields_home_first(factory: PathFactory) -> None:
    paths = list(factory.iter_paths("bob"))
    assert paths[0] == factory.home("bob")
    assert len(paths) == 8


def test_get_user(factory: PathFactory) -> None:
    file = factory.new_simplex("carol") / "scan.pdf"
    assert factory.get_user(file) == "carol"


def test_is_subpath_true(factory: PathFactory) -> None:
    dir_ = factory.new_duplex("dave")
    file = dir_ / "a.pdf"
    assert is_subpath(file, dir_)


def test_is_subpath_false_outside(factory: PathFactory) -> None:
    assert not is_subpath(factory.new_raw("a"), factory.new_duplex("a"))
    assert not is_subpath(factory.home("a"), factory.new_duplex("a"))


def test_is_subpath_equal_is_not_subpath(factory: PathFactory) -> None:
    dir_ = factory.observed("erin")
    assert not is_subpath(dir_, dir_)


def test_contains(factory: PathFactory) -> None:
    home = factory.home("frank")
    assert factory.contains(home / "new_simplex" / "x.pdf", "frank")
    assert not factory.contains(factory.home("other") / "x.pdf", "frank")


def test_ensure_user_dirs(factory: PathFactory) -> None:
    factory.ensure_user_dirs("gina")
    for path in factory.iter_paths("gina"):
        assert path.is_dir()
