"""Data directory layout.

Each FTP user gets a home directory below the configured base directory.
The subdirectory a PDF is uploaded into decides what happens with it:

- ``new_simplex``: run OCR on single-sided scans
- ``new_duplex``:  re-order interleaved duplex scans, then run OCR
- ``new_raw``:     copy through without OCR
- ``observed``:    same as ``new_simplex``, but also watched on the filesystem

Results and state end up in ``processed`` (pickup for e.g. Nextcloud),
``backup`` (the uploaded originals) and ``error`` (failures + explanations).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path


def is_subpath(file_path: Path | str, dir_path: Path | str) -> bool:
    """Return ``True`` when *file_path* lies strictly inside *dir_path*."""
    try:
        rel = Path(os.path.normpath(file_path)).relative_to(Path(os.path.normpath(dir_path)))
    except ValueError:
        return False
    return not rel.is_absolute() and rel.parts != ()


class PathFactory:
    """Resolves the on-disk locations for one user's directory tree."""

    def __init__(self, base_path: Path | str):
        self._base_path = Path(base_path)

    @property
    def base_path(self) -> Path:
        return self._base_path

    def home(self, username: str) -> Path:
        return self._base_path / username

    def new_raw(self, username: str) -> Path:
        return self.home(username) / "new_raw"

    def new_simplex(self, username: str) -> Path:
        return self.home(username) / "new_simplex"

    def new_duplex(self, username: str) -> Path:
        return self.home(username) / "new_duplex"

    def backup(self, username: str) -> Path:
        return self.home(username) / "backup"

    def error(self, username: str) -> Path:
        return self.home(username) / "error"

    def processed(self, username: str) -> Path:
        return self.home(username) / "processed"

    def observed(self, username: str) -> Path:
        return self.home(username) / "observed"

    def iter_paths(self, username: str) -> Iterator[Path]:
        yield from (
            self.home(username),
            self.new_raw(username),
            self.new_simplex(username),
            self.new_duplex(username),
            self.backup(username),
            self.error(username),
            self.processed(username),
            self.observed(username),
        )

    def get_user(self, path: Path | str) -> str:
        """Return the username a *path* belongs to."""
        rel = Path(os.path.normpath(path)).relative_to(Path(os.path.normpath(self._base_path)))
        return rel.parts[0]

    def contains(self, path: Path | str, username: str) -> bool:
        """Return ``True`` when *path* is inside the user's home directory."""
        try:
            rel = Path(os.path.normpath(path)).relative_to(
                Path(os.path.normpath(self.home(username)))
            )
        except ValueError:
            return False
        return not rel.is_absolute()

    def ensure_user_dirs(self, username: str) -> None:
        for path in self.iter_paths(username):
            path.mkdir(parents=True, exist_ok=True)
