"""Tests for the OCR module (duplex reorder; OCR itself is integration-only)."""

from pathlib import Path

import pytest

from ftp2ocr.ocr import OcrConfig, reorder_duplex
from tests.conftest import make_pdf, page_markers


@pytest.mark.parametrize(
    ("pages", "expected"),
    [
        (1, [0]),
        (2, [0, 1]),
        (3, [0, 2, 1]),
        (4, [0, 3, 1, 2]),
        (5, [0, 4, 1, 3, 2]),
        (6, [0, 5, 1, 4, 2, 3]),
    ],
)
def test_reorder_duplex(tmp_path: Path, pages: int, expected: list[int]) -> None:
    source = make_pdf(tmp_path / "in.pdf", pages)
    output = tmp_path / "out.pdf"

    reorder_duplex(source, output)

    assert page_markers(output) == [f"P{i}" for i in expected]


def test_reorder_keeps_page_count(tmp_path: Path) -> None:
    source = make_pdf(tmp_path / "in.pdf", 7)
    output = tmp_path / "out.pdf"
    reorder_duplex(source, output)
    assert len(page_markers(output)) == 7


def test_ocr_config_defaults() -> None:
    config = OcrConfig()
    assert config.language == "deu"
    assert config.timeout == 300
    assert config.optimize == 3
    assert config.rotate_pages
    assert config.deskew
    assert config.clean
