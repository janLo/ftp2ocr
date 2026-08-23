"""OCR and PDF processing primitives.

The heavy lifting is delegated to :mod:`ocrmypdf` (Python API, not a
subprocess) and :mod:`pikepdf`. Duplex reordering interleaves the two halves
of a scan so that a scanner that emits odd pages front-to-back and even pages
back-to-front ends up in reading order.
"""

from __future__ import annotations

import logging
import math
import shutil
from dataclasses import dataclass
from pathlib import Path

import pikepdf

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class OcrConfig:
    """Settings for the OCR run."""

    language: str = "deu"
    timeout: int = 300
    optimize: int = 3
    rotate_pages: bool = True
    deskew: bool = True
    clean: bool = True
    jobs: int | None = None


def reorder_duplex(input_file: Path | str, output_file: Path | str) -> None:
    """Re-order interleaved duplex pages into reading order."""
    with pikepdf.open(input_file) as pdf:
        count = len(pdf.pages)
        half = math.ceil(count / 2)

        order: list[int] = []
        for idx in range(half):
            order.append(idx)
            if idx + half < count:
                order.append(count - idx - 1)

        reordered = [pdf.pages[i] for i in order]
        for idx, page in enumerate(reordered):
            pdf.pages[idx] = page

        pdf.remove_unreferenced_resources()
        pdf.save(output_file)


def run_ocr(input_file: Path | str, output_file: Path | str, config: OcrConfig) -> None:
    """Run OCR over *input_file* and write the result to *output_file*."""
    import ocrmypdf

    _log.info("OCR %s -> %s (lang=%s)", input_file, output_file, config.language)
    ocrmypdf.ocr(
        str(input_file),
        str(output_file),
        language=config.language,
        rotate_pages=config.rotate_pages,
        deskew=config.deskew,
        clean=config.clean,
        optimize=config.optimize,
        tesseract_timeout=config.timeout,
        jobs=config.jobs,
        progress_bar=False,
    )


def copy_file(source: Path | str, destination: Path | str) -> None:
    """Copy *source* to *destination*, creating parent directories."""
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
