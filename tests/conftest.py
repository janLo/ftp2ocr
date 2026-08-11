"""Shared test fixtures."""

from pathlib import Path

import pikepdf
import pytest


def make_pdf(path: Path, pages: int) -> Path:
    """Create a minimal PDF where page *i* carries a ``/Marker`` of ``/P<i>``."""
    pdf = pikepdf.Pdf.new()
    for i in range(pages):
        page = pikepdf.Dictionary(
            Type=pikepdf.Name("/Page"),
            MediaBox=[0, 0, 10, 10],
            Resources=pikepdf.Dictionary(),
            Contents=pikepdf.Stream(pdf, b""),
        )
        page[pikepdf.Name("/Marker")] = pikepdf.Name(f"/P{i}")
        pdf.pages.append(pikepdf.Page(page))
    pdf.save(path)
    pdf.close()
    return path


def page_markers(path: Path) -> list[str]:
    """Read back the ``/Marker`` names in page order."""
    with pikepdf.open(path) as pdf:
        return [str(page["/Marker"]).lstrip("/") for page in pdf.pages]


@pytest.fixture
def pdf_factory():
    return make_pdf
