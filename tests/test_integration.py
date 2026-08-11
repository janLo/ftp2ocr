"""End-to-end OCR tests.

These need the real OCR toolchain (tesseract, ghostscript, …) and are
skipped when it is missing. CI runs them inside the container image.
"""

import shutil
from pathlib import Path

import pytest

from ftp2ocr.ocr import OcrConfig, run_ocr

HAS_TESSERACT = shutil.which("tesseract") is not None

pytestmark = pytest.mark.integration


@pytest.fixture
def skip_without_toolchain() -> None:
    if not HAS_TESSERACT:
        pytest.skip("tesseract not available")


def _make_scanned_pdf(path: Path, text: str = "Hallo Welt") -> Path:
    """Render *text* into an image and wrap it into a PDF (like a scan)."""
    from img2pdf import convert
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (800, 200), "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default(size=64)
    except TypeError:  # very old Pillow
        font = ImageFont.load_default()
    draw.text((40, 60), text, fill="black", font=font)

    png_path = path.with_suffix(".png")
    img.save(png_path, dpi=(150, 150))
    path.write_bytes(convert(str(png_path)))
    return path


def _extract_text(path: Path) -> str:
    from pdfminer.high_level import extract_text

    return extract_text(str(path))


@pytest.mark.skipif(not HAS_TESSERACT, reason="tesseract not available")
def test_ocr_adds_text_layer(tmp_path: Path, skip_without_toolchain) -> None:
    source = _make_scanned_pdf(tmp_path / "scan.pdf")
    output = tmp_path / "ocr.pdf"

    run_ocr(source, output, OcrConfig(language="deu"))

    assert output.exists()
    extracted = _extract_text(output)
    assert "Hallo" in extracted


@pytest.mark.skipif(not HAS_TESSERACT, reason="tesseract not available")
def test_full_duplex_task(tmp_path: Path, skip_without_toolchain) -> None:
    from ftp2ocr.paths import PathFactory
    from ftp2ocr.pipeline import Mode, Task, process_file_task

    factory = PathFactory(tmp_path)
    factory.ensure_user_dirs("alice")

    # Two "scanned" pages, as produced by a duplex scanner.
    from img2pdf import convert
    from PIL import Image

    pngs = []
    for i in range(2):
        img = Image.new("RGB", (400, 200), "white")
        png = tmp_path / f"page{i}.png"
        img.save(png, dpi=(150, 150))
        pngs.append(str(png))

    source = factory.new_duplex("alice") / "duplex.pdf"
    source.write_bytes(convert(pngs))

    task = Task(source, "alice", factory.base_path, Mode.DUPLEX, OcrConfig(language="deu"))
    process_file_task(task)

    processed = factory.processed("alice") / "duplex.pdf"
    assert processed.exists()
    assert not source.exists()  # original moved to backup
    assert (factory.backup("alice") / "duplex.pdf").exists()

    import pikepdf

    with pikepdf.open(processed) as pdf:
        assert len(pdf.pages) == 2
