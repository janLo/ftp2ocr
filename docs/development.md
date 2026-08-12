# Development

This project is managed with [uv](https://docs.astral.sh/uv/). Everything — local
development, tests, CI, and the Docker image — installs dependencies from the committed
`uv.lock`, so builds are reproducible.

## Setup

Requires Python 3.12+ (3.14 in `.python-version`) and `uv`.

```bash
git clone https://github.com/janlo/ftp2ocr
cd ftp2ocr
uv sync          # creates .venv and installs deps (incl. dev group)
```

## Running locally

```bash
uv run ftp2ocr serve \
  --base-dir ./data \
  --user-list ./users.txt \
  --port 2121
```

Generate a password hash first with `uv run ftp2ocr mkpasswd` and add it to `users.txt`.

!!! note "OCR needs the system toolchain"

    The OCR path needs Tesseract, Ghostscript, unpaper and pngquant installed on
    the host. `jbig2` is optional (it enables JBIG2 image recompression; ocrmypdf
    skips it when missing — and Ubuntu does not package it at all). Without the
    toolchain, unit tests still run (OCR tests are skipped), but real OCR
    requires it — easiest via the Docker image.

## Tests

```bash
uv run pytest                 # unit tests (fast, no OCR)
uv run pytest -m integration  # OCR round-trip (needs the toolchain)
```

Integration tests are marked with `@pytest.mark.integration` and are excluded from the
default run so the suite stays fast and dependency-light.

## Lint & format

```bash
uv run ruff check src tests
uv run ruff format --check src tests
```

## Building the image

```bash
docker build -t ftp2ocr:local .
docker run --rm ftp2ocr:local ftp2ocr --help
```

## Project layout

```
src/ftp2ocr/
  cli.py        # click commands: serve, mkpasswd, healthcheck
  pipeline.py   # routing, worker pool, FTP handler, observer
  ocr.py        # run_ocr + reorder_duplex
  users.py      # user list, hashing, authorizer
  paths.py      # directory layout
  certs.py      # self-signed TLS certs
  stability.py  # wait-for-file-to-settle helper
tests/          # pytest suite (unit + integration)
docker/         # entrypoint.sh (jemalloc preload)
```

## CI

- **`ci.yml`** — runs ruff + pytest, then builds and pushes the Docker image.
- **`docs.yml`** — builds this documentation and publishes it to GitHub Pages.
