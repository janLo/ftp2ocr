# syntax=docker/dockerfile:1

FROM python:3.14-slim

# --- uv (dependency manager) -------------------------------------------------
# Copied from the official image; the lockfile controls exact versions, so the
# uv binary itself only needs to be recent.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# --- System OCR toolchain ----------------------------------------------------
# ghostscript, tesseract (+ German), unpaper, pngquant and jbig2 are required
# by ocrmypdf. libjemalloc2 is preloaded by the entrypoint for long-running
# Python processes (can be disabled with FTP2OCR_JEMALLOC=0).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ghostscript \
        jbig2 \
        libjemalloc2 \
        pngquant \
        tesseract-ocr \
        tesseract-ocr-deu \
        unpaper \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# --- Python dependencies (cached layer) -------------------------------------
# Install third-party deps first so code changes don't bust this layer.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# --- Install the project itself ---------------------------------------------
# Non-editable: code is copied into site-packages so the runtime does not rely
# on /app/src being readable by the unprivileged user.
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

ENV PATH="/app/.venv/bin:$PATH"

# --- Entrypoint (optional jemalloc preload) ---------------------------------
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# --- Data directory ----------------------------------------------------------
RUN mkdir -p /data && chown -R www-data:www-data /data

# Run as www-data (UID 33). This UID is intentional: the produced files are
# consumed by Nextcloud via a shared volume and must keep this ownership.
USER www-data
WORKDIR /data

EXPOSE 21

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["ftp2ocr", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["ftp2ocr", "serve", "--base-dir", "/data", "--user-list", "/data/users.txt", "--port", "21"]
