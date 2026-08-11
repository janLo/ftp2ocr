# Upgrading

This page lists every **breaking change** and how to migrate. The jump from v1 to v2 is
the big one; it modernises packaging, fixes long-standing bugs, and changes a few
behaviours deliberately.

!!! note "No ownership change"

    The container **still runs as `www-data` (UID 33)**. Your Nextcloud-side permissions
    keep working; there is no `chown` migration step.

## v1 → v2

### 1. `-r` is the PASV range only; host moved to `-H`

In v1 the short option `-r` was registered twice (range *and* host), which broke both.
`-r` now means the PASV **range**; the PASV host is `-H`/`--passv-host`.

**Migrate:** replace `-r <host>` with `-H <host>` in your run command, and set the range
with `-r <from>-<to>` (or `FTP2OCR_PASSV_RANGE`).

### 2. Collisions get a timestamp instead of overwriting

If `processed/`, `backup/`, or `error/` already contains a file with the same name, the
new file is written with a timestamp suffix instead of silently overwriting the old one.

**Migrate:** nothing required. Just be aware that downstream consumers (e.g. Nextcloud)
may see `name_<timestamp>.pdf` for duplicates.

### 3. Non-PDF uploads move to `error/`

Previously, non-PDF files were only logged and left in the input directory forever. They
are now moved to `error/` with an explanation.

**Migrate:** clean up any leftover non-PDF files from the input directories once after
upgrading.

### 4. `observed/` waits for files to settle

Files dropped into `observed/` are only processed after their size stops changing, so a
half-written file is no longer OCR'd prematurely. This adds a small, intentional delay.

**Migrate:** nothing required — this is a correctness fix.

### 5. `mkpasswd` emits PBKDF2 hashes

`ftp2ocr mkpasswd` now produces `pbkdf2_sha256$…` hashes. Old `crypt(3)` hashes are still
**verified**, but a new-format hash cannot be read by a v1 installation.

**Migrate:** back up your `users.txt` before regenerating hashes, in case you need to roll
back. Existing files keep working untouched.

### 6. OCR engine switches to PyPI ocrmypdf 17.x

v1 used the (older) Debian-packaged `ocrmypdf` invoked as a subprocess. v2 uses the PyPI
`ocrmypdf` 17.x **Python API** with the same settings.

**Migrate:** nothing functional. OCR output may differ slightly between engine versions.

!!! warning "`--jbig2-lossy` removed"

    ocrmypdf 17 removed lossy JBIG2 (character-substitution risk), so the former
    `--jbig2-lossy` flag is gone and is no longer passed. Lossless optimisation still
    applies via `--optimize 3`.

### 7. Certificates: `ca=False` for fresh self-signed certs

Freshly generated self-signed certificates now use `BasicConstraints ca=False`. Existing
certificate/key files are kept untouched, and you can mount your own.

**Migrate:** nothing required unless you pinned the old generated cert; then mount your
own via `--certfile`/`--keyfile` (or `FTP2OCR_CERTFILE`/`FTP2OCR_KEYFILE`).

### 8. jemalloc kept, made arch-agnostic and optional

The jemalloc preload is **kept** (it helps long-running Python) but the hard-coded
x86_64 `LD_PRELOAD` path is now detected at runtime, so it also works on arm64. Set
`FTP2OCR_JEMALLOC=0` to disable.

**Migrate:** nothing required — behaviour is preserved; the env var only exists if you
want to turn it off.

## Behaviour summary table

| # | Change | Migration |
| - | ------ | --------- |
| 1 | `-r` = PASV range only; host → `-H`/`--passv-host` | Use `-H <host>` for the host. |
| 2 | Collisions get a timestamp suffix | None (avoid silent overwrites). |
| 3 | Non-PDF uploads go to `error/` | Clean up old leftovers once. |
| 4 | `observed/` waits for files to settle | None (correctness fix). |
| 5 | `mkpasswd` emits PBKDF2 hashes | Back up `users.txt` first. |
| 6 | PyPI ocrmypdf 17.x (Python API); `--jbig2-lossy` dropped | None functional. |
| 7 | Fresh certs use `ca=False` | Mount your own if pinned. |
| 8 | jemalloc kept, arch-agnostic, `FTP2OCR_JEMALLOC` opt-out | None. |

## Rolling back

v2 reads v1 user files (legacy hashes are verified), so configuration files are
forward-compatible. However, PBKDF2 hashes written by `mkpasswd` on v2 are not understood
by v1 — keep a backup of `users.txt` if you may roll back.
