# Usage

This page explains how to point a scanner at ftp2ocr and which folder to use for what.

## Configure a Kyocera (address book)

The exact menu varies by model, but the flow on a Kyocera MFP is typically:

1. Open **Address Book / Send Function** and add a new destination.
2. Choose **FTP** (or **FTP over SSL/TLS** if you enabled TLS enforcement).
3. Fill in:
   - **Host name** — the server address (and the value you gave `FTP2OCR_PASSV_HOST`).
   - **Port** — `21` (or your custom `FTP2OCR_PORT`).
   - **Login user name** and **password** — a user from your `users.txt`.
   - **File format** — PDF.
4. Set the **path / folder** to one of the input directories below, e.g. `new_simplex`.
5. Save and send a test scan.

!!! tip "Which folder should I use?"

    - **Single-sided documents** → `new_simplex`.
    - **Double-sided documents** that come out as "all fronts, then all backs" →
      `new_duplex` (ftp2ocr interleaves them back into reading order first).
    - **Already-searchable PDFs** you just want forwarded → `new_raw` (no OCR).
    - `observed` behaves like `new_simplex` but also picks up files dropped onto the
      filesystem by other means.

## What happens after upload

1. The file is routed by its folder (see above).
2. For duplex, pages are re-ordered; then OCR runs (unless `new_raw`).
3. The **searchable result** is written to the user's `processed/` folder.
4. The **original upload** is moved to `backup/`.
5. If anything fails, the file is moved to `error/` together with a
   `*.error.txt` explaining what went wrong.

The scanner can keep scanning while OCR runs — uploads are handed off to a worker pool
and do not block the FTP session.

## Pointing Nextcloud at the results

Mount or sync the user's `processed/` directory into Nextcloud. For example, with the
Nextcloud "External storage" local backend, add:

```
/data/alice/processed
```

Because the files are written by UID 33 (`www-data`), make sure Nextcloud can read that
directory. Nothing else needs to be shared — `backup/` and `error/` are internal.

## Filename collisions

If two uploads produce the same file name, ftp2ocr keeps **both**: the newer one gets a
timestamp suffix (e.g. `scan.20260812-091500.pdf`) instead of overwriting the existing
file. This applies to `processed/`, `backup/`, and `error/`.

## Non-PDF uploads

Only `.pdf` files are processed. Anything else uploaded into an input folder is moved to
`error/` with a note, so it does not silently pile up.
