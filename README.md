# ftp2ocr

**ftp2ocr** is a small FTP(S) server that receives PDF scans from network scanners (e.g.
Kyocera multifunction printers), runs OCR on them, and drops the searchable results where
a tool like [Nextcloud](https://nextcloud.com/) can pick them up.

Which folder a scan is uploaded into decides what happens:

| Folder        | Behaviour                                   |
| ------------- | ------------------------------------------- |
| `new_simplex` | OCR single-sided scans.                     |
| `new_duplex`  | Re-order duplex pages, then OCR.            |
| `new_raw`     | Pass through without OCR.                   |
| `observed`    | OCR; also watches the filesystem for drops. |

Results land in each user's `processed/` folder; originals go to `backup/`, failures to
`error/`.

## Quick start

```bash
# 1. Create a password hash
docker run --rm -it janlo/pdf2ocr:latest ftp2ocr mkpasswd

# 2. Put it into users.txt
#    [default]
#    alice: pbkdf2_sha256$600000$...

# 3. Run
docker run -d \
  --publish 21:21 --publish 60000-60100:60000-60100 \
  --volume /srv/ftp2ocr:/data \
  janlo/pdf2ocr:latest
```

## Documentation

Full documentation is built with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)
and published to **<https://janlo.github.io/ftp2ocr/>**:

- [Installation](https://janlo.github.io/ftp2ocr/installation/)
- [Configuration](https://janlo.github.io/ftp2ocr/configuration/)
- [Usage](https://janlo.github.io/ftp2ocr/usage/)
- [Upgrading (v1 → v2 breaking changes)](https://janlo.github.io/ftp2ocr/upgrading/)

To build the docs locally: `uv run mkdocs serve`.

## Development

The project is managed with [`uv`](https://docs.astral.sh/uv/). See the
[development docs](https://janlo.github.io/ftp2ocr/development/).

```bash
uv sync          # install dependencies
uv run pytest    # run tests
uv run ruff check src tests
```

## License

MIT — see [LICENSE](LICENSE).
