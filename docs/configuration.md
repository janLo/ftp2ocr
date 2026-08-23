# Configuration

Every `serve` option can be given on the command line **or** through an `FTP2OCR_*`
environment variable. Environment variables are the preferred way to configure the
container.

## Option reference

| Option | Env var | Default | Description |
| ------ | ------- | ------- | ----------- |
| `-d`, `--base-dir` | `FTP2OCR_BASE_DIR` | `/data` (container) | Base directory for the per-user data directories. |
| `-u`, `--user-list` | `FTP2OCR_USER_LIST` | `/data/users.txt` (container) | Path to the user list file. |
| `-p`, `--port` | `FTP2OCR_PORT` | `21` | FTP control port to listen on. |
| `-H`, `--passv-host` | `FTP2OCR_PASSV_HOST` | – | Public hostname/address announced for PASV connections (NAT). |
| `-r`, `--passv-range` | `FTP2OCR_PASSV_RANGE` | – | PASV port range, e.g. `60000-60100`. |
| `-c`, `--certfile` | `FTP2OCR_CERTFILE` | `cert.pem` | TLS certificate (relative paths resolve against `--base-dir`). |
| `-k`, `--keyfile` | `FTP2OCR_KEYFILE` | `key.pem` | TLS private key (relative paths resolve against `--base-dir`). |
| `--hostname` | `FTP2OCR_HOSTNAME` | see below | Common name for generated self-signed certificates. |
| `--workers` | `FTP2OCR_WORKERS` | `2` | Number of parallel OCR worker processes. |
| `--ocr-timeout` | `FTP2OCR_OCR_TIMEOUT` | `300` | Per-page OCR engine timeout in seconds. |
| `--ocr-language` | `FTP2OCR_OCR_LANGUAGE` | `deu` | Tesseract language for OCR. |
| `--ocr-jobs` | `FTP2OCR_OCR_JOBS` | – (ocrmypdf's own CPU-based default) | Concurrent OCR jobs per file. `ocrmypdf` defaults to the host's CPU count, which is not cgroup-aware and can oversubscribe a constrained container when combined with `--workers`; set this explicitly to cap it. |
| `--tls-control-required` | `FTP2OCR_TLS_CONTROL_REQUIRED` | off | Require TLS on the control channel. |
| `--tls-data-required` | `FTP2OCR_TLS_DATA_REQUIRED` | off | Require TLS on data connections. |
| `--verbose` | `FTP2OCR_VERBOSE` | off | Enable debug logging. |

The `--hostname` used for a freshly generated certificate defaults to `--passv-host`
when set, otherwise `localhost`.

!!! note "The old `-r` bug is fixed"

    In v1 the short option `-r` was registered twice (for both the PASV range and the
    PASV host), which made them unusable. `-r` now means **range** only; the host moved
    to `-H`/`--passv-host`.

## Environment-only variables

| Env var | Default | Description |
| ------- | ------- | ----------- |
| `FTP2OCR_JEMALLOC` | `1` | Preload jemalloc into the process. Set `0` to disable. |

## User list

The user list is an INI-style file with a single `[default]` section. Each line maps a
username to a password hash:

```ini
[default]
alice: pbkdf2_sha256$600000$AbC123...
bob: pbkdf2_sha256$600000$XyZ789...
```

If the file does not exist, ftp2ocr creates an empty one (and logs a warning that no
user can log in yet).

### Generating hashes

Use the `mkpasswd` subcommand. It prompts for a password twice (hidden input) and prints
the hash:

```bash
ftp2ocr mkpasswd
```

You can tune the PBKDF2 iteration count with `--iterations` if you need to.

### Legacy hashes

Hashes that do not start with `pbkdf2_sha256$` are treated as classic `crypt(3)` hashes
and verified through the optional `legacycrypt` package. This keeps pre-v2 user files
working. Newly generated hashes always use PBKDF2.

## TLS

ftp2ocr always offers TLS (FTPS) via `AUTH TLS`. By default TLS is **advertised but not
required**, matching the scanner's typical behaviour.

- If `--certfile`/`--keyfile` already exist, they are used as-is — mount your own
  certificates to control them fully.
- Otherwise ftp2ocr generates a self-signed certificate (valid ~10 years) and stores it
  next to the data. The private key is written with `0600` permissions.
- `--tls-control-required` and `--tls-data-required` turn TLS from optional into
  mandatory. Leave them off unless you know your scanner negotiates TLS.

!!! info "What self-signed certs actually do"

    A self-signed certificate only encrypts when the client negotiates TLS (`AUTH TLS`).
    It provides encryption, **not** authentication — scanners generally do not validate
    certificates anyway. If the scanner uploads plain FTP, the certificate is never used.

## Example: fully-configured container

```yaml
services:
  ftp2ocr:
    image: janlo/pdf2ocr:latest
    restart: unless-stopped
    ports:
      - "21:21"
      - "60000-60100:60000-60100"
    environment:
      FTP2OCR_PASSV_RANGE: "60000-60100"
      FTP2OCR_PASSV_HOST: "scanner.example.com"
      FTP2OCR_OCR_LANGUAGE: "deu"
      FTP2OCR_WORKERS: "4"
      FTP2OCR_OCR_TIMEOUT: "600"
      FTP2OCR_VERBOSE: "0"
    volumes:
      - /srv/ftp2ocr:/data
```
