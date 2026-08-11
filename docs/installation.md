# Installation

The recommended way to run ftp2ocr is the Docker image. It bundles the full OCR
toolchain (Tesseract, Ghostscript, unpaper, pngquant, jbig2) plus the Python
dependencies, so there is nothing to install on the host.

## Prerequisites

- Docker (or any OCI-compatible runtime).
- A directory to hold the data, writable by UID **33** (`www-data`). See the note below.
- A user list file (or let ftp2ocr create an empty one and add users afterwards).

!!! warning "File ownership (UID 33)"

    The container runs as `www-data` (UID **33**) on purpose: the produced files are
    typically consumed by Nextcloud through a shared volume, and that integration
    expects this ownership. Make sure the host directory you mount is writable by
    UID 33, e.g.:

    ```bash
    sudo mkdir -p /srv/ftp2ocr
    sudo chown -R 33:33 /srv/ftp2ocr
    ```

## Create a user

Generate a password hash and add it to a `users.txt` file:

```bash
docker run --rm -it janlo/pdf2ocr:latest ftp2ocr mkpasswd
# prints: pbkdf2_sha256$600000$...
```

Then create `users.txt`:

```ini
[default]
alice: pbkdf2_sha256$600000$...
```

You can list any number of `user: hash` pairs in the `[default]` section. See
[Configuration](configuration.md#user-list) for details and legacy hash support.

## Run with Docker

```bash
docker run -d \
  --name ftp2ocr \
  --publish 21:21 \
  --publish 60000-60100:60000-60100 \
  --volume /srv/ftp2ocr:/data \
  janlo/pdf2ocr:latest
```

The defaults assume:

- data lives in `/data` inside the container,
- the user list is `/data/users.txt`,
- the FTP control port is `21`.

Configure everything else through environment variables or by overriding the command —
see [Configuration](configuration.md).

### Ports

FTP needs the control port (default `21`) **and** a passive (PASV) port range for the
data connections. Publish both, and tell ftp2ocr about the range with
`FTP2OCR_PASSV_RANGE` (e.g. `60000-60100`). Behind NAT, also set `FTP2OCR_PASSV_HOST`
to the public address so clients can reach the data connection.

## Run with Docker Compose

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
      FTP2OCR_PASSV_HOST: "scanner.example.com"   # your public address
    volumes:
      - /srv/ftp2ocr:/data
```

Drop `users.txt` into `/srv/ftp2ocr/` before starting.

## Health check

The image ships a `HEALTHCHECK` that runs `ftp2ocr healthcheck`, which opens the control
port and verifies the FTP greeting. You can run it manually too:

```bash
docker exec ftp2ocr ftp2ocr healthcheck
```

## Building the image yourself

If you prefer to build locally (for example to bake in extra Tesseract languages):

```bash
git clone https://github.com/janlo/ftp2ocr
cd ftp2ocr
docker build -t ftp2ocr:local .
```

The build is driven by [`uv`](https://docs.astral.sh/uv/) and the committed `uv.lock`,
so builds are reproducible. See [Development](development.md).
