# Operations

Day-to-day running: logs, monitoring, failures, and backups.

## Logs

ftp2ocr logs to stdout/stderr, so `docker logs ftp2ocr` shows everything. Increase
verbosity with `FTP2OCR_VERBOSE=1` (or `--verbose`). Log lines are prefixed with the
module that produced them (e.g. `ftp2ocr.pipeline`).

## Monitoring

- **Health check** — the container ships a `HEALTHCHECK`; orchestrators pick it up
  automatically. Manually: `ftp2ocr healthcheck` (or `--port` to probe a custom port).
  Each probe opens a loopback FTP control connection without logging in; ftp2ocr logs
  those connect/disconnect lines at `DEBUG` (visible with `FTP2OCR_VERBOSE=1`) so they
  don't drown out real scanner sessions, which still log at `INFO`.
- **Queue depth** — there is no explicit queue metric; a growing number of files in the
  `new_*`/`observed` input folders while workers are busy indicates OCR is slower than
  the ingest rate. Increase `FTP2OCR_WORKERS` or CPU in that case.

## Init process

The image runs [`tini`](https://github.com/krallin/tini) as PID 1 so that orphaned
child processes — notably the ones Docker forks each time it runs the `HEALTHCHECK`
probe — are reaped instead of piling up as zombies. Without a reaper, a
long-running container can exhaust its cgroup's PID limit purely from healthcheck
probes, at which point OCR workers start failing with `RuntimeError("can't start new
thread")` or `BlockingIOError`. If you run the image with a custom entrypoint that
bypasses `tini`, pass `docker run --init` (or the orchestrator equivalent) instead.

## Failures

Anything that cannot be processed is moved to the user's `error/` directory alongside a
`<name>.error.txt` file describing the reason. Typical causes:

| Symptom | Likely cause |
| ------- | ------------ |
| `not a PDF file…` | Non-PDF uploaded into an input folder. |
| `uploaded into an unknown directory` | File placed outside the four input folders. |
| OCR failure in `.error.txt` | Corrupt/unreadable PDF, or OCR engine timeout. |
| `RuntimeError("can't start new thread")` / `BlockingIOError` | Container hit its PID limit — see [Init process](#init-process) below. |

Re-processing is manual: fix the input and upload it again (or drop it into `observed/`).

## Backups

- The **original uploads** are kept in each user's `backup/` directory. ftp2ocr does not
  prune them — add your own retention/cleanup if space is a concern.
- The **OCR results** in `processed/` are the thing Nextcloud consumes; back them up via
  your normal Nextcloud/backup strategy.

## Shutdown behaviour

On `SIGTERM`/`SIGINT` (e.g. `docker stop`), ftp2ocr stops accepting connections, stops the
filesystem observer, and waits for in-flight OCR jobs to finish before exiting. Container
`stop_timeout` should be generous if very large scans are common.

## jemalloc

The entrypoint preloads jemalloc (good for long-running Python memory behaviour). The
library path is detected at runtime, so the same image works on amd64 and arm64. Disable
with `FTP2OCR_JEMALLOC=0` if you suspect an interaction problem.
