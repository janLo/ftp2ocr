"""Self-signed TLS certificate generation.

The certificate is only *used* when a client negotiates TLS via ``AUTH TLS``;
pyftpdlib merely advertises the capability unless enforcement is enabled
(``--tls-control-required`` / ``--tls-data-required``). A self-signed
certificate provides encryption but no authentication — scanners usually
do not validate certificates anyway. Mount real certificates if you need
proper trust.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_log = logging.getLogger(__name__)

_VALIDITY_DAYS = 10 * 365


def generate_selfsigned_cert(hostname: str, ip_addresses: list[str] | None = None):
    """Generate a self-signed certificate for *hostname* (+ optional IPs)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    # Include the hostname in the SAN; modern clients ignore the CN.
    alt_names: list[x509.GeneralName] = [x509.DNSName(hostname)]
    for addr in ip_addresses or []:
        alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem


def ensure_cert(
    hostname: str, keyfile: Path | str, certfile: Path | str, ip_addresses: list[str] | None = None
) -> tuple[Path, Path]:
    """Return paths to a usable certificate/key pair, generating one if missing.

    Existing files win, so administrators can mount their own certificates.
    """
    certfile = Path(certfile)
    keyfile = Path(keyfile)

    if certfile.exists() and keyfile.exists():
        return certfile, keyfile

    _log.info("Generating self-signed TLS certificate for %r in %s", hostname, certfile)
    cert_data, key_data = generate_selfsigned_cert(hostname, ip_addresses)

    certfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.parent.mkdir(parents=True, exist_ok=True)

    # Write the private key with restrictive permissions.
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fk:
        fk.write(key_data)
    os.chmod(keyfile, 0o600)

    certfile.write_bytes(cert_data)

    return certfile, keyfile
