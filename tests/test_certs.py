"""Tests for TLS certificate generation."""

from pathlib import Path

from cryptography import x509

from ftp2ocr.certs import ensure_cert, generate_selfsigned_cert


def test_generate_selfsigned_cert_parses() -> None:
    cert_pem, key_pem = generate_selfsigned_cert("scanner.example.com", ["192.168.1.5"])

    assert b"BEGIN CERTIFICATE" in cert_pem
    assert b"PRIVATE KEY" in key_pem

    cert = x509.load_pem_x509_certificate(cert_pem)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns_names = san.get_values_for_type(x509.DNSName)
    ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]

    assert "scanner.example.com" in dns_names
    assert "192.168.1.5" in ips

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False


def test_ensure_cert_generates_and_reuses(tmp_path: Path) -> None:
    certfile = tmp_path / "cert.pem"
    keyfile = tmp_path / "key.pem"

    cert, key = ensure_cert("host1", keyfile, certfile)
    assert cert == certfile
    assert key == keyfile
    assert certfile.exists()
    assert keyfile.exists()
    first_content = certfile.read_bytes()

    # Key file must not be world-readable.
    assert keyfile.stat().st_mode & 0o077 == 0

    # Second call reuses the existing files (custom certs win).
    cert, key = ensure_cert("other-host", keyfile, certfile)
    assert certfile.read_bytes() == first_content
