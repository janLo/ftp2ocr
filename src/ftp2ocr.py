#!/usr/bin/env python3

import configparser
import crypt
import datetime
import ipaddress
import logging
import math
import multiprocessing
import os
import shutil
import subprocess
import typing

from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

import pikepdf
import click
from pyftpdlib.servers import FTPServer

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent

_log = logging.getLogger(__name__)


class UserEntry(typing.NamedTuple):
    username: str
    passwd: str


def _is_subpath(file_path, dir_path):
    return file_path.startswith(os.path.abspath(dir_path) + os.sep)


CERT_FILE = "selfsigned.crt"
KEY_FILE = "private.key"


def generate_selfsigned_cert(hostname, ip_addresses=None, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    # Generate our key
    if key is None:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend(),
        )

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
    alt_names = [x509.DNSName(hostname)]

    # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
    if ip_addresses:
        for addr in ip_addresses:
            # openssl wants DNSnames for ips...
            alt_names.append(x509.DNSName(addr))
            # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
            # note: older versions of cryptography do not understand ip_address objects
            alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

    san = x509.SubjectAlternativeName(alt_names)

    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return cert_pem, key_pem


def ensure_cert(hostname, keyfile, certfile):
    if os.path.exists(certfile):
        return certfile, keyfile

    cert_data, key_data = generate_selfsigned_cert(hostname)
    with open(certfile, "wb") as fc:
        fc.write(cert_data)

    with open(keyfile, "wb") as fk:
        fk.write(key_data)

    return certfile, keyfile


class PathFactory:
    def __init__(self, base_path: str):
        self._base_path = base_path

    def home(self, username):
        return os.path.join(self._base_path, username)

    def new_raw(self, username):
        return os.path.join(self.home(username), "new_raw")

    def new_simplex(self, username):
        return os.path.join(self.home(username), "new_simplex")

    def new_duplex(self, username):
        return os.path.join(self.home(username), "new_duplex")

    def backup(self, username):
        return os.path.join(self.home(username), "backup")

    def error(self, username):
        return os.path.join(self.home(username), "error")

    def processed(self, username):
        return os.path.join(self.home(username), "processed")

    def observed(self, username):
        return os.path.join(self.home(username), "observed")

    def iter_paths(self, username):
        for path_fn in (
            self.home,
            self.new_raw,
            self.new_duplex,
            self.new_simplex,
            self.backup,
            self.error,
            self.processed,
            self.observed,
        ):
            yield path_fn(username)

    def get_user(self, path: str):
        rem = os.path.abspath(self._base_path) + os.sep
        assert path.startswith(rem)

        user_part = path[len(rem) :].lstrip(os.sep)

        return user_part.split(os.sep)[0]


def _reorder_duplex(input: str, output: str):
    with pikepdf.open(input) as pdf:
        cnt = len(pdf.pages)
        half = int(math.ceil(cnt / 2))
        res = []
        for idx in range(half):
            res.append(pdf.pages[idx])
            if idx + half < cnt:
                res.append(pdf.pages[cnt - idx - 1])

        for idx, page in enumerate(res):
            pdf.pages[idx] = page

        pdf.remove_unreferenced_resources()
        pdf.save(output)


def _run_ocr_processor(input: str, output: str):
    proc = subprocess.Popen(
        f"ocrmypdf --rotate-pages --language deu --deskew --clean --optimize 3 --jbig2-lossy --quiet {input} {output}",
        shell=True,
        stderr=subprocess.PIPE,
    )
    proc.wait(300)

    if proc.returncode != 0:
        err = proc.stderr.read()
        raise RuntimeError(err)


def _write_error(input: str, target: str, error: str):
    os.rename(input, target)
    with open(target + ".error.txt", "w") as fn:
        fn.write(error)


def _clean(process):
    process.cleanup()


class Process:
    def __init__(self, filename: str, user: str):

        self._filename = filename
        self._user = user
        self._tempfiles = []

    def mktmpfile(self, suffix):
        tmpfile = self._filename + suffix
        _log.debug("new tmpfile: %s", tmpfile)
        self._tempfiles.append(tmpfile)

        return tmpfile

    def cleanup(self):
        for file in self._tempfiles:
            if os.path.exists(file):
                os.unlink(file)

    @property
    def last_filename(self):
        return self._tempfiles[-1] if self._tempfiles else self._filename

    @property
    def orig_path(self):
        return self._filename

    @property
    def user(self):
        return self._user


class PdfProcessor:
    def __init__(self, path_factory: PathFactory):
        self._path_factory = path_factory
        self._pool = multiprocessing.Pool(2, maxtasksperchild=10)
        self._observer = Observer()

    def run_ocr(self, process):
        self._pool.apply_async(
            _run_ocr_processor,
            args=(process.last_filename, process.mktmpfile("ocr.pdf")),
            callback=lambda _: self.move_processed(process),
            error_callback=lambda ex: self.fail_pdf(process, "Error in doing ocr", ex),
        )

    def move_processed(self, process):
        dest = os.path.join(
            self._path_factory.processed(username=process.user),
            os.path.basename(process.orig_path),
        )

        self._pool.apply_async(
            shutil.copyfile,
            args=(process.last_filename, dest),
            callback=lambda _: self.backup(process),
            error_callback=lambda ex: self.fail_pdf(
                process, "Error in writing the destination file", ex
            ),
        )

    def run_reorder_duplex(self, process: Process):
        lastfile = process.last_filename
        outfile = process.mktmpfile(".reordered.pdf")
        _log.info("reorder pages from %s into %s", lastfile, outfile)

        self._pool.apply_async(
            _reorder_duplex,
            args=(lastfile, outfile),
            callback=lambda _: self.run_ocr(process),
            error_callback=lambda ex: self.fail_pdf(
                process, "Error in reordering duplex pages", ex
            ),
        )

    def fail_pdf(self, process: Process, error: str, ex: Exception):
        target = os.path.join(
            self._path_factory.error(process.user), os.path.basename(process.orig_path)
        )
        self._pool.apply_async(
            _write_error,
            args=(process.orig_path, target, f"{error}\n\n{ex}"),
            callback=lambda _: self._pool.apply_async(_clean, args=(process,)),
        )

    def backup(self, process):
        target = os.path.join(
            self._path_factory.backup(process.user), os.path.basename(process.orig_path)
        )
        self._pool.apply_async(
            os.rename,
            args=(process.orig_path, target),
            callback=lambda _: self._pool.apply_async(_clean, args=(process,)),
        )

    def process(self, file):
        if not file.endswith(".pdf"):
            _log.error("Unrecognized file: %s", os.path.basename(file))
            return

        user = self._path_factory.get_user(file)
        process = Process(file, user)

        _log.info("process file %s for user %s", file, user)

        if _is_subpath(file, self._path_factory.new_duplex(user)):
            self.run_reorder_duplex(process)
        elif _is_subpath(file, self._path_factory.new_simplex(user)):
            self.run_ocr(process)
        elif _is_subpath(file, self._path_factory.new_raw(user)):
            self.move_processed(process)
        else:
            self.fail_pdf(process, "No known input dir", RuntimeError())

    def make_handler(self, authorizer, passv_range, passv_host, certfile, keyfile):

        outer_self = self

        class OcrFtpHandler(TLS_FTPHandler):
            def on_file_received(self, file: str):
                outer_self.process(file)

        OcrFtpHandler.authorizer = authorizer

        cert, key = ensure_cert(passv_host, certfile, keyfile)

        OcrFtpHandler.certfile = cert
        OcrFtpHandler.keyfile = key

        if passv_range is not None:

            start, end = passv_range.split("-", maxsplit=1)
            OcrFtpHandler.passive_ports = range(int(start), int(end) + 1)

        if passv_host is not None:
            OcrFtpHandler.masquerade_address = passv_host

        return OcrFtpHandler

    def make_observer(self, user_manager):
        for entry in user_manager.users():
            self._observer.schedule(ObserveHandler(self), self._path_factory.observed(entry.username), recursive=True)
    
        self._observer.start()
        
                    
class ObserveHandler(FileSystemEventHandler):
    def __init__(self, processor: PdfProcessor):
        super().__init__()
        self._processor = processor

    def on_created(self, event):
        if isinstance(self, event, FileCreatedEvent):
            self._processor.process(event.src_path)


class UserManager(DummyAuthorizer):
    def __init__(self, path_factory: PathFactory, user_list: typing.List[UserEntry]):
        super().__init__()

        self._path_factory = path_factory
        self._user_list = user_list

        self._init_users()

    def _init_users(self):
        for user in self._user_list:
            for path in self._path_factory.iter_paths(user.username):
                os.makedirs(path, exist_ok=True)

            self.add_user(
                user.username,
                password=user.passwd,
                homedir=self._path_factory.home(user.username),
                perm="el",
            )
            self.override_perm(
                user.username,
                self._path_factory.new_raw(user.username),
                "elrawMT",
                recursive=True,
            )
            self.override_perm(
                user.username,
                self._path_factory.new_duplex(user.username),
                "elrawMT",
                recursive=True,
            )
            self.override_perm(
                user.username,
                self._path_factory.new_simplex(user.username),
                "elrawMT",
                recursive=True,
            )

    def users() -> UserEntry:
        return list(self._user_list)

    def validate_authentication(self, username, password, handler):
        try:
            pw1 = self.user_table[username]["pwd"]
            pw2 = crypt.crypt(password, pw1)
        except KeyError:  # no such username
            raise AuthenticationFailed("No such user")
        else:
            if pw1 != pw2:
                raise AuthenticationFailed("Wrong password")


def read_user_list(list_file) -> typing.List[UserEntry]:
    cfg = configparser.ConfigParser()
    cfg.read(list_file)

    dflt = cfg["default"]

    res = []
    for user in dflt:
        res.append(UserEntry(username=user, passwd=dflt[user]))

    return res


@click.command("pdf2ocr")
@click.option("-d", "--base-dir", help="The directory to save to", required=True)
@click.option("-u", "--user-list", help="user list config", required=True)
@click.option("-p", "--port", help="ftp port to listen on", type=int, required=True)
@click.option(
    "-r", "--passv-range", help="PASV port range", required=False, default=None
)
@click.option("-r", "--passv-host", help="PASV hostname", required=False, default=None)
@click.option("-c", "--certfile", help="certificate file", default="cert.pem")
@click.option("-k", "--keyfile", help="private key file", default="key.pem")
def main(base_dir, user_list, port, passv_range, passv_host, certfile, keyfile):
    logging.basicConfig(level=logging.INFO)

    path_factory = PathFactory(base_dir)
    user_manager = UserManager(path_factory, read_user_list(user_list))
    pdf_processor = PdfProcessor(path_factory)
    handler = pdf_processor.make_handler(user_manager, passv_range, passv_host, certfile, keyfile)
    processor.make_observer(user_manager)

    server = FTPServer(("", port), handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
