"""The device identity: a self-signed certificate and its fingerprint.

Like the LocalSend apps: RSA-2048, ``CN=LocalSend User``, and the
fingerprint is the SHA-256 of the certificate's DER bytes as uppercase hex.
The same certificate serves HTTPS and is offered as client certificate when
this plugin sends. The private key lives in an owner-only file.
"""
from __future__ import annotations

import datetime
import hashlib
import ssl
from dataclasses import dataclass
from pathlib import Path

from blueferry_plugin_kit.secrets import SecretsError, check_private, private_dir, write_private

class IdentityError(SecretsError):
    """The TLS identity is unusable; the kit's file errors arrive as this."""


def fingerprint_of(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest().upper()


def same_fingerprint(a: str, b: str) -> bool:
    return bool(a) and a.strip().upper() == b.strip().upper()


@dataclass(frozen=True, slots=True)
class Identity:
    cert_path: Path
    key_path: Path
    fingerprint: str

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        # LocalSend peers have self-signed client certificates that OpenSSL
        # cannot verify against a CA; their identity is checked by
        # connecting back to them (see client.verify_peer).
        context.verify_mode = ssl.CERT_NONE
        return context

    def client_context(self) -> ssl.SSLContext:
        """TLS towards a peer: no CA check (self-signed); callers pin the
        fingerprint of the presented certificate instead."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        return context


def generate(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LocalSend User")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 30))
        .sign(key, hashes.SHA256())
    )
    write_private(directory / "key.pem", key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    write_private(directory / "cert.pem", certificate.public_bytes(serialization.Encoding.PEM))


def load_identity(directory: Path) -> Identity:
    """The stored identity, created on first use."""
    try:
        return _load_identity(directory)
    except IdentityError:
        raise
    except SecretsError as error:
        raise IdentityError(str(error)) from None


def _load_identity(directory: Path) -> Identity:
    private_dir(directory, "identity directory")
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    if not cert_path.exists() or not key_path.exists():
        generate(directory)
    check_private(cert_path)
    check_private(key_path)
    pem = cert_path.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    return Identity(cert_path, key_path, fingerprint_of(der))
