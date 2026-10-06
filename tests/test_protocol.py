"""LocalSend v2 payloads from the spec and the TLS identity."""
from __future__ import annotations

import json
import ssl

import pytest
from helpers import fixture

from blueferry_localsend.protocol import (
    DeviceInfo,
    ProtocolError,
    parse_announcement,
    parse_device,
    parse_prepare_response,
    parse_prepare_upload,
)
from blueferry_localsend.tls import fingerprint_of, load_identity

# ---- protocol payloads from the spec ---------------------------------------


def test_spec_announcement_parses() -> None:
    info, wants_answer = parse_announcement(fixture("announce.json"))
    assert wants_answer is True
    assert info == DeviceInfo(
        alias="Nice Orange", fingerprint="random string", version="2.0",
        device_model="Samsung", device_type="mobile", port=53317, protocol="https",
        download=True,
    )


def test_spec_register_and_response_parse() -> None:
    register = parse_device(json.loads(fixture("register.json")))
    assert (register.alias, register.device_type, register.port) == (
        "Secret Banana", "desktop", 53317)
    # The register answer carries no endpoint; defaults fill in.
    answer = parse_device(json.loads(fixture("register-response.json")))
    assert answer.alias == "Nice Orange" and answer.port == 53317


def test_spec_prepare_upload_parses() -> None:
    request = parse_prepare_upload(fixture("prepare-upload.json"))
    assert request.info.alias == "Nice Orange"
    names = {offer.id: offer for offer in request.files}
    assert names["some file id"].file_name == "my image.png"
    assert names["some file id"].size == 324242
    # "*sha256 hash*" is not a hash: ignored instead of trusted.
    assert names["some file id"].sha256 == ""
    assert request.total_size == 324242 + 1234


def test_spec_prepare_response_parses() -> None:
    session, tokens = parse_prepare_response(fixture("prepare-upload-response.json"))
    assert session == "mySessionId"
    assert tokens == {"someFileId": "someFileToken", "someOtherFileId": "someOtherFileToken"}


@pytest.mark.parametrize("payload", [
    b"[]", b"{", b"x" * 5000,
    json.dumps({"alias": "a", "fingerprint": "f", "port": 0}).encode(),
    json.dumps({"alias": "a", "fingerprint": "f", "version": "3.0"}).encode(),
    json.dumps({"alias": "", "fingerprint": "f"}).encode(),
    json.dumps({"alias": "a", "fingerprint": "bad fingerprint\n"}).encode(),
])
def test_malformed_announcements_are_refused(payload) -> None:
    with pytest.raises(ProtocolError):
        parse_announcement(payload)


def test_unknown_device_type_falls_back_to_desktop_and_alias_is_plain() -> None:
    info = parse_device(
        {"alias": "Evil\x1b[31m\nName", "fingerprint": "F", "deviceType": "toaster"},
    )
    assert info.device_type == "desktop"
    assert info.alias == "Evil [31m Name"


@pytest.mark.parametrize("files", [
    {}, {"a": {"id": "b", "fileName": "x", "size": 1}},
    {"a": {"id": "a", "fileName": "x", "size": -1}},
    {"a": {"id": "a", "fileName": "", "size": 1}},
    {"a": {"id": "a", "fileName": "x\x00y", "size": 1}},
    {str(i): {"id": str(i), "fileName": "x", "size": 1} for i in range(1001)},
])
def test_malformed_upload_requests_are_refused(files) -> None:
    body = json.dumps({"info": json.loads(fixture("register.json")), "files": files})
    with pytest.raises(ProtocolError):
        parse_prepare_upload(body.encode())


# ---- identity ---------------------------------------------------------------


def test_fingerprint_matches_localsend_test_vector() -> None:
    der = ssl.PEM_cert_to_DER_cert(fixture("localsend-cert.pem").decode())
    assert fingerprint_of(der) == (
        "4BADDE53A7F7CDEEED93189FD898E02BF6B4806CA4C05DE0ACE08319B86552FA"
    )


def test_identity_is_created_once_and_owner_only(tmp_path) -> None:
    first = load_identity(tmp_path / "identity")
    second = load_identity(tmp_path / "identity")
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64 and first.fingerprint == first.fingerprint.upper()
    assert oct(first.key_path.stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "identity").stat().st_mode & 0o777) == "0o700"
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(first.cert_path.read_bytes())
    assert cert.subject.rfc4514_string() == "CN=LocalSend User"
    assert cert.public_key().key_size == 2048
