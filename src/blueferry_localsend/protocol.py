"""LocalSend protocol v2: constants and strict parsing of peer payloads.

Implements the wire format of https://github.com/localsend/protocol
(README, protocol version 2.x). Everything a peer sends is untrusted: each
field is type-checked and length-limited here, before any other module
sees it.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

# 2.2 only adds 422 for a sha256 mismatch on upload, which the receiver
# already answers and the sender reports as "checksum".
PROTOCOL_VERSION = "2.2"
DEFAULT_PORT = 53317
MULTICAST_GROUP = "224.0.0.167"
API_PREFIX = "/api/localsend/v2"

DEVICE_TYPES = frozenset({"mobile", "desktop", "web", "headless", "server"})
MAX_JSON_BYTES = 1024 * 1024          # prepare-upload with previews stays far below
MAX_DATAGRAM_BYTES = 4096
MAX_FILES_PER_SESSION = 1000
MAX_ALIAS = 64
MAX_FIELD = 255
_FINGERPRINT = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")  # random text in HTTP mode
# Ids and tokens are opaque; the spec examples even contain spaces.
_TOKENISH = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_VERSION = re.compile(r"^\d{1,3}\.\d{1,3}$")


class ProtocolError(ValueError):
    """A peer payload that does not follow the protocol."""


def _text(value: object, limit: int, what: str, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ProtocolError(f"{what} must be text")
    cleaned = "".join(ch if ch.isprintable() else " " for ch in value)
    cleaned = " ".join(cleaned.split())[:limit]
    if required and not cleaned:
        raise ProtocolError(f"{what} is empty")
    return cleaned


def loads(raw: bytes | str, limit: int = MAX_JSON_BYTES) -> dict:
    """A JSON object of at most ``limit`` bytes."""
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(data) > limit:
        raise ProtocolError("payload too large")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("payload is not JSON") from None
    if not isinstance(value, dict):
        raise ProtocolError("payload is not a JSON object")
    return value


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """``alias``, ``version``, ``deviceModel`` … as in announce/register/info."""

    alias: str
    fingerprint: str
    version: str = PROTOCOL_VERSION
    device_model: str = ""
    device_type: str = "desktop"
    port: int = DEFAULT_PORT
    protocol: str = "https"
    download: bool = False

    def to_json(self, *, announce: bool | None = None, with_endpoint: bool = True) -> dict:
        payload: dict[str, object] = {
            "alias": self.alias,
            "version": self.version,
            "deviceModel": self.device_model or None,
            "deviceType": self.device_type,
            "fingerprint": self.fingerprint,
        }
        if with_endpoint:
            payload["port"] = self.port
            payload["protocol"] = self.protocol
        payload["download"] = self.download
        if announce is not None:
            payload["announce"] = announce
        return payload


def parse_device(value: object, *, default_port: int = DEFAULT_PORT) -> DeviceInfo:
    """A peer's info object (announce, register, prepare-upload ``info``)."""
    if not isinstance(value, Mapping):
        raise ProtocolError("device info must be an object")
    fingerprint = value.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise ProtocolError("invalid fingerprint")
    version = value.get("version", "2.0")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ProtocolError("invalid version")
    if not version.startswith("2."):
        raise ProtocolError("unsupported protocol version")
    device_type = value.get("deviceType")
    if not isinstance(device_type, str) or device_type not in DEVICE_TYPES:
        # The official implementation falls back to desktop for unknown types.
        device_type = "desktop"
    port = value.get("port", default_port)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProtocolError("invalid port")
    protocol = value.get("protocol", "https")
    if protocol not in ("http", "https"):
        raise ProtocolError("invalid protocol")
    download = value.get("download", False)
    return DeviceInfo(
        alias=_text(value.get("alias"), MAX_ALIAS, "alias"),
        fingerprint=fingerprint,
        version=version,
        device_model=_text(value.get("deviceModel"), MAX_ALIAS, "deviceModel", required=False),
        device_type=device_type,
        port=port,
        protocol=str(protocol),
        download=download if isinstance(download, bool) else False,
    )


def parse_announcement(raw: bytes) -> tuple[DeviceInfo, bool]:
    """A multicast datagram: the device and whether it asks for an answer."""
    value = loads(raw, MAX_DATAGRAM_BYTES)
    announce = value.get("announce", value.get("announcement", False))
    return parse_device(value), announce is True


@dataclass(frozen=True, slots=True)
class FileOffer:
    id: str
    file_name: str          # as sent; never used as a path before files.safe_relative_path
    size: int
    file_type: str = ""
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class UploadRequest:
    info: DeviceInfo
    files: tuple[FileOffer, ...] = field(default_factory=tuple)

    @property
    def total_size(self) -> int:
        return sum(offer.size for offer in self.files)


def parse_prepare_upload(raw: bytes) -> UploadRequest:
    value = loads(raw)
    info = parse_device(value.get("info"))
    files = value.get("files")
    if not isinstance(files, Mapping) or not files:
        raise ProtocolError("no files offered")
    if len(files) > MAX_FILES_PER_SESSION:
        raise ProtocolError("too many files")
    offers: list[FileOffer] = []
    for key, entry in files.items():
        if not isinstance(entry, Mapping):
            raise ProtocolError("file entry must be an object")
        file_id = entry.get("id", key)
        if not isinstance(file_id, str) or not _TOKENISH.fullmatch(file_id) or file_id != key:
            raise ProtocolError("invalid file id")
        size = entry.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ProtocolError("invalid file size")
        name = entry.get("fileName")
        if not isinstance(name, str) or not name or len(name) > 4096 or "\x00" in name:
            raise ProtocolError("invalid file name")
        digest = entry.get("sha256")
        if digest is not None and (
            not isinstance(digest, str) or not re.fullmatch(r"[0-9A-Fa-f]{64}", digest)
        ):
            digest = None  # nullable; an unusable hash is ignored, not trusted
        offers.append(FileOffer(
            id=file_id,
            file_name=name,
            size=size,
            file_type=_text(entry.get("fileType"), MAX_FIELD, "fileType", required=False),
            sha256=(digest or "").lower(),
        ))
    return UploadRequest(info=info, files=tuple(offers))


def parse_prepare_response(raw: bytes) -> tuple[str, dict[str, str]]:
    """``{sessionId, files: {fileId: token}}`` from a receiver."""
    value = loads(raw)
    session = value.get("sessionId")
    files = value.get("files")
    if not isinstance(session, str) or not _TOKENISH.fullmatch(session):
        raise ProtocolError("invalid session id")
    if not isinstance(files, Mapping):
        raise ProtocolError("invalid file tokens")
    tokens: dict[str, str] = {}
    for file_id, token in files.items():
        if not isinstance(token, str) or not _TOKENISH.fullmatch(token):
            raise ProtocolError("invalid file token")
        tokens[str(file_id)] = token
    return session, tokens
