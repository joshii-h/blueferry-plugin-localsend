"""HTTP(S) client towards LocalSend peers.

Peers use self-signed certificates, so there is no CA check. Instead the
certificate a peer presents is pinned: its SHA-256 must equal the
fingerprint the peer announced. A mismatch aborts before any request body
(and so before any file content) leaves this machine.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from blueferry_localsend.protocol import (
    API_PREFIX,
    DeviceInfo,
    ProtocolError,
    loads,
    parse_device,
    parse_prepare_response,
)
from blueferry_localsend.tls import fingerprint_of, same_fingerprint

CONNECT_TIMEOUT = 5.0
# The receiver asks its user; LocalSend waits for that answer.
PREPARE_TIMEOUT = 120.0
UPLOAD_TIMEOUT = 60.0
CHUNK = 256 * 1024


class PeerError(Exception):
    """``token`` is one of: network, fingerprint, rejected, pin, busy,
    too-many, checksum, bad-response, cancelled, insecure, error."""

    def __init__(self, token: str, status: int = 0) -> None:
        super().__init__(token)
        self.token = token
        self.status = status


_STATUS_TOKENS = {401: "pin", 403: "rejected", 409: "busy", 422: "checksum", 429: "too-many"}


@dataclass(frozen=True, slots=True)
class Peer:
    address: str
    port: int
    protocol: str
    fingerprint: str


class PeerClient:
    def __init__(self, context: ssl.SSLContext | None) -> None:
        self._context = context

    def _connection(self, peer: Peer, timeout: float) -> http.client.HTTPConnection:
        if peer.protocol == "https":
            if self._context is None:
                raise PeerError("network")
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                peer.address, peer.port, timeout=CONNECT_TIMEOUT, context=self._context,
            )
        else:
            connection = http.client.HTTPConnection(
                peer.address, peer.port, timeout=CONNECT_TIMEOUT,
            )
        try:
            connection.connect()
        except OSError:
            connection.close()
            raise PeerError("network") from None
        if peer.protocol == "https":
            der = connection.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
            if not der or not same_fingerprint(fingerprint_of(der), peer.fingerprint):
                connection.close()
                raise PeerError("fingerprint")
        connection.sock.settimeout(timeout)  # type: ignore[union-attr]
        return connection

    def _request(
        self, peer: Peer, path: str, body: bytes | None, *, timeout: float,
        query: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        url = API_PREFIX + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        connection = self._connection(peer, timeout)
        try:
            connection.request(
                "POST", url, body=body or b"",
                headers={"Content-Type": "application/json"} if body else {},
            )
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            return response.status, data
        except (OSError, http.client.HTTPException):
            raise PeerError("network") from None
        finally:
            connection.close()

    @staticmethod
    def _raise_for(status: int) -> None:
        if status in _STATUS_TOKENS:
            raise PeerError(_STATUS_TOKENS[status], status)
        if status != 200:
            raise PeerError("error", status)

    def register(self, peer: Peer, me: DeviceInfo) -> DeviceInfo:
        status, data = self._request(
            peer, "/register", json.dumps(me.to_json()).encode(), timeout=CONNECT_TIMEOUT,
        )
        self._raise_for(status)
        try:
            info = loads(data)
            # The answer carries no endpoint; the one we called is the truth.
            info = {**info, "port": peer.port, "protocol": peer.protocol}
            return parse_device(info)
        except ProtocolError:
            raise PeerError("bad-response") from None

    def prepare_upload(
        self, peer: Peer, me: DeviceInfo, files: dict[str, dict], pin: str = "",
    ) -> tuple[str, dict[str, str]] | None:
        """Session id and file tokens; None if the receiver needs nothing (204)."""
        body = json.dumps({"info": me.to_json(), "files": files}).encode()
        status, data = self._request(
            peer, "/prepare-upload", body, timeout=PREPARE_TIMEOUT,
            query={"pin": pin} if pin else None,
        )
        if status == 204:
            return None
        self._raise_for(status)
        try:
            return parse_prepare_response(data)
        except ProtocolError:
            raise PeerError("bad-response") from None

    def upload(
        self, peer: Peer, session: str, file_id: str, token: str, path: Path, size: int,
        progress: Callable[[int], None], cancelled: Callable[[], bool],
    ) -> None:
        query = urllib.parse.urlencode({"sessionId": session, "fileId": file_id, "token": token})
        connection = self._connection(peer, UPLOAD_TIMEOUT)
        try:
            connection.putrequest("POST", f"{API_PREFIX}/upload?{query}")
            connection.putheader("Content-Type", "application/octet-stream")
            connection.putheader("Content-Length", str(size))
            connection.endheaders()
            sent = 0
            with open(path, "rb") as stream:
                while sent < size:
                    if cancelled():
                        raise PeerError("cancelled")
                    block = stream.read(min(CHUNK, size - sent))
                    if not block:
                        raise PeerError("error")  # the file shrank while sending
                    connection.send(block)
                    sent += len(block)
                    progress(len(block))
            response = connection.getresponse()
            response.read(64 * 1024)
            status = response.status
        except (OSError, http.client.HTTPException):
            raise PeerError("network") from None
        finally:
            connection.close()
        if status == 204:
            status = 200
        self._raise_for(status)

    def cancel(self, peer: Peer, session: str) -> None:
        try:
            self._request(peer, "/cancel", None, timeout=CONNECT_TIMEOUT,
                          query={"sessionId": session})
        except PeerError:
            pass

    def verify_peer(self, peer: Peer) -> bool:
        """Does the device at this address hold the certificate it claims?"""
        return self.probe(peer) is None

    def probe(self, peer: Peer) -> str | None:
        """None when the device answers (over HTTPS with the claimed
        certificate), else the reason: ``network`` or ``fingerprint``."""
        try:
            self._connection(peer, CONNECT_TIMEOUT).close()
        except PeerError as error:
            return error.token
        return None
