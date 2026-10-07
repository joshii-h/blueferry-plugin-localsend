"""Receiving: the LocalSend HTTPS server and its upload sessions.

Routes (protocol v2): ``POST register``, ``GET|POST info``,
``POST prepare-upload``, ``POST upload``, ``POST cancel``. The download API
(section 5, browser downloads over plain HTTP) is not offered.

The server binds only to the addresses it is given (the LAN interfaces) and
additionally drops connections whose source is outside the allowed subnets,
so a Docker container or a VPN peer cannot reach it through host routing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import shutil
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from blueferry_plugin_kit.lanserver import (
    ConnectionsPerAddress,
    DeadlineRequestHandler,
    HardenedHTTPServer,
    SlidingWindows,
)

from blueferry_localsend import files as fs
from blueferry_localsend.protocol import (
    API_PREFIX,
    MAX_JSON_BYTES,
    DeviceInfo,
    FileOffer,
    ProtocolError,
    UploadRequest,
    loads,
    parse_device,
    parse_prepare_upload,
)

log = logging.getLogger(__name__)

SESSION_IDLE_TIMEOUT = 120.0
PREPARE_PER_MINUTE = 10
REGISTER_PER_MINUTE = 20
PIN_FAILURES_ALLOWED = 5
PIN_FAILURE_WINDOW = 600.0
MAX_TRACKED_ADDRESSES = 1024
MAX_CONNECTIONS = 32
DISK_RESERVE = 100 * 1024 * 1024
READ_CHUNK = 256 * 1024
REQUEST_SOCKET_TIMEOUT = 60.0
# Request line, headers and JSON bodies (at most 1 MB) must arrive within
# this; the wait between keep-alive requests counts too.
REQUEST_DEADLINE = 30.0
# Upload bodies: 60 s plus one second per 16 KiB, a floor no real transfer
# hits but a trickling client does.
UPLOAD_GRACE = 60.0
MIN_UPLOAD_RATE = 16 * 1024
# A phone holds more than one connection while it sends: LocalSend's HTTP
# clients keep idle connections open (discovery's register/info and the
# sender's own), the upload runs on one, and Cancel needs another. With two
# a cancel or a register during a transfer was refused. Four still keeps
# one address from taking a noticeable share of MAX_CONNECTIONS.
MAX_CONNECTIONS_PER_ADDRESS = 4


@dataclass
class Session:
    id: str
    address: str
    request: UploadRequest
    root: Path
    tokens: dict[str, str]
    started: float
    last_activity: float
    done: dict[str, Path] = field(default_factory=dict)
    busy: set[str] = field(default_factory=set)
    received: int = 0
    finished: bool = False
    failed: bool = False

    @property
    def offers(self) -> dict[str, FileOffer]:
        return {offer.id: offer for offer in self.request.files}

    @property
    def total(self) -> int:
        return self.request.total_size


@dataclass(frozen=True, slots=True)
class Policy:
    """What the receiver needs from the settings, read per request."""

    target_dir: Path
    max_bytes: int
    pin: str = ""
    visible: bool = True


class Receiver:
    """Protocol logic without sockets, so tests can call it directly."""

    def __init__(
        self,
        *,
        me: Callable[[], DeviceInfo],
        policy: Callable[[], Policy],
        decide: Callable[[UploadRequest, str], bool],
        on_register: Callable[[DeviceInfo, str], None],
        on_change: Callable[[Session], None],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._me = me
        self._policy = policy
        self._decide = decide
        self._on_register = on_register
        self._on_change = on_change
        self._clock = clock
        self._lock = threading.Lock()
        self._session: Session | None = None
        self._asking: set[str] = set()
        tracked = MAX_TRACKED_ADDRESSES
        self._prepares = SlidingWindows(60.0, PREPARE_PER_MINUTE, clock, max_tracked=tracked)
        self._registers = SlidingWindows(60.0, REGISTER_PER_MINUTE, clock, max_tracked=tracked)
        self._pin_failures = SlidingWindows(
            PIN_FAILURE_WINDOW, PIN_FAILURES_ALLOWED, clock, max_tracked=tracked,
        )

    # ---- helpers ---------------------------------------------------------

    def _current(self) -> Session | None:
        """The active session, after expiring an idle one. Caller holds the lock."""
        session = self._session
        if session is not None and (
            session.finished or self._clock() - session.last_activity > SESSION_IDLE_TIMEOUT
        ):
            if not session.finished:
                # Running uploads see this and delete their temp files.
                session.failed = True
            self._session = None
            return None
        return session

    # ---- routes ----------------------------------------------------------

    def info(self) -> tuple[int, dict | None]:
        if not self._policy().visible:
            return 404, None
        return 200, self._me().to_json(with_endpoint=False)

    def register(self, body: bytes, address: str) -> tuple[int, dict | None]:
        if not self._policy().visible:
            return 404, None
        with self._lock:
            if not self._registers.take(address):
                return 429, None
        try:
            info = parse_device(loads(body))
        except ProtocolError:
            return 400, None
        self._on_register(info, address)
        return 200, self._me().to_json(with_endpoint=False)

    def prepare_upload(
        self, body: bytes, address: str, query: dict[str, str],
    ) -> tuple[int, dict | None]:
        policy = self._policy()
        if not policy.visible:
            return 403, None  # hidden means receiving nothing, not only staying quiet
        with self._lock:
            # Five wrong PINs lock the address out for ten minutes.
            if self._pin_failures.full(address) or not self._prepares.take(address):
                return 429, None
        if policy.pin:
            given = query.get("pin", "")
            if not secrets.compare_digest(given.encode(), policy.pin.encode()):
                if given:
                    # The first attempt without a PIN is how a sender learns
                    # that one is needed; only actual guesses count.
                    with self._lock:
                        self._pin_failures.add(address)
                return 401, None
        try:
            request = parse_prepare_upload(body)
        except ProtocolError as error:
            log.info("prepare-upload refused: %s", error)
            return 400, None
        if request.info.fingerprint.upper() == self._me().fingerprint.upper():
            return 400, None
        with self._lock:
            if self._current() is not None or self._asking:
                return 409, None
            self._asking.add(address)
        try:
            if request.total_size > policy.max_bytes:
                log.info("prepare-upload refused: %d bytes over the limit", request.total_size)
                return 403, None
            try:
                root = fs.prepare_root(policy.target_dir)
                free = shutil.disk_usage(root).free
            except (OSError, fs.UnsafePath):
                return 500, None
            if request.total_size + DISK_RESERVE > free:
                return 403, None
            # Blocks while the user decides (or until the decision times out).
            if not self._decide(request, address):
                return 403, None
            tokens = {offer.id: secrets.token_urlsafe(24) for offer in request.files}
            now = self._clock()
            session = Session(
                id=secrets.token_urlsafe(18), address=address, request=request, root=root,
                tokens=tokens, started=now, last_activity=now,
            )
            with self._lock:
                self._session = session
        finally:
            with self._lock:
                self._asking.discard(address)
        self._on_change(session)
        return 200, {"sessionId": session.id, "files": tokens}

    def cancel(self, query: dict[str, str], address: str) -> int:
        with self._lock:
            session = self._current()
            if session is None or session.id != query.get("sessionId"):
                return 200  # nothing to cancel is not an error for the sender
            if session.address != address:
                return 403
            session.failed = True
            session.finished = True
            self._session = None
        self._on_change(session)
        return 200

    def upload(
        self, query: dict[str, str], address: str, stream: BinaryIO, length: int | None,
        chunked: bool,
    ) -> int:
        session_id, file_id, token = (
            query.get("sessionId"), query.get("fileId"), query.get("token"),
        )
        if not session_id or not file_id or not token:
            return 400
        with self._lock:
            session = self._current()
            if session is None or session.id != session_id:
                return 409 if session is not None else 403
            expected = session.tokens.get(file_id)
            if (
                session.address != address or expected is None
                or not secrets.compare_digest(expected.encode(), token.encode())
            ):
                return 403
            if file_id in session.done or file_id in session.busy:
                return 409
            session.busy.add(file_id)
            session.last_activity = self._clock()
        offer = session.offers[file_id]
        try:
            status = self._receive(session, offer, stream, length, chunked)
        finally:
            with self._lock:
                session.busy.discard(file_id)
        return status

    # ---- storage ---------------------------------------------------------

    def _receive(
        self, session: Session, offer: FileOffer, stream: BinaryIO, length: int | None,
        chunked: bool,
    ) -> int:
        if not chunked and (length is None or length != offer.size):
            return 400
        try:
            relative = fs.safe_relative_path(offer.file_name)
            parent = fs.target_parent(session.root, relative)
            descriptor, temporary = fs.open_temporary(parent)
        except (fs.UnsafePath, OSError) as error:
            log.info("cannot store an offered file: %s", type(error).__name__)
            return 500
        digest = hashlib.sha256()
        written = 0
        ok = False
        last_report = 0.0
        try:
            with os.fdopen(descriptor, "wb") as out:
                for block in _body(stream, length, chunked):
                    written += len(block)
                    if written > offer.size:
                        return 400  # more than announced: the size limit holds
                    out.write(block)
                    digest.update(block)
                    with self._lock:
                        session.received += len(block)
                        session.last_activity = self._clock()
                        if session.failed:
                            return 409
                    if self._clock() - last_report > 0.5:
                        last_report = self._clock()
                        self._on_change(session)
            if written != offer.size:
                return 400
            if offer.sha256 and digest.hexdigest() != offer.sha256:
                return 422
            ok = True
        except (OSError, ValueError) as error:
            log.info("upload aborted: %s", type(error).__name__)
            return 500
        finally:
            if not ok:
                temporary.unlink(missing_ok=True)
                with self._lock:
                    session.received -= min(written, offer.size)
        try:
            path = fs.commit(temporary, parent, relative.name)
        except OSError:
            temporary.unlink(missing_ok=True)
            return 500
        self._mark_done(session, offer, path)
        return 200

    def _mark_done(self, session: Session, offer: FileOffer, path: Path) -> None:
        with self._lock:
            session.done[offer.id] = path
            if len(session.done) == len(session.tokens):
                session.finished = True
                if self._session is session:
                    self._session = None
        self._on_change(session)

    @property
    def active(self) -> Session | None:
        with self._lock:
            return self._current()


def _body(stream: BinaryIO, length: int | None, chunked: bool):
    if not chunked:
        remaining = length or 0
        while remaining > 0:
            block = stream.read(min(READ_CHUNK, remaining))
            if not block:
                raise ValueError("connection closed early")
            remaining -= len(block)
            yield block
        return
    while True:
        line = stream.readline(66)
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            raise ValueError("bad chunk header") from None
        if size == 0:
            while stream.readline(1024) not in (b"\r\n", b"\n", b""):
                pass
            return
        remaining = size
        while remaining > 0:
            block = stream.read(min(READ_CHUNK, remaining))
            if not block:
                raise ValueError("connection closed early")
            remaining -= len(block)
            yield block
        stream.readline(4)


class _Handler(DeadlineRequestHandler):
    # The kit replaces the socket file so every read respects the request's
    # remaining time (the wait between keep-alive requests counts too), and
    # never logs the request line: its query carries the PIN and tokens.
    server_version = "LocalSend"
    timeout = REQUEST_SOCKET_TIMEOUT
    server: LocalSendServer

    def request_deadline(self) -> float:
        return REQUEST_DEADLINE  # read at runtime, tests shorten it

    # Under this plugin's logger, not the kit's.
    log = log
    log_prefix = "http: "

    def _route(self) -> tuple[str, dict[str, str]]:
        parsed = urllib.parse.urlsplit(self.path)
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items() if v}
        if not parsed.path.startswith(API_PREFIX + "/"):
            return "", query
        return parsed.path[len(API_PREFIX) + 1:], query

    def _reply(self, status: int, payload: dict | None = None) -> None:
        body = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length < 0 or length > MAX_JSON_BYTES:
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:
        route, _query = self._route()
        if route == "info":
            self._reply(*self.server.receiver.info())
        else:
            self._reply(404)

    def do_POST(self) -> None:
        route, query = self._route()
        address = self.client_address[0]
        receiver = self.server.receiver
        if route == "upload":
            self.deadline.stream(UPLOAD_GRACE, MIN_UPLOAD_RATE)
            chunked = "chunked" in (self.headers.get("Transfer-Encoding") or "").lower()
            try:
                length = None if chunked else int(self.headers.get("Content-Length") or "x")
            except ValueError:
                length = None
            status = receiver.upload(query, address, self.rfile, length, chunked)
            if status != 200:
                self.close_connection = True  # the body may be unread
            self._reply(status)
            return
        if route == "cancel":
            self._reply(receiver.cancel(query, address))
            return
        if route in ("register", "prepare-upload", "info"):
            body = self._json_body()
            if body is None:
                self.close_connection = True
                self._reply(400 if route != "info" else 413)
                return
            if route == "register":
                self._reply(*receiver.register(body, address))
            elif route == "info":
                self._reply(*receiver.info())
            else:
                self._reply(*receiver.prepare_upload(body, address, query))
            return
        self.close_connection = True
        self._reply(404)


class LocalSendServer(HardenedHTTPServer):
    """Connection caps, the subnet allowlist and the TLS handshake on the
    connection's own thread come from the kit."""

    log = log

    def __init__(
        self, address: tuple[str, int], receiver: Receiver,
        context: ssl.SSLContext | None, allowed: Callable[[str], bool],
        per_address: ConnectionsPerAddress | None = None,
    ) -> None:
        self.receiver = receiver
        super().__init__(
            address, _Handler, context=context, allowed=allowed,
            max_connections=MAX_CONNECTIONS, max_per_address=MAX_CONNECTIONS_PER_ADDRESS,
            per_address=per_address,
        )

    def handshake_timeout(self) -> float:
        return REQUEST_DEADLINE  # read at runtime, tests shorten it
