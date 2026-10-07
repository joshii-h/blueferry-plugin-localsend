"""The plugin process: LocalSend discovery, receiving and sending.

Threads: the GLib main loop (D-Bus), one HTTPS server thread per LAN
address plus one thread per connection, the multicast reader, and one
thread per outgoing transfer. D-Bus signals are always emitted through
``self._to_main``.
"""
from __future__ import annotations

import http.client
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import ssl
import subprocess  # nosec B404 - only xdg-open with a file:// URI, no shell
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from blueferry.plugin_api.config import ConfigError
from blueferry.plugin_api.manifest import PluginManifest
from blueferry.plugin_api.service import PluginCallError

from blueferry_localsend import files as fs
from blueferry_localsend.client import Peer, PeerClient, PeerError
from blueferry_localsend.discovery import Device, DeviceRegistry, MulticastTransport, UdpMulticast
from blueferry_localsend.i18n import german, t
from blueferry_localsend.netif import Interface, lan_interfaces, parse_interface_list
from blueferry_localsend.protocol import (
    API_PREFIX,
    DEFAULT_PORT,
    PROTOCOL_VERSION,
    DeviceInfo,
    ProtocolError,
    UploadRequest,
    loads,
    parse_announcement,
    parse_device,
)
from blueferry_localsend.server import Policy, Receiver, ServerGroup, Session
from blueferry_localsend.settings import Settings, SettingsError, SettingsStore
from blueferry_localsend.surfaces import (
    Action,
    CardItem,
    ShareTarget,
    SurfacesService,
    action_result,
)
from blueferry_localsend.tls import Identity, IdentityError, fingerprint_of, load_identity

log = logging.getLogger(__name__)

DECISION_TIMEOUT = 60.0
ANNOUNCE_INTERVAL = 10.0
DISCOVERY_WAIT = 1.0
MAX_RECENT = 10
MAX_PENDING_SHOWN = 2
MAX_DEVICES_SHOWN = 3
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_DEVICE_ICONS = {"mobile": "phone", "desktop": "computer", "web": "web-browser",
                 "headless": "utilities-terminal", "server": "network-server"}


@dataclass
class Pending:
    id: str
    request: UploadRequest
    address: str
    created: float
    event: threading.Event = field(default_factory=threading.Event)
    accepted: bool = False


@dataclass
class SendJob:
    id: str
    device: Device
    paths: list[Path]
    total: int
    sent: int = 0
    state: str = "waiting"  # waiting | sending | done | failed
    reason: str = ""
    session: str = ""
    cancelled: threading.Event = field(default_factory=threading.Event)


@dataclass(frozen=True, slots=True)
class Transfer:
    direction: str  # "in" | "out"
    peer: str
    count: int
    size: int
    when: float
    ok: bool
    reason: str = ""


def open_with_desktop(uri: str) -> bool:
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio

        return bool(Gio.AppInfo.launch_default_for_uri(uri, None))
    except Exception:
        pass
    opener = shutil.which("xdg-open")
    if not opener:
        return False
    subprocess.Popen(  # nosec B603 - fixed program, URI built by us
        [opener, uri], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, start_new_session=True,
    )
    return True


def _system_interfaces(names: list[str]) -> list[Interface]:
    return lan_interfaces(names)


class LocalSendService(SurfacesService):
    def __init__(
        self,
        manifest: PluginManifest,
        bus: Any = None,
        *,
        settings: SettingsStore | None = None,
        interfaces: Callable[[list[str]], list[Interface]] = _system_interfaces,
        multicast: MulticastTransport | None = None,
        port: int | None = None,
        decision_timeout: float = DECISION_TIMEOUT,
        discovery_wait: float = DISCOVERY_WAIT,
        opener: Callable[[str], bool] = open_with_desktop,
        **kwargs: Any,
    ) -> None:
        super().__init__(manifest, bus, **kwargs)
        self._store = settings or SettingsStore()
        self._interfaces_for = interfaces
        self._multicast = multicast if multicast is not None else UdpMulticast()
        self._port_override = port
        self._decision_timeout = decision_timeout
        self._discovery_wait = discovery_wait
        self._opener = opener
        self._lock = threading.RLock()
        self._identity: Identity | None = None
        self._client: PeerClient | None = None
        self._registry = DeviceRegistry()
        self._servers = ServerGroup()
        self._active_interfaces: list[Interface] = []
        self._problem = ""
        self._pending: dict[str, Pending] = {}
        self._jobs: dict[str, SendJob] = {}
        self._recent: deque[Transfer] = deque(maxlen=MAX_RECENT)
        self._recorded: set[str] = set()
        self._last_announce = 0.0
        self._last_card_signal = 0.0
        self.receiver = Receiver(
            me=self.me, policy=self._policy, decide=self._decide,
            on_register=self._on_register, on_change=self._on_session_change,
        )

    # ---- lifecycle -------------------------------------------------------

    def _settings(self) -> Settings:
        try:
            return self._store.load()
        except SettingsError as error:
            log.warning("settings unreadable, using defaults: %s", error)
            return Settings()

    def identity(self) -> Identity:
        with self._lock:
            if self._identity is None:
                self._identity = load_identity(self._store.identity_dir)
                self._client = PeerClient(self._identity.client_context())
                self._registry.own_fingerprint = self._identity.fingerprint.upper()
            return self._identity

    @property
    def peer_client(self) -> PeerClient:
        self.identity()
        assert self._client is not None
        return self._client

    def start(self) -> None:
        """Bind the servers and join multicast on the LAN interfaces."""
        settings = self._settings()
        try:
            identity = self.identity()
        except (IdentityError, OSError) as error:
            self._problem = f"identity: {error}"
            log.error("cannot load the TLS identity: %s", error)
            return
        interfaces = self._interfaces_for(parse_interface_list(settings.interfaces))
        port = settings.port if self._port_override is None else self._port_override
        with self._lock:
            self._active_interfaces = list(interfaces)
        if not interfaces:
            self._problem = t("no_interface")
            log.warning("no LAN interface to use")
            return
        addresses = list(dict.fromkeys(i.address for i in interfaces))
        failed = self._servers.start(
            addresses, port, self.receiver, identity.server_context(), self.allowed,
        )
        self._problem = f"port {port} busy on " + ", ".join(failed) if failed else ""
        try:
            self._multicast.start(interfaces, self.port, self._on_datagram)
        except OSError as error:
            log.warning("multicast unavailable: %s", error.strerror)
        if settings.visible:
            self.announce()
        log.info("LocalSend ready on %d address(es)", len(self._servers.servers))

    def stop(self) -> None:
        self._multicast.stop()
        self._servers.stop()
        for pending in list(self._pending.values()):
            pending.event.set()
        for job in list(self._jobs.values()):
            job.cancelled.set()

    def restart(self) -> None:
        self.stop()
        self.start()
        self.emit_card_changed()

    @property
    def port(self) -> int:
        ports = self._servers.ports
        if ports:
            return ports[0]
        settings = self._settings()
        return settings.port if self._port_override is None else self._port_override

    def me(self) -> DeviceInfo:
        return DeviceInfo(
            alias=self._settings().alias,
            fingerprint=self.identity().fingerprint,
            version=PROTOCOL_VERSION,
            device_model="Linux",
            device_type="desktop",
            port=self.port,
            protocol="https",
            download=False,
        )

    def allowed(self, address: str) -> bool:
        """Only peers inside the subnets of the chosen interfaces."""
        with self._lock:
            interfaces = list(self._active_interfaces)
        return any(interface.contains(address) for interface in interfaces)

    def _policy(self) -> Policy:
        settings = self._settings()
        return Policy(
            target_dir=settings.target_dir,
            max_bytes=settings.max_bytes,
            pin=settings.pin if settings.require_pin else "",
            visible=settings.visible,
        )

    # ---- discovery -------------------------------------------------------

    def announce(self) -> None:
        self._last_announce = time.monotonic()
        payload = json.dumps(self.me().to_json(announce=True)).encode()
        self._multicast.send(payload)

    def _on_datagram(self, data: bytes, source: str) -> None:
        try:
            info, wants_answer = parse_announcement(data)
        except ProtocolError:
            return
        if info.fingerprint.upper() == self.identity().fingerprint.upper():
            return
        if self._registry.seen(info, source):
            self.emit_card_changed()
        if wants_answer and self._settings().visible:
            self._background(self._answer, info, source)

    def _answer(self, info: DeviceInfo, source: str) -> None:
        peer = Peer(source, info.port, info.protocol, info.fingerprint)
        try:
            answer = self.peer_client.register(peer, self.me())
        except PeerError:
            # Spec fallback: answer on the multicast group instead.
            self._multicast.send(json.dumps(self.me().to_json(announce=False)).encode())
            return
        # The answer's fingerprint is "ignored in HTTPS mode"; the one we
        # pinned while connecting (from the announcement) identifies it.
        # Over HTTPS that pin is the proof; plain HTTP proves nothing.
        verified = peer.protocol == "https"
        if self._registry.seen(replace(answer, fingerprint=info.fingerprint), source,
                               verified=verified):
            self.emit_card_changed()

    def _on_register(self, info: DeviceInfo, address: str) -> None:
        if self._registry.seen(info, address):
            self.emit_card_changed()
        known = self._registry.by_fingerprint(info.fingerprint)
        if info.protocol == "https" and known is not None and not known.verified:
            self._background(self._verify, info, address)

    def _verify(self, info: DeviceInfo, address: str) -> None:
        """Connect back and check the certificate a register claimed."""
        if self.peer_client.verify_peer(Peer(address, info.port, "https", info.fingerprint)):
            if self._registry.seen(info, address, verified=True):
                self.emit_card_changed()

    def _background(self, work: Callable[..., None], *args: Any) -> None:
        threading.Thread(target=work, args=args, name="localsend-answer", daemon=True).start()

    def refresh_devices(self) -> None:
        """Announce (if visible) and give peers a moment to answer."""
        settings = self._settings()
        if settings.visible and time.monotonic() - self._last_announce > ANNOUNCE_INTERVAL:
            self.announce()
            if not self._registry.active():
                time.sleep(self._discovery_wait)
        if settings.http_scan and not self._registry.active():
            self.scan_subnets()

    def scan_subnets(self, limit: int = 1024) -> None:
        """Legacy HTTP discovery: ``register`` at every address of the own
        subnets (at most ``limit`` hosts per interface, so never a /16)."""
        me = self.me()
        with self._lock:
            interfaces = list(self._active_interfaces)
        targets: list[str] = []
        for interface in interfaces:
            network = interface.network
            if network.num_addresses > limit:
                continue
            targets += [str(h) for h in network.hosts() if str(h) != interface.address]

        def probe(address: str) -> None:
            for protocol in ("https", "http"):
                try:
                    # The fingerprint is unknown; only a reachable LocalSend
                    # answers. Over HTTPS the fingerprint recorded is the one
                    # of the certificate it showed, so that entry is verified.
                    info = self._probe(address, protocol, me)
                except PeerError:
                    continue
                self._registry.seen(info, address, verified=protocol == "https")
                return

        with ThreadPoolExecutor(max_workers=32) as pool:
            list(pool.map(probe, targets))
        self.emit_card_changed()

    def _probe(self, address: str, protocol: str, me: DeviceInfo) -> DeviceInfo:
        identity = self.identity()
        try:
            if protocol == "https":
                connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                    address, DEFAULT_PORT, timeout=0.8, context=identity.client_context(),
                )
            else:
                connection = http.client.HTTPConnection(address, DEFAULT_PORT, timeout=0.8)
            connection.connect()
            seen = ""
            if protocol == "https":
                seen = fingerprint_of(connection.sock.getpeercert(binary_form=True))
            connection.request("POST", API_PREFIX + "/register",
                               body=json.dumps(me.to_json()).encode(),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read(65536)
            connection.close()
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise PeerError("network") from None
        if response.status != 200:
            raise PeerError("error")
        try:
            raw = {**loads(data), "port": DEFAULT_PORT, "protocol": protocol}
            if seen:
                raw["fingerprint"] = seen
            return parse_device(raw)
        except ProtocolError:
            raise PeerError("bad-response") from None

    # ---- receiving -------------------------------------------------------

    def _decide(self, request: UploadRequest, address: str) -> bool:
        settings = self._settings()
        info = request.info
        if settings.auto_accept_trusted and settings.is_trusted(info.fingerprint):
            # The fingerprint in the request is only a claim; the device at
            # this address must present the matching certificate.
            if info.protocol == "https" and self.peer_client.verify_peer(
                Peer(address, info.port, "https", info.fingerprint)
            ):
                log.info("upload from a trusted device accepted automatically")
                return True
            log.info("trusted fingerprint not proven; asking the user")
        self._registry.seen(info, address)
        pending = Pending(secrets.token_hex(6), request, address, time.monotonic())
        with self._lock:
            self._pending[pending.id] = pending
        size = fs.human_size(request.total_size, german=german())
        count = len(request.files)
        body = (t("wants_to_send_one", name=info.alias, size=size) if count == 1
                else t("wants_to_send", name=info.alias, count=count, size=size))
        self.emit_notify(t("localsend"), body, "document-save", t("accept"),
                         f"accept-{pending.id}")
        self.emit_card_changed()
        pending.event.wait(self._decision_timeout)
        with self._lock:
            self._pending.pop(pending.id, None)
        self.emit_card_changed()
        log.info("upload request %s", "accepted" if pending.accepted else "declined")
        return pending.accepted

    def resolve(self, pending_id: str, accept: bool) -> bool:
        with self._lock:
            pending = self._pending.get(pending_id)
        if pending is None:
            return False
        pending.accepted = accept
        pending.event.set()
        return True

    def _on_session_change(self, session: Session) -> None:
        if session.finished and session.id not in self._recorded:
            self._recorded.add(session.id)
            size = sum(o.size for o in session.request.files if o.id in session.done)
            transfer = Transfer("in", session.request.info.alias, len(session.done), size,
                                time.time(), not session.failed)
            self._recent.appendleft(transfer)
            if transfer.ok:
                shown = fs.human_size(size, german=german())
                text = (t("received_one", name=transfer.peer, size=shown)
                        if transfer.count == 1 else
                        t("received", name=transfer.peer, count=transfer.count, size=shown))
                self.emit_notify(t("localsend"), text, "folder-download", t("open_folder"),
                                 "open-folder")
            self.emit_card_changed()
            return
        self._throttled_card_changed()

    def _throttled_card_changed(self) -> None:
        now = time.monotonic()
        if now - self._last_card_signal >= 1.0:
            self._last_card_signal = now
            self.emit_card_changed()

    # ---- sending ---------------------------------------------------------

    def _sendable(self, device: Device) -> bool:
        """HTTPS pins the receiver's certificate; plain HTTP is opt-in."""
        return device.info.protocol == "https" or self._settings().allow_http_send

    def share_targets(self) -> list[ShareTarget]:
        self.refresh_devices()
        return [
            ShareTarget(d.target_id, t("target_label", name=d.info.alias),
                        _DEVICE_ICONS.get(d.info.device_type, "computer"))
            for d in self._registry.active() if self._sendable(d)
        ]

    def send_files(self, target_id: str, paths: list[str]) -> dict:
        device = self._registry.by_target(target_id)
        if device is None:
            return {"ok": False, "message": t("unknown_target"), "job": None}
        if not self._sendable(device):
            return {"ok": False, "message": t("insecure_target"), "job": None}
        chosen: list[Path] = []
        for raw in paths:
            path = Path(raw)
            if path.is_absolute() and path.is_file() and os.access(path, os.R_OK):
                chosen.append(path)
        if not chosen:
            return {"ok": False, "message": t("no_files"), "job": None}
        with self._lock:
            if any(j.state in ("waiting", "sending") for j in self._jobs.values()):
                return {"ok": False, "message": t("busy"), "job": None}
            job = SendJob(secrets.token_hex(6), device, chosen,
                          sum(p.stat().st_size for p in chosen))
            self._jobs = {k: v for k, v in self._jobs.items()
                          if v.state in ("waiting", "sending")}
            self._jobs[job.id] = job
        threading.Thread(target=self._send, args=(job,), name="localsend-send",
                         daemon=True).start()
        self.emit_card_changed()
        return {"ok": True, "job": job.id,
                "message": t("sending_started", count=len(chosen), name=device.info.alias)}

    def _send(self, job: SendJob) -> None:
        info = job.device.info
        peer = Peer(job.device.address, info.port, info.protocol, info.fingerprint)
        client = self.peer_client
        try:
            if not self._sendable(job.device):
                raise PeerError("insecure")
            offers: dict[str, dict] = {}
            by_id: dict[str, Path] = {}
            for path in job.paths:
                file_id = secrets.token_hex(8)
                stat = path.stat()
                offers[file_id] = {
                    "id": file_id,
                    "fileName": path.name,
                    "size": stat.st_size,
                    "fileType": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                    "sha256": fs.sha256_file(path),
                    "preview": None,
                    "metadata": {
                        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
                        "accessed": None,
                    },
                }
                by_id[file_id] = path
            answer = client.prepare_upload(peer, self.me(), offers)
            if answer is None:
                job.state = "done"
                return
            job.session, tokens = answer
            job.state = "sending"
            self.emit_card_changed()

            def progress(amount: int) -> None:
                job.sent += amount
                self._throttled_card_changed()

            for file_id, token in tokens.items():
                if file_id not in by_id:
                    continue  # the receiver may accept only some files
                if job.cancelled.is_set():
                    raise PeerError("cancelled")
                client.upload(peer, job.session, file_id, token, by_id[file_id],
                              offers[file_id]["size"], progress, job.cancelled.is_set)
            job.state = "done"
        except PeerError as error:
            job.state, job.reason = "failed", error.token
            if job.session:
                client.cancel(peer, job.session)
            log.info("sending failed: %s", error.token)
        except OSError as error:
            job.state, job.reason = "failed", "error"
            log.info("sending failed: %s", type(error).__name__)
        finally:
            ok = job.state == "done"
            self._recent.appendleft(Transfer("out", info.alias, len(job.paths), job.total,
                                             time.time(), ok, job.reason))
            if not ok and job.reason != "cancelled":
                self.emit_notify(t("localsend"), t("failed_send", name=info.alias,
                                 reason=t(f"reason_{job.reason}")), "dialog-error")
            self.emit_card_changed()

    # ---- card ------------------------------------------------------------

    def card_items(self) -> list[CardItem]:
        items: list[CardItem] = []
        de = german()
        with self._lock:
            pendings = sorted(self._pending.values(), key=lambda p: p.created)
            jobs = [j for j in self._jobs.values() if j.state in ("waiting", "sending")]
        for pending in pendings[:MAX_PENDING_SHOWN]:
            request = pending.request
            size = fs.human_size(request.total_size, german=de)
            count = len(request.files)
            title = (t("wants_to_send_one", name=request.info.alias, size=size) if count == 1
                     else t("wants_to_send", name=request.info.alias, count=count, size=size))
            names = ", ".join(o.file_name.replace("\\", "/").split("/")[-1]
                              for o in request.files[:3])
            items.append(CardItem(
                f"pending-{pending.id}", "document-save", title, names,
                (Action("accept", t("accept"), "dialog-ok", "primary"),
                 Action("reject", t("reject"), "dialog-cancel")),
            ))
        session = self.receiver.active
        if session is not None:
            items.append(CardItem(
                "receiving", "folder-download",
                t("receiving", name=session.request.info.alias,
                  percent=_percent(session.received, session.total),
                  done=fs.human_size(session.received, german=de),
                  size=fs.human_size(session.total, german=de)),
            ))
        for job in jobs[:1]:
            if job.state == "waiting":
                title = t("waiting", name=job.device.info.alias)
            else:
                title = t("sending", name=job.device.info.alias,
                          percent=_percent(job.sent, job.total),
                          done=fs.human_size(job.sent, german=de),
                          size=fs.human_size(job.total, german=de))
            items.append(CardItem(f"job-{job.id}", "document-send", title, None,
                                  (Action("cancel", t("cancel"), "process-stop"),)))
        items += self._device_items()
        items.append(self._recent_item())
        return items[:8]

    def _device_items(self) -> list[CardItem]:
        settings = self._settings()
        devices = self._registry.active()
        if not devices:
            subtitle = t("no_devices") if settings.visible else t("invisible")
            return [CardItem("devices", "network-wireless", t("devices"), subtitle)]
        items = []
        for device in devices[:MAX_DEVICES_SHOWN]:
            trusted = settings.is_trusted(device.info.fingerprint)
            details = [t("devices")]
            if device.info.device_model:
                details.append(device.info.device_model)
            # The badge and "Trust device" only for a certificate this plugin
            # checked itself; an announcement alone may be spoofed.
            if not device.verified:
                details.append(t("unverified"))
                actions: tuple[Action, ...] = (
                    (Action("untrust", t("untrust"), "security-low"),) if trusted else ()
                )
            elif trusted:
                details.append(t("trusted"))
                actions = (Action("untrust", t("untrust"), "security-low"),)
            else:
                actions = (Action("trust", t("trust"), "security-high"),)
            items.append(CardItem(
                f"dev-{device.target_id}", _DEVICE_ICONS.get(device.info.device_type, "computer"),
                device.info.alias, " · ".join(details), actions,
            ))
        return items

    def _recent_item(self) -> CardItem:
        de = german()
        lines = []
        for transfer in list(self._recent)[:2]:
            size = fs.human_size(transfer.size, german=de)
            stamp = time.strftime("%H:%M", time.localtime(transfer.when))
            if not transfer.ok:
                text = (t("failed_receive", name=transfer.peer) if transfer.direction == "in"
                        else t("failed_send", name=transfer.peer,
                               reason=t(f"reason_{transfer.reason or 'error'}")))
            elif transfer.direction == "in":
                text = (t("received_one", name=transfer.peer, size=size) if transfer.count == 1
                        else t("received", name=transfer.peer, count=transfer.count, size=size))
            else:
                text = (t("sent_one", name=transfer.peer, size=size) if transfer.count == 1
                        else t("sent", name=transfer.peer, count=transfer.count, size=size))
            lines.append(f"{stamp} {text}")
        return CardItem(
            "recent", "folder-download", t("recent"),
            "; ".join(lines) if lines else t("no_recent"),
            (Action("open-folder", t("open_folder"), "folder-open"),),
        )

    def invoke_action(self, item_id: str, action_id: str, args: dict) -> str:
        if item_id == "notify":
            if action_id == "open-folder":
                return self._open_folder()
            for prefix, accept in (("accept-", True), ("reject-", False)):
                if action_id.startswith(prefix):
                    return self._resolve_result(action_id[len(prefix):], accept)
            return action_result(False, "unknown action")
        if item_id.startswith("pending-") and action_id in ("accept", "reject"):
            return self._resolve_result(item_id[len("pending-"):], action_id == "accept")
        if item_id.startswith("job-") and action_id == "cancel":
            job = self._jobs.get(item_id[len("job-"):])
            if job is None:
                return action_result(False, "unknown transfer")
            job.cancelled.set()
            return action_result(True, t("reason_cancelled"))
        if item_id.startswith("dev-") and action_id in ("trust", "untrust"):
            device = self._registry.by_target(item_id[len("dev-"):])
            if device is None:
                return action_result(False, t("unknown_target"))
            try:
                if action_id == "trust":
                    if not device.verified:
                        return action_result(False, t("not_verified"))
                    self._store.trust(device.info.fingerprint, device.info.alias)
                    message = t("trusted_now", name=device.info.alias)
                else:
                    self._store.untrust(device.info.fingerprint)
                    message = t("untrusted_now", name=device.info.alias)
            except (SettingsError, OSError) as error:
                raise PluginCallError(str(error)) from None
            self.emit_card_changed()
            return action_result(True, message)
        if action_id == "open-folder":
            return self._open_folder()
        return action_result(False, "unknown action")

    def _resolve_result(self, pending_id: str, accept: bool) -> str:
        if not self.resolve(pending_id, accept):
            return action_result(False, "the request is no longer open")
        return action_result(True, t("accepted") if accept else t("rejected"))

    def _open_folder(self) -> str:
        target = self._settings().target_dir
        try:
            fs.prepare_root(target)
        except (OSError, fs.UnsafePath) as error:
            return action_result(False, str(error))
        # Not via open_uri: the core opens file:// only below the plugin
        # cache, and the download folder is elsewhere.
        if not self._opener(target.resolve().as_uri()):
            return action_result(False, "no file manager found")
        return action_result(True)

    # ---- Plugin1 ---------------------------------------------------------

    def status(self) -> dict[str, object]:
        if self._problem:
            return {"state": "error", "detail": self._problem}
        with self._lock:
            interfaces = list(self._active_interfaces)
        where = ", ".join(f"{i.name} ({i.address}:{self.port})" for i in interfaces)
        return {"state": "ok", "detail": t("ok_listening", where=where)}

    def config_values(self) -> dict[str, object]:
        settings = self._settings()
        return {
            "device_name": settings.device_name,
            "visible": settings.visible,
            "download_dir": settings.download_dir,
            "max_size_mb": settings.max_size_mb,
            "auto_accept_trusted": settings.auto_accept_trusted,
            "require_pin": settings.require_pin,
            "pin": bool(settings.pin),
            "port": settings.port,
            "interfaces": settings.interfaces,
            "http_scan": settings.http_scan,
            "allow_http_send": settings.allow_http_send,
        }

    def apply_config(self, values: dict[str, object]) -> None:
        current = self._settings()
        name = str(values.get("device_name") or "")
        if len(name) > 64:
            raise ConfigError("device_name", "is too long (64 characters at most)")
        directory = str(values.get("download_dir") or "")
        if directory and not os.path.isabs(os.path.expanduser(directory)):
            raise ConfigError("download_dir", "must be an absolute path or start with ~/")
        names = parse_interface_list(str(values.get("interfaces") or ""))
        if any(not _INTERFACE_NAME.fullmatch(n) for n in names):
            raise ConfigError("interfaces", "must be interface names separated by commas")
        pin = current.pin
        if "pin" in values:
            pin = str(values["pin"])
            if not pin.isdigit() or not 4 <= len(pin) <= 12:
                raise ConfigError("pin", "must be 4 to 12 digits")
        require_pin = bool(values.get("require_pin", current.require_pin))
        if require_pin and not pin:
            raise ConfigError("pin", "set a PIN or turn the PIN off")
        updated = replace(
            current,
            device_name=name,
            visible=bool(values.get("visible", current.visible)),
            download_dir=directory,
            max_size_mb=int(values.get("max_size_mb", current.max_size_mb)),  # type: ignore[arg-type]
            auto_accept_trusted=bool(values.get("auto_accept_trusted",
                                                current.auto_accept_trusted)),
            require_pin=require_pin,
            pin=pin,
            port=int(values.get("port", current.port)),  # type: ignore[arg-type]
            interfaces=", ".join(names),
            http_scan=bool(values.get("http_scan", current.http_scan)),
            allow_http_send=bool(values.get("allow_http_send", current.allow_http_send)),
        )
        try:
            self._store.save(updated)
        except (SettingsError, OSError) as error:
            raise ConfigError("", f"could not store the settings: {error}") from None
        network_changed = (updated.port, updated.interfaces) != (current.port, current.interfaces)
        if network_changed or updated.visible != current.visible:
            self.restart()
        else:
            self.emit_card_changed()


def _percent(done: int, total: int) -> int:
    return 100 if total <= 0 else min(100, int(done * 100 / total))

