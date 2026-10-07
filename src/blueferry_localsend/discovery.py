"""Multicast discovery transport and the registry of seen devices."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import struct
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from blueferry_plugin_kit.netaddr import Interface

from blueferry_localsend.protocol import MAX_DATAGRAM_BYTES, MULTICAST_GROUP, DeviceInfo

log = logging.getLogger(__name__)

# Forget a device after this long without any contact. LocalSend apps
# announce only when they start or refresh, so the service probes the
# devices it knows (see LocalSendService.check_devices); a device that
# answers stays, one that stopped answering (an iPhone that put LocalSend
# to sleep, a closed app) is gone after this.
DEVICE_TTL = 3 * 60
MAX_DEVICES = 32
# How often the own addresses are read again (interfaces come and go).
OWN_ADDRESSES_TTL = 30.0

OnDatagram = Callable[[bytes, str], None]


class MulticastTransport(Protocol):
    def start(self, interfaces: Sequence[Interface], port: int, on_datagram: OnDatagram) -> None:
        ...

    def send(self, payload: bytes) -> None: ...

    def stop(self) -> None: ...


class UdpMulticast:
    """224.0.0.167:<port> on the chosen interfaces only.

    Datagrams whose source is not inside one of those interfaces' subnets
    are dropped, so a packet arriving through Docker or a VPN never counts.
    """

    def __init__(self, group: str = MULTICAST_GROUP) -> None:
        self._group = group
        self._sock: socket.socket | None = None
        self._interfaces: list[Interface] = []
        self._port = 0
        self._thread: threading.Thread | None = None

    def start(self, interfaces: Sequence[Interface], port: int, on_datagram: OnDatagram) -> None:
        self.stop()
        if not interfaces:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            # The LocalSend desktop app may listen on the same port.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        # Membership is per interface; binding to the group address keeps
        # unrelated unicast datagrams to this port out.
        sock.bind((self._group, port))
        joined = []
        for interface in interfaces:
            membership = struct.pack(
                "4s4s", socket.inet_aton(self._group), socket.inet_aton(interface.address),
            )
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
                joined.append(interface)
            except OSError as error:
                log.info("cannot join multicast on %s: %s", interface.name, error.strerror)
        sock.settimeout(1.0)
        self._sock, self._interfaces, self._port = sock, joined, port
        self._thread = threading.Thread(
            target=self._loop, args=(sock, on_datagram), name="localsend-multicast", daemon=True,
        )
        self._thread.start()

    def _loop(self, sock: socket.socket, on_datagram: OnDatagram) -> None:
        while self._sock is sock:
            try:
                data, (source, _port) = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
            except TimeoutError:
                continue
            except OSError:
                return
            if len(data) > MAX_DATAGRAM_BYTES:
                continue
            if not any(interface.contains(source) for interface in self._interfaces):
                continue
            try:
                on_datagram(data, source)
            except Exception:  # one bad datagram must not end discovery
                log.exception("multicast datagram handling failed")

    def send(self, payload: bytes) -> None:
        sock = self._sock
        if sock is None:
            return
        for interface in self._interfaces:
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface.address),
                )
                sock.sendto(payload, (self._group, self._port))
            except OSError as error:
                log.info("multicast send on %s failed: %s", interface.name, error.strerror)

    def stop(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


@dataclass(frozen=True, slots=True)
class Device:
    """A device seen on the LAN.

    ``verified`` means this plugin itself connected to ``address`` over
    HTTPS and the certificate there matched ``info.fingerprint``. Anything
    else (an announcement, an incoming register, an upload request) is only
    a claim: anyone on the LAN can send any fingerprint.
    """

    info: DeviceInfo
    address: str
    last_seen: float
    verified: bool = False
    # False after a probe found nobody answering at ``address``.
    reachable: bool = True

    @property
    def target_id(self) -> str:
        return target_id_for(self.info.fingerprint)


def target_id_for(fingerprint: str) -> str:
    """A short id that is safe on the bus, stable per device."""
    return "ls-" + hashlib.sha256(fingerprint.upper().encode()).hexdigest()[:16]


class DeviceRegistry:
    """The devices seen on the LAN, never this computer itself.

    Besides this plugin's own fingerprint, everything that comes from one of
    this computer's addresses is ignored: another LocalSend on this machine
    (the app, started once) would otherwise show up as a device.
    """

    def __init__(
        self, own_fingerprint: str = "", clock: Callable[[], float] = time.time,
        own_addresses: Callable[[], Iterable[str]] = lambda: (),
    ) -> None:
        self.own_fingerprint = own_fingerprint.upper()
        self._clock = clock
        self._own_addresses = own_addresses
        self._own: frozenset[str] = frozenset()
        self._own_read = float("-inf")
        self._lock = threading.Lock()
        self._devices: dict[str, Device] = {}

    def is_own_address(self, address: str) -> bool:
        now = time.monotonic()
        if now - self._own_read > OWN_ADDRESSES_TTL:
            try:
                self._own = frozenset(self._own_addresses())
            except OSError:
                self._own = frozenset()
            self._own_read = now
        return address in self._own

    def seen(self, info: DeviceInfo, address: str, *, verified: bool = False) -> bool:
        """Record a device; True when it is new or its details changed.

        An unverified claim never replaces a verified entry: a LAN attacker
        announcing a known fingerprint (say with ``protocol: "http"``) must
        not take over that device's address, endpoint or trust badge. It
        only refreshes the entry when it repeats exactly what was verified.
        """
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            return False
        key = info.fingerprint.upper()
        if key == self.own_fingerprint or self.is_own_address(address):
            return False
        now = self._clock()
        with self._lock:
            previous = self._devices.get(key)
            if previous is not None and previous.verified and not verified:
                if previous.address == address and previous.info == info:
                    self._devices[key] = replace(previous, last_seen=now, reachable=True)
                    return not previous.reachable
                return False
            if previous is None and len(self._devices) >= MAX_DEVICES and not self._evict(
                verified,
            ):
                return False
            self._devices[key] = Device(info, address, now, verified)
        return (
            previous is None or previous.info != info or previous.address != address
            or previous.verified != verified or not previous.reachable
        )

    def answered(self, fingerprint: str, address: str, *, verified: bool) -> bool:
        """A probe reached the device at ``address``; True if that changed it.

        ``verified``: the connection was HTTPS and the certificate matched.
        Only refreshes an entry still at that address.
        """
        with self._lock:
            device = self._devices.get(fingerprint.upper())
            if device is None or device.address != address:
                return False
            updated = replace(device, last_seen=self._clock(), reachable=True,
                              verified=device.verified or verified)
            self._devices[fingerprint.upper()] = updated
        return updated.verified != device.verified or not device.reachable

    def unreachable(self, fingerprint: str, address: str) -> bool:
        """A probe found nobody; True if that changed the entry."""
        with self._lock:
            device = self._devices.get(fingerprint.upper())
            if device is None or device.address != address or not device.reachable:
                return False
            self._devices[fingerprint.upper()] = replace(device, reachable=False)
        return True

    def forget(self, fingerprint: str, address: str) -> bool:
        """Drop the entry if it is still at ``address``; True if it was."""
        with self._lock:
            device = self._devices.get(fingerprint.upper())
            if device is None or device.address != address:
                return False
            del self._devices[fingerprint.upper()]
        return True

    def quiet_since(self, seconds: float) -> list[Device]:
        """Devices without contact for at least ``seconds`` (to probe)."""
        now = self._clock()
        return [d for d in self.active() if now - d.last_seen >= seconds]

    def _evict(self, for_verified: bool) -> bool:
        """Make room for one entry. Caller holds the lock.

        Unverified entries go first; verified ones only for another verified
        device, so a flood of announcements never pushes a verified device out.
        """
        unverified = [d for d in self._devices.values() if not d.verified]
        pool = unverified or (list(self._devices.values()) if for_verified else [])
        if not pool:
            return False
        oldest = min(pool, key=lambda d: d.last_seen)
        self._devices.pop(oldest.info.fingerprint.upper(), None)
        return True

    def expire(self) -> bool:
        """Drop devices without contact for DEVICE_TTL; True if any went."""
        now = self._clock()
        with self._lock:
            gone = [k for k, d in self._devices.items()
                    if now - d.last_seen > DEVICE_TTL or self.is_own_address(d.address)]
            for key in gone:
                del self._devices[key]
        return bool(gone)

    def active(self) -> list[Device]:
        """Known devices, reachable ones first, newest contact first."""
        self.expire()
        with self._lock:
            return sorted(self._devices.values(),
                          key=lambda d: (not d.reachable, -d.last_seen))

    def by_target(self, target_id: str) -> Device | None:
        return next((d for d in self.active() if d.target_id == target_id), None)

    def by_fingerprint(self, fingerprint: str) -> Device | None:
        with self._lock:
            return self._devices.get(fingerprint.upper())

    def clear(self) -> None:
        with self._lock:
            self._devices.clear()
