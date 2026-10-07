"""Interface choice and multicast discovery, with mocked sockets."""
from __future__ import annotations

import socket
import struct
from typing import ClassVar

from helpers import fixture

from blueferry_localsend import discovery as discovery_module
from blueferry_localsend.discovery import DeviceRegistry, UdpMulticast
from blueferry_localsend.netif import IFF_POINTOPOINT, IFF_UP, Interface, lan_interfaces
from blueferry_localsend.protocol import (
    DeviceInfo,
)

# ---- interfaces and multicast (mocked) --------------------------------------


def test_only_lan_interfaces_are_used() -> None:
    p2p = IFF_UP | IFF_POINTOPOINT
    system = [
        Interface("lo", "127.0.0.1", "255.0.0.0", IFF_UP | 0x8),
        Interface("wlp7s0", "192.168.1.95", "255.255.255.0"),
        Interface("enp0s20f0u9u2", "192.168.1.4", "255.255.255.0"),
        Interface("enp6s0", "192.168.2.4", "255.255.255.0", 0),            # down
        Interface("docker0", "172.17.0.1", "255.255.0.0", virtual=True),
        Interface("br-26254538c1fe", "172.19.0.1", "255.255.0.0", virtual=True),
        Interface("veth257267f", "169.254.3.3", "255.255.0.0", virtual=True),
        Interface("Immeditech", "10.10.22.16", "255.255.255.255", p2p, virtual=True),
        Interface("wg0", "10.8.0.2", "255.255.255.0", p2p, virtual=True),
        Interface("tun0", "10.9.0.2", "255.255.255.0", p2p, virtual=True),
    ]
    names = [i.name for i in lan_interfaces(source=lambda: system)]
    assert names == ["wlp7s0", "enp0s20f0u9u2"]
    # A configured list wins, but the deny-list still holds.
    chosen = lan_interfaces(["enp0s20f0u9u2", "docker0"], source=lambda: system)
    assert [i.name for i in chosen] == ["enp0s20f0u9u2"]


class _FakeSocket:
    instances: ClassVar[list[_FakeSocket]] = []

    def __init__(self, *args) -> None:
        self.options: list[tuple] = []
        self.sent: list[tuple] = []
        self.bound = None
        self.inbox = [
            (fixture("announce.json"), ("192.168.1.50", 53317)),
            (fixture("announce.json"), ("172.17.0.2", 53317)),   # via Docker: dropped
        ]
        _FakeSocket.instances.append(self)

    def setsockopt(self, *args) -> None:
        self.options.append(args)

    def bind(self, address) -> None:
        self.bound = address

    def settimeout(self, value) -> None:
        pass

    def recvfrom(self, size):
        if self.inbox:
            return self.inbox.pop(0)
        raise OSError("closed")

    def sendto(self, payload, address) -> None:
        self.sent.append((payload, address))

    def close(self) -> None:
        pass


def test_multicast_joins_and_sends_per_interface(monkeypatch) -> None:
    monkeypatch.setattr(discovery_module.socket, "socket", _FakeSocket)
    received: list = []
    transport = UdpMulticast()
    interfaces = [
        Interface("wlp7s0", "192.168.1.95", "255.255.255.0"),
        Interface("enp9s0", "10.1.0.5", "255.255.0.0"),
    ]
    transport.start(interfaces, 53317, lambda data, source: received.append(source))
    transport._thread.join(timeout=2)
    sock = _FakeSocket.instances[-1]
    assert sock.bound == ("224.0.0.167", 53317)
    memberships = [o[2] for o in sock.options if o[1] == socket.IP_ADD_MEMBERSHIP]
    assert memberships == [
        struct.pack("4s4s", socket.inet_aton("224.0.0.167"), socket.inet_aton(a))
        for a in ("192.168.1.95", "10.1.0.5")
    ]
    assert received == ["192.168.1.50"]
    transport._sock = sock
    transport.send(b"{}")
    assert sock.sent == [(b"{}", ("224.0.0.167", 53317))] * 2
    choices = [o[2] for o in sock.options if o[1] == socket.IP_MULTICAST_IF]
    assert choices == [socket.inet_aton("192.168.1.95"), socket.inet_aton("10.1.0.5")]
    transport.stop()


def test_registry_ignores_itself_and_expires() -> None:
    now = [1000.0]
    registry = DeviceRegistry("ME", clock=lambda: now[0])
    me = DeviceInfo(alias="me", fingerprint="me")
    phone = DeviceInfo(alias="iPhone", fingerprint="ab12")
    assert registry.seen(me, "192.168.1.2") is False
    assert registry.seen(phone, "192.168.1.3") is True
    assert registry.seen(phone, "192.168.1.3") is False
    assert registry.by_fingerprint("AB12").address == "192.168.1.3"
    now[0] += discovery_module.DEVICE_TTL + 1
    assert registry.active() == []


def test_unverified_claims_never_replace_or_evict_verified_devices() -> None:
    now = [1000.0]
    registry = DeviceRegistry("ME", clock=lambda: now[0])
    phone = DeviceInfo(alias="iPhone", fingerprint="AB12")
    assert registry.seen(phone, "192.168.1.3", verified=True) is True
    spoof = DeviceInfo(alias="iPhone", fingerprint="AB12", protocol="http", port=80)
    assert registry.seen(spoof, "192.168.1.66") is False
    kept = registry.by_fingerprint("AB12")
    assert kept.verified and kept.address == "192.168.1.3" and kept.info.protocol == "https"
    # A verified answer from a new address (DHCP) does move it.
    assert registry.seen(phone, "192.168.1.4", verified=True) is True
    # A flood of unverified announcements cannot push it out.
    for number in range(discovery_module.MAX_DEVICES * 2):
        now[0] += 1
        registry.seen(DeviceInfo(alias="x", fingerprint=f"F{number}"), "192.168.1.9")
    assert registry.by_fingerprint("AB12") is not None
    assert len(registry.active()) == discovery_module.MAX_DEVICES
