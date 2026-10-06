"""Which network interfaces LocalSend may use.

Only IPv4 (LocalSend's multicast group is IPv4). By default every
interface that is up, has an address, is backed by real hardware and is not
point-to-point: that excludes loopback, Docker (``docker*``, ``br-*``,
``veth*``), libvirt and VPN tunnels (WireGuard, OpenVPN tun, PPP), which are
all virtual or point-to-point on Linux. A configured list overrides the
automatic choice, but the hard deny-list still applies.
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import socket
import struct
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
IFF_UP = 0x1
IFF_LOOPBACK = 0x8
IFF_POINTOPOINT = 0x10

DENIED_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "vnet", "tun", "tap", "wg", "ppp",
    "tailscale", "zt", "vboxnet", "vmnet", "lxc", "lxd", "podman", "cni", "flannel",
    "cali", "kube", "nordlynx", "proton", "ipsec", "utun",
)


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    address: str
    netmask: str
    flags: int = IFF_UP
    virtual: bool = False

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.address}/{self.netmask}", strict=False)

    def contains(self, address: str) -> bool:
        try:
            return ipaddress.IPv4Address(address) in self.network
        except ValueError:
            return False


def denied(name: str) -> bool:
    return name.startswith(DENIED_PREFIXES)


def _ioctl(sock: socket.socket, request: int, name: str) -> bytes:
    packed = struct.pack("256s", name.encode()[:15])
    return fcntl.ioctl(sock.fileno(), request, packed)


def system_interfaces(sys_net: Path = Path("/sys/class/net")) -> list[Interface]:
    """All IPv4 interfaces of this host (Linux)."""
    result: list[Interface] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _index, name in socket.if_nameindex():
            try:
                flags = struct.unpack("H", _ioctl(sock, SIOCGIFFLAGS, name)[16:18])[0]
                address = socket.inet_ntoa(_ioctl(sock, SIOCGIFADDR, name)[20:24])
                netmask = socket.inet_ntoa(_ioctl(sock, SIOCGIFNETMASK, name)[20:24])
            except OSError:
                continue  # no IPv4 address
            device = sys_net / name
            try:
                virtual = "/devices/virtual/" in os.path.realpath(device)
            except OSError:
                virtual = True
            result.append(Interface(name, address, netmask, flags, virtual))
    return result


def lan_interfaces(
    configured: Iterable[str] = (),
    *,
    source: Callable[[], list[Interface]] = system_interfaces,
) -> list[Interface]:
    """The interfaces to serve and announce on."""
    wanted = [name.strip() for name in configured if name.strip()]
    chosen: list[Interface] = []
    for interface in source():
        if not interface.flags & IFF_UP or interface.flags & IFF_LOOPBACK:
            continue
        if wanted:
            if interface.name in wanted and not denied(interface.name):
                chosen.append(interface)
            continue
        if denied(interface.name) or interface.virtual or interface.flags & IFF_POINTOPOINT:
            continue
        if ipaddress.IPv4Address(interface.address).is_link_local:
            continue
        chosen.append(interface)
    return chosen


def parse_interface_list(text: str) -> list[str]:
    return [part.strip() for part in text.replace(";", ",").split(",") if part.strip()]
