"""Two plugin instances on localhost and the FakeHost core; manifest and settings.

No real multicast and no real bus: discovery runs over an in-memory
multicast bus, the BlueFerry core is the FakeHost.
"""
from __future__ import annotations

import ast
import json
import os
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from blueferry.plugin_api.client import PluginClient
from blueferry.plugin_api.testing import ServiceTransport, inline_service
from fakehost import FakeHost, accept_api_1_2
from helpers import _offer, _request

from blueferry_localsend import PLUGIN_ID, manifest_text
from blueferry_localsend import __main__ as cli
from blueferry_localsend.client import Peer, PeerClient, PeerError
from blueferry_localsend.netif import IFF_UP, Interface
from blueferry_localsend.protocol import DeviceInfo
from blueferry_localsend.service import LocalSendService
from blueferry_localsend.settings import Settings, SettingsStore

LOOPBACK = Interface("lo-test", "127.0.0.1", "255.0.0.0", IFF_UP)


# ---- two plugin instances on localhost ----------------------------------------


class MulticastBus:
    """In-memory stand-in for 224.0.0.167: every member hears the others."""

    def __init__(self) -> None:
        self.members: list[_Member] = []

    def member(self) -> _Member:
        member = _Member(self)
        self.members.append(member)
        return member


class _Member:
    def __init__(self, bus: MulticastBus) -> None:
        self.bus = bus
        self.handler = None
        self.sent: list[bytes] = []

    def start(self, interfaces, port, on_datagram) -> None:
        self.handler = on_datagram

    def send(self, payload: bytes) -> None:
        self.sent.append(payload)
        for other in self.bus.members:
            if other is not self and other.handler is not None:
                other.handler(payload, "127.0.0.1")

    def stop(self) -> None:
        self.handler = None


@pytest.fixture
def manifest(monkeypatch):
    accept_api_1_2(monkeypatch)
    return cli.load_manifest()


@pytest.fixture
def plugins(tmp_path, manifest):
    bus = MulticastBus()
    made: list[LocalSendService] = []
    opened: list[str] = []

    def make(name: str, **kwargs) -> tuple[LocalSendService, FakeHost]:
        store = SettingsStore(tmp_path / name / "config")
        settings = kwargs.pop("settings", Settings())
        store.save(replace(settings, device_name=name,
                           download_dir=str(tmp_path / name / "inbox")))
        service = inline_service(
            LocalSendService, manifest, settings=store,
            interfaces=lambda names: [LOOPBACK], multicast=bus.member(), port=0,
            opener=lambda uri: opened.append(uri) or True, discovery_wait=0.0, **kwargs,
        )
        host = FakeHost(service)
        service.start()
        made.append(service)
        return service, host

    make.opened = opened
    yield make
    for service in made:
        service.stop()


def _wait(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.02)


def _files(tmp_path: Path) -> list[Path]:
    out = tmp_path / "outbox"
    out.mkdir()
    paths = []
    for name, size in (("IMG_0001.HEIC", 300_000), ("notes.txt", 12), ("empty.bin", 0)):
        path = out / name
        path.write_bytes(os.urandom(size))
        paths.append(path)
    return paths


def test_roundtrip_between_two_instances(tmp_path, plugins) -> None:
    alice, alice_host = plugins("alice")
    bob, bob_host = plugins("bob")
    # Bob started after Alice: his announcement reached her, she answered
    # with register over HTTPS, so both know each other.
    _wait(lambda: alice._registry.active() and bob._registry.active())

    targets = alice_host.share_targets()
    assert [t["label"] for t in targets] == ["bob (LocalSend)"]
    assert targets[0]["icon"] == "computer"

    paths = _files(tmp_path)
    answer = alice_host.send_files(targets[0]["id"], [str(p) for p in paths] + ["/nonexistent"])
    assert answer["ok"] is True and answer["job"]

    # Bob's core shows a notification and a pending card item.
    bob_host.wait_for(lambda: bob_host.notifications)
    _title, body, _icon, label, _action = bob_host.notifications[0]
    assert body == "alice wants to send 3 files (300 KB)" and label == "Accept"
    pending = bob_host.item("pending-")
    assert [a["label"] for a in pending["actions"]] == ["Accept", "Decline"]
    assert alice_host.item("job-")["title"].startswith("Waiting for bob")

    assert bob_host.click_notification(bob_host.notifications[0])["ok"] is True
    _wait(lambda: alice._recent)
    assert alice._recent[0].ok, alice._recent[0]

    inbox = tmp_path / "bob" / "inbox"
    for path in paths:
        assert (inbox / path.name).read_bytes() == path.read_bytes()
    bob_host.wait_for(lambda: len(bob_host.notifications) == 2)
    assert bob_host.notifications[1][1] == "Received 3 files from alice (300 KB)"
    assert bob_host.notifications[1][4] == "open-folder"

    recent = alice_host.item("recent")
    assert "Sent 3 files to bob" in recent["subtitle"]
    assert bob_host.card_changed > 0 and alice_host.card_changed > 0

    # "Open folder" opens the download folder itself (not via open_uri).
    result = bob_host.invoke("recent", "open-folder")
    assert result == {"ok": True, "message": None, "open_uri": None}
    assert plugins.opened == [inbox.resolve().as_uri()]

    # A second transfer of the same names does not overwrite.
    alice_host.send_files(targets[0]["id"], [str(paths[1])])
    bob_host.wait_for(lambda: len(bob_host.notifications) == 3)
    bob_host.click_notification(bob_host.notifications[2])
    _wait(lambda: (inbox / "notes (1).txt").exists())


def test_unanswered_request_is_declined_after_the_timeout(tmp_path, plugins) -> None:
    alice, alice_host = plugins("alice")
    _bob, _bob_host = plugins("bob", decision_timeout=0.3)
    _wait(lambda: alice._registry.active())
    target = alice_host.share_targets()[0]["id"]
    alice_host.send_files(target, [str(_files(tmp_path)[1])])
    _wait(lambda: alice._recent)
    assert alice._recent[0].ok is False and alice._recent[0].reason == "rejected"
    assert not list((tmp_path / "bob" / "inbox").glob("*.txt"))
    assert "declined" in alice_host.item("recent")["subtitle"]


def test_decline_button_on_the_card(tmp_path, plugins) -> None:
    alice, alice_host = plugins("alice")
    _bob, bob_host = plugins("bob")
    _wait(lambda: alice._registry.active())
    alice_host.send_files(alice_host.share_targets()[0]["id"], [str(_files(tmp_path)[1])])
    bob_host.wait_for(lambda: bob_host.notifications)
    item = bob_host.item("pending-")
    assert bob_host.invoke(item["id"], "reject")["ok"] is True
    _wait(lambda: alice._recent)
    assert alice._recent[0].reason == "rejected"


def test_trusted_device_is_accepted_without_asking(tmp_path, plugins) -> None:
    alice, alice_host = plugins("alice")
    bob, bob_host = plugins("bob", settings=Settings(auto_accept_trusted=True))
    _wait(lambda: alice._registry.active() and bob._registry.active())
    device_item = bob_host.item("dev-")
    assert device_item["title"] == "alice"
    assert bob_host.invoke(device_item["id"], "trust")["ok"] is True
    assert "trusted" in bob_host.item("dev-")["subtitle"]

    alice_host.send_files(alice_host.share_targets()[0]["id"], [str(_files(tmp_path)[1])])
    _wait(lambda: alice._recent)
    assert alice._recent[0].ok
    assert not any(n[4].startswith("accept-") for n in bob_host.notifications)


def test_a_spoofed_trusted_fingerprint_still_asks(tmp_path, plugins) -> None:
    alice, _alice_host = plugins("alice")
    bob, bob_host = plugins("bob", settings=Settings(auto_accept_trusted=True),
                            decision_timeout=0.3)
    _wait(lambda: bob._registry.active())
    # Bob trusts some fingerprint; a request claims it, but alice's
    # certificate does not match, so bob asks (and times out).
    bob._store.trust("AA" * 32, "iPhone")
    status, _ = bob.receiver.prepare_upload(
        _request({"f1": _offer("f1", "a", b"x")}, fingerprint="AA" * 32)
        .replace(b'"port": 53317', b'"port": %d' % alice.port),
        "127.0.0.1", {},
    )
    assert status == 403
    assert any(n[4].startswith("accept-") for n in bob_host.notifications)


def test_sender_pins_the_receivers_certificate(tmp_path, plugins) -> None:
    alice, _alice_host = plugins("alice")
    _bob, bob_host = plugins("bob")
    _wait(lambda: alice._registry.active())
    device = alice._registry.active()[0]
    client = PeerClient(alice.identity().client_context())
    honest = Peer("127.0.0.1", device.info.port, "https", device.info.fingerprint)
    forged = Peer("127.0.0.1", device.info.port, "https", "00" * 32)
    assert client.verify_peer(honest) is True
    assert client.verify_peer(forged) is False
    with pytest.raises(PeerError) as caught:
        client.prepare_upload(forged, alice.me(), {"f": _offer("f", "a", b"x")})
    assert caught.value.token == "fingerprint"
    assert bob_host.notifications == []


def test_server_refuses_addresses_outside_the_lan(tmp_path, plugins) -> None:
    bob, _host = plugins("bob")
    bob._active_interfaces = [Interface("wlp7s0", "192.168.1.95", "255.255.255.0")]
    client = PeerClient(bob.identity().client_context())
    peer = Peer("127.0.0.1", bob.port, "https", bob.identity().fingerprint)
    with pytest.raises(PeerError):
        client.register(peer, DeviceInfo(alias="x", fingerprint="X"))


def test_card_and_notification_text_in_german(tmp_path, plugins, monkeypatch) -> None:
    monkeypatch.setenv("LANG", "de_CH.UTF-8")
    bob, bob_host = plugins("bob", decision_timeout=5)
    files = {
        f"f{i}": {"id": f"f{i}", "fileName": f"IMG_{i}.HEIC", "size": 4_000_000}
        for i in range(3)
    }
    worker = threading.Thread(target=bob.receiver.prepare_upload, args=(
        json.dumps({"info": {"alias": "iPhone", "fingerprint": "F1", "deviceType": "mobile"},
                    "files": files}).encode(), "127.0.0.1", {}))
    worker.start()
    bob_host.wait_for(lambda: bob_host.notifications)
    assert bob_host.notifications[0][1] == "iPhone möchte 3 Dateien senden (12 MB)"
    assert bob_host.notifications[0][3] == "Annehmen"
    items = bob_host.card_items()
    assert [a["label"] for a in items[0]["actions"]] == ["Annehmen", "Ablehnen"]
    assert items[-1]["title"] == "Letzte Übertragungen"
    assert items[-1]["actions"][0]["label"] == "Ordner öffnen"
    assert any(i["title"] == "iPhone" and i["actions"][0]["label"] == "Gerät vertrauen"
               for i in items)
    bob_host.invoke(items[0]["id"], "reject")
    worker.join(timeout=5)


def test_hidden_plugin_does_not_announce(tmp_path, plugins) -> None:
    bob, bob_host = plugins("bob", settings=Settings(visible=False))
    assert bob._multicast.sent == []
    assert bob_host.item("devices")["subtitle"] == "Hidden: this computer does not answer."


# ---- manifest, settings, packaging -------------------------------------------


def test_manifest_declares_the_surfaces_and_settings(manifest) -> None:
    assert manifest.id == PLUGIN_ID
    assert manifest.api_version == 1 and manifest.api_minor == 2
    assert set(manifest.capabilities) == {"card", "share", "notify"}
    keys = [field.key for field in manifest.config]
    assert keys[:2] == ["device_name", "visible"]
    assert {f.key: f.default for f in manifest.config}["port"] == 53317
    assert {f.key: f.type for f in manifest.config}["pin"] == "secret"


def test_settings_form_masks_the_pin_and_validates(tmp_path, plugins, manifest) -> None:
    bob, _host = plugins("bob")
    client = PluginClient(manifest, transport=ServiceTransport(bob))
    assert client.set_config({"require_pin": True}).errors == {
        "pin": "set a PIN or turn the PIN off"}
    assert client.set_config({"pin": "12ab"}).errors == {"pin": "must be 4 to 12 digits"}
    assert client.set_config({"interfaces": "wlp7s0; eth0"}).ok
    assert client.set_config({"require_pin": True, "pin": "4711"}).ok
    values = client.get_config()
    assert values["pin"] == "********" and values["require_pin"] is True
    assert values["interfaces"] == "wlp7s0, eth0"
    stored = SettingsStore(tmp_path / "bob" / "config")
    assert stored.load().pin == "4711"
    assert oct(stored.path.stat().st_mode & 0o777) == "0o600"


def test_plugin_imports_only_the_plugin_api_from_blueferry() -> None:
    package = Path(__file__).parents[1] / "src" / "blueferry_localsend"
    for source in package.glob("*.py"):
        tree = ast.parse(source.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name == "blueferry" or name.startswith("blueferry."):
                    assert name.startswith("blueferry.plugin_api"), (source.name, name)


def test_install_writes_activation_and_autostart(tmp_path, manifest, monkeypatch) -> None:
    written = cli.install_activation(tmp_path / "data")
    assert [p.name for p in written] == [
        f"{PLUGIN_ID}.plugin", f"io.weirdware.BlueFerry.Plugin.{PLUGIN_ID}.service",
    ]
    assert "serve" in written[1].read_text()
    autostart = cli.set_autostart(True, tmp_path / "config")
    assert autostart.read_text().startswith("[Desktop Entry]")
    cli.set_autostart(False, tmp_path / "config")
    assert not autostart.exists()
    assert "card;share;notify;" in manifest_text()


def test_all_surfaces_live_on_plugin1() -> None:
    from blueferry.plugin_api import PLUGIN_INTERFACE

    from blueferry_localsend.surfaces import SurfacesService

    table = SurfacesService._dbus_class_table[
        f"{SurfacesService.__module__}.{SurfacesService.__name__}"
    ]
    assert set(table) - {"org.freedesktop.DBus.Introspectable"} == {PLUGIN_INTERFACE}
    members = set(table[PLUGIN_INTERFACE])
    assert {"GetCardItems", "CardChanged", "InvokeAction", "ShareTargets", "SendFiles",
            "Notify", "GetInfo", "Status"} <= members
    assert table[PLUGIN_INTERFACE]["SendFiles"]._dbus_in_signature == "sas"
    assert table[PLUGIN_INTERFACE]["Notify"]._dbus_signature == "sssss"
