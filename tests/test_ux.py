"""The everyday flow (0.3): send from the device, see who is there, messages.

Two plugin instances on localhost and the kit's FakeHost, as in
test_plugin; no real multicast, bus, clipboard or file manager.
"""
from __future__ import annotations

import json
import threading

import pytest
from test_plugin import _files, _wait, manifest, plugins  # noqa: F401 - fixtures

from blueferry_localsend import discovery as discovery_module
from blueferry_localsend import service as service_module
from blueferry_localsend.protocol import DeviceInfo
from blueferry_localsend.settings import Settings


def _pair(plugins):
    alice, alice_host = plugins("alice")
    bob, bob_host = plugins("bob")
    _wait(lambda: alice._registry.active() and bob._registry.active())
    return alice, alice_host, bob, bob_host


def test_send_files_right_from_the_device_on_the_card(tmp_path, plugins) -> None:
    alice, alice_host, _bob, bob_host = _pair(plugins)
    device = alice_host.item("dev-")
    send = device["actions"][0]
    assert (send["id"], send["kind"], send["label"]) == ("send", "primary", "Send files…")
    # The action names the same target "Send to…" lists.
    assert send["send_to"] == alice_host.share_targets()[0]["id"]
    picked = _files(tmp_path)[1]
    answer = alice_host.send_action(device["id"], "send", [str(picked)])
    assert answer["ok"] is True and answer["job"]
    bob_host.wait_for(lambda: bob_host.notifications)
    bob_host.click_notification(bob_host.notifications[0])
    _wait(lambda: alice._recent)
    assert alice._recent[0].ok
    assert (tmp_path / "bob" / "inbox" / picked.name).read_bytes() == picked.read_bytes()
    # A BlueFerry without plugin API 1.4 would invoke the action instead.
    old = alice_host.invoke(device["id"], "send")
    assert old["ok"] is False and "Send to" in old["message"]


def test_this_computer_never_lists_itself(tmp_path, plugins) -> None:
    """The LocalSend app on the same computer announces from our address."""
    bob, bob_host = plugins("bob", own_addresses=lambda: ["127.0.0.1"])
    app_here = json.dumps({
        "alias": "Solid Pear", "version": "2.1", "deviceModel": "Linux",
        "deviceType": "desktop", "fingerprint": "FF" * 32, "port": 53317,
        "protocol": "https", "announce": True,
    }).encode()
    bob._on_datagram(app_here, "127.0.0.1")
    assert bob._registry.active() == []
    item = bob_host.item("devices")
    assert item["title"] == "No devices found"
    assert [a["id"] for a in item["actions"]] == ["search"]
    assert bob_host.invoke("devices", "search")["ok"] is True


def test_probes_verify_devices_and_mark_the_ones_that_left(tmp_path, plugins, monkeypatch):
    alice, alice_host = plugins("alice")
    bob, _bob_host = plugins("bob")
    _wait(lambda: alice._registry.active())
    # Only an announcement so far: unverified until someone connects.
    device = alice._registry.active()[0]
    alice._registry.clear()
    alice._registry.seen(device.info, device.address)
    assert "not checked yet" in alice_host.item("dev-")["subtitle"]
    assert [a["id"] for a in alice_host.item("dev-")["actions"]] == ["send"]
    alice.check_devices(0.0)
    item = alice_host.item("dev-")
    assert "ready" in item["subtitle"]
    assert [a["id"] for a in item["actions"]] == ["send", "trust"]
    # Bob quits (an iPhone puts LocalSend to sleep): not answering, a hint.
    bob.stop()
    alice.check_devices(0.0)
    assert "not answering: open LocalSend on the Linux" in alice_host.item("dev-")["subtitle"]
    assert alice_host.card_changed > 0
    # Long gone: forgotten.
    monkeypatch.setattr(discovery_module, "DEVICE_TTL", -1)
    alice.check_devices(0.0)
    assert alice_host.item("devices")["title"] == "No devices found"


def test_the_watcher_runs_until_stop_and_a_restart_keeps_only_one(tmp_path, plugins) -> None:
    bob, _host = plugins("bob", probe_interval=0.05)
    calls = []
    bob.check_devices = lambda quiet_for: calls.append(  # type: ignore[method-assign]
        threading.current_thread())
    bob._start_watcher()
    _wait(lambda: len(calls) >= 2)
    first = bob._watcher
    bob.restart()
    _wait(lambda: calls[-1] is not first)
    threading.Event().wait(0.3)
    assert not first.is_alive()
    assert {thread for thread in calls[-3:]} == {bob._watcher}
    bob.stop()
    count = len(calls)
    threading.Event().wait(0.2)
    assert len(calls) <= count + 1


def test_a_fingerprint_change_forgets_the_device(tmp_path, plugins) -> None:
    alice, _alice_host = plugins("alice")
    _bob, _bob_host = plugins("bob")
    _wait(lambda: alice._registry.active())
    device = alice._registry.active()[0]
    alice._registry.clear()
    forged = DeviceInfo(alias="bob", fingerprint="00" * 32, port=device.info.port)
    alice._registry.seen(forged, device.address, verified=True)
    alice.check_devices(0.0)
    assert alice._registry.by_fingerprint("00" * 32) is None


def test_the_watcher_rebinds_only_when_nothing_is_bound(tmp_path, plugins) -> None:
    _alice, _host = plugins("alice")
    bob, _bob_host = plugins("bob")
    calls = []
    bob.rebind = lambda: calls.append(1) or False  # type: ignore[method-assign]
    bob._port_busy = True  # one address busy, the other one serving
    bob.check_devices(0.0)
    assert calls == []
    bob._servers.stop()
    bob.check_devices(0.0)
    assert calls == [1]


def test_a_busy_port_shows_on_the_card_and_retry_binds_again(tmp_path, plugins) -> None:
    alice, _alice_host = plugins("alice")
    bob, bob_host = plugins("bob")
    bob._port_override = alice.port
    assert bob.rebind() is False
    problem = bob_host.card_items()[0]
    assert problem["id"] == "problem" and "LocalSend app" in problem["subtitle"]
    assert problem["actions"][0]["id"] == "retry"
    assert bob_host.status()["state"] == "error"
    failed = bob_host.invoke("problem", "retry")
    assert failed["ok"] is False and "still in use" in failed["message"]
    alice.stop()
    assert bob_host.invoke("problem", "retry") == {
        "ok": True, "message": "Receiving again", "open_uri": None}
    assert bob_host.card_items()[0]["id"] != "problem"
    assert bob_host.status()["state"] == "ok"


def _message(text: str, *, alias: str = "iPhone") -> bytes:
    data = text.encode()
    return json.dumps({
        "info": {"alias": alias, "fingerprint": "F1", "deviceType": "mobile",
                 "deviceModel": "iPhone"},
        "files": {"m1": {"id": "m1", "fileName": "a.txt", "size": len(data),
                         "fileType": "text/plain", "preview": text}},
    }).encode()


def test_a_text_message_is_shown_and_copied_not_saved(tmp_path, plugins, caplog) -> None:
    bob, bob_host = plugins("bob")
    secret_text = "Treffpunkt 18 Uhr beim Bahnhof"
    status, body = bob.receiver.prepare_upload(_message(secret_text), "127.0.0.1", {})
    assert (status, body) == (204, None)
    assert not (tmp_path / "bob" / "inbox").exists() or not any(
        (tmp_path / "bob" / "inbox").iterdir())
    _title, popup, _icon, label, _action = bob_host.notifications[-1]
    assert popup == "iPhone sent a message" and label == "Copy"
    assert secret_text not in popup  # the text stays off the session bus
    item = bob_host.item("msg-")
    assert item["title"] == "Message from iPhone" and item["subtitle"] == secret_text
    assert [a["id"] for a in item["actions"]] == ["copy", "dismiss"]
    assert bob_host.click_notification()["message"] == "Copied to the clipboard"
    assert plugins.copied == [secret_text]
    assert bob_host.invoke(item["id"], "dismiss")["ok"] is True
    assert bob_host.item("msg-") is None
    assert secret_text not in caplog.text
    assert bob_host.invoke(item["id"], "copy")["ok"] is False


def test_a_shared_link_opens_only_from_a_verified_device(tmp_path, plugins) -> None:
    bob, bob_host = plugins("bob")
    bob.receiver.prepare_upload(_message("https://example.org/a?b=1"), "127.0.0.1", {})
    item = bob_host.item("msg-")
    # Only claimed so far: anyone on the LAN can send a text.
    assert [a["id"] for a in item["actions"]] == ["copy", "dismiss"]
    assert bob_host.invoke(item["id"], "open")["ok"] is False
    sender = bob._registry.by_fingerprint("F1")
    bob._registry.answered("F1", sender.address, verified=True)
    item = bob_host.item("msg-")
    assert [a["id"] for a in item["actions"]] == ["copy", "open", "dismiss"]
    assert bob_host.invoke(item["id"], "open")["open_uri"] == "https://example.org/a?b=1"


def test_a_long_text_is_a_file_not_a_message(tmp_path, plugins) -> None:
    from blueferry_localsend.protocol import MAX_MESSAGE_CHARS, parse_prepare_upload

    long_text = "x" * (MAX_MESSAGE_CHARS + 1)
    assert parse_prepare_upload(_message(long_text)).message is None
    # A preview of a longer file (size far larger than the text) is no message.
    raw = json.loads(_message("short"))
    raw["files"]["m1"]["size"] = 999
    assert parse_prepare_upload(json.dumps(raw).encode()).message is None
    # A sender counting UTF-16 or CRLF still sends a message.
    raw["files"]["m1"]["size"] = len("short".encode("utf-16-le"))
    assert parse_prepare_upload(json.dumps(raw).encode()).message == "short"


def test_receiving_can_be_cancelled_on_the_card(tmp_path, plugins) -> None:
    alice, _alice_host, bob, bob_host = _pair(plugins)
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 1024)
    session_ready = threading.Event()

    def accept_when_asked() -> None:
        bob_host.wait_for(lambda: bob_host.notifications)
        bob_host.click_notification(bob_host.notifications[0])
        session_ready.set()

    # Keep the upload from starting: answer prepare-upload only.
    from blueferry_localsend.client import Peer, PeerClient

    device = alice._registry.active()[0]
    peer = Peer("127.0.0.1", device.info.port, "https", device.info.fingerprint)
    helper = threading.Thread(target=accept_when_asked)
    helper.start()
    PeerClient(alice.identity().client_context()).prepare_upload(
        peer, alice.me(), {"f": {"id": "f", "fileName": "big.bin", "size": 1024,
                                 "fileType": "application/octet-stream"}},
    )
    helper.join(10)
    assert session_ready.is_set()
    item = bob_host.item("receiving")
    assert [a["id"] for a in item["actions"]] == ["cancel"]
    assert bob_host.invoke("receiving", "cancel")["message"] == "Receiving cancelled"
    assert bob.receiver.active is None
    assert bob_host.invoke("receiving", "cancel")["ok"] is False


def test_start_at_login_is_a_setting(tmp_path, plugins) -> None:
    _bob, bob_host = plugins("bob")
    assert bob_host.get_config()["values"]["autostart"] is False
    assert bob_host.set_config({"autostart": True})["ok"] is True
    entry = tmp_path / "bob" / "xdg-config" / "autostart" / (
        "io.weirdware.blueferry.localsend.desktop")
    assert entry.read_text().startswith("[Desktop Entry]")
    assert bob_host.get_config()["values"]["autostart"] is True
    assert bob_host.set_config({"autostart": False})["ok"] is True
    assert not entry.exists()


def test_unreachable_devices_name_the_model(tmp_path, plugins) -> None:
    bob, bob_host = plugins("bob")
    phone = DeviceInfo(alias="Efficient Banana", fingerprint="AB" * 32,
                       device_model="iPhone", device_type="mobile")
    bob._registry.seen(phone, "127.0.0.9")
    bob._registry.unreachable(phone.fingerprint, "127.0.0.9")
    item = bob_host.item("dev-")
    assert item["icon"] == "phone"
    assert item["subtitle"] == (
        "iPhone · not answering: open LocalSend on the iPhone and keep it open")


@pytest.mark.parametrize(("text", "link"), [
    ("https://example.org", True), ("http://x.y/z", True), ("see https://a.b", False),
    ("ftp://x", False), ("https://a.b\nnext", False), ("https://user:pw@host/x", False),
    ("https://a.b/path@x", True), ("https://a.b\tx", False),
])
def test_only_a_bare_web_link_gets_open(text, link) -> None:
    assert service_module._is_web_link(text) is link


def test_settings_default_keeps_auto_accept_off() -> None:
    assert Settings().auto_accept_trusted is False
