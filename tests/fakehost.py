"""A stand-in for the BlueFerry core side of PLUGIN-SURFACES v1.2.

It calls the plugin's D-Bus methods in-process (no bus), checks every reply
against the limits of the spec, and records the content-free
``CardChanged()`` and the ``Notify(...)`` signals.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from blueferry.plugin_api import manifest as manifest_module

ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SURFACE_CAPABILITIES = frozenset({"card", "share", "notify"})


def accept_api_1_2(monkeypatch) -> None:
    """Make the installed plugin_api parse ``card;share;notify`` like a 1.2 core."""
    known = manifest_module.KNOWN_CAPABILITIES | SURFACE_CAPABILITIES
    monkeypatch.setattr(manifest_module, "KNOWN_CAPABILITIES", known)


class FakeHost:
    def __init__(self, service: Any) -> None:
        self.service = service
        self.card_changed = 0
        self.notifications: list[tuple[str, str, str, str, str]] = []
        self._changed = threading.Condition()
        service.CardChanged = self._on_card_changed
        service.Notify = self._on_notify

    # ---- signals --------------------------------------------------------

    def _on_card_changed(self) -> None:
        with self._changed:
            self.card_changed += 1
            self._changed.notify_all()

    def _on_notify(self, title, body, icon, action_label, action_id) -> None:
        for value in (title, body, icon, action_label, action_id):
            assert isinstance(value, str)
        assert len(title) <= 80 and len(body) <= 160 and len(action_label) <= 40
        with self._changed:
            self.notifications.append((title, body, icon, action_label, action_id))
            self._changed.notify_all()

    def wait_for(self, predicate, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        with self._changed:
            while not predicate():
                remaining = deadline - time.monotonic()
                assert remaining > 0, "timed out waiting for the plugin"
                self._changed.wait(min(remaining, 0.05))

    # ---- calls ----------------------------------------------------------

    def _call(self, method: str, *args: Any) -> Any:
        outcome: dict[str, Any] = {}
        getattr(self.service, method)(
            *args,
            reply=lambda value: outcome.setdefault("reply", value),
            error=lambda error: outcome.setdefault("error", error),
            sender=":1.host",
        )
        if "error" in outcome:
            raise outcome["error"]
        return json.loads(outcome["reply"])

    def card_items(self) -> list[dict]:
        value = self._call("GetCardItems")
        items = value["items"]
        assert isinstance(items, list) and len(items) <= 8
        for item in items:
            assert ID.fullmatch(item["id"]), item["id"]
            assert isinstance(item["icon"], str) and item["icon"]
            assert isinstance(item["title"], str) and 0 < len(item["title"]) <= 80
            assert item["subtitle"] is None or len(item["subtitle"]) <= 160
            assert len(item["actions"]) <= 3
            for action in item["actions"]:
                assert ID.fullmatch(action["id"])
                assert 0 < len(action["label"]) <= 40
                assert action["kind"] in ("button", "primary")
        return items

    def item(self, prefix: str) -> dict | None:
        return next((i for i in self.card_items() if i["id"].startswith(prefix)), None)

    def invoke(self, item_id: str, action_id: str, args: dict | None = None) -> dict:
        value = self._call("InvokeAction", item_id, action_id, json.dumps(args or {}))
        assert isinstance(value["ok"], bool)
        uri = value["open_uri"]
        assert uri is None or uri.startswith(("https://", "http://", "file://"))
        return value

    def click_notification(self, notification: tuple) -> dict:
        return self.invoke("notify", notification[4])

    def share_targets(self) -> list[dict]:
        targets = self._call("ShareTargets")["targets"]
        for target in targets:
            assert ID.fullmatch(target["id"]) and target["label"] and target["icon"]
        return targets

    def send_files(self, target_id: str, paths: list[str]) -> dict:
        value = self._call("SendFiles", target_id, paths)
        assert isinstance(value["ok"], bool)
        return value
