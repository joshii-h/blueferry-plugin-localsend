"""Plugin1 v1.2 surfaces: the ``card``, ``share`` and ``notify`` capabilities.

Implemented strictly from the shared spec (PLUGIN-SURFACES-v1.2): plugins
never ship UI, they hand the core JSON and content-free signals.

- ``card``: ``GetCardItems() -> s``, ``InvokeAction(s item, s action, s args) -> s``,
  signal ``CardChanged()``.
- ``share``: ``ShareTargets() -> s``, ``SendFiles(s target, as paths) -> s``.
- ``notify``: signal ``Notify(s title, s body, s icon, s action_label, s action_id)``;
  a click comes back as ``InvokeAction("notify", action_id, "{}")``.

All of them live on the existing ``io.weirdware.BlueFerry.Plugin1``
interface at the plugin's object path (spec section "D-Bus placement"); the
manifest's capabilities tell the core which of them to call.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

import dbus
import dbus.service
from blueferry.plugin_api import PLUGIN_INTERFACE
from blueferry.plugin_api.service import PluginService

MAX_ITEMS = 8
MAX_ACTIONS = 3
MAX_TITLE = 80
MAX_SUBTITLE = 160
MAX_LABEL = 40
MAX_PATHS = 1000


def clip(text: str, limit: int) -> str:
    cleaned = " ".join("".join(ch if ch.isprintable() else " " for ch in text).split())
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


@dataclass(frozen=True, slots=True)
class Action:
    id: str
    label: str
    icon: str | None = None
    kind: str = "button"  # "button" | "primary"

    def to_json(self) -> dict:
        return {"id": self.id, "label": clip(self.label, MAX_LABEL), "icon": self.icon,
                "kind": self.kind}


@dataclass(frozen=True, slots=True)
class CardItem:
    id: str
    icon: str
    title: str
    subtitle: str | None = None
    actions: tuple[Action, ...] = field(default_factory=tuple)

    def to_json(self) -> dict:
        return {
            "id": self.id, "icon": self.icon, "title": clip(self.title, MAX_TITLE),
            "subtitle": clip(self.subtitle, MAX_SUBTITLE) if self.subtitle else None,
            "actions": [a.to_json() for a in self.actions[:MAX_ACTIONS]],
        }


@dataclass(frozen=True, slots=True)
class ShareTarget:
    id: str
    label: str
    icon: str

    def to_json(self) -> dict:
        return {"id": self.id, "label": clip(self.label, MAX_TITLE), "icon": self.icon}


def action_result(ok: bool, message: str | None = None, open_uri: str | None = None) -> str:
    return json.dumps({"ok": ok, "message": message, "open_uri": open_uri})


class SurfacesService(PluginService):
    """Base class for a plugin with the card, share and notify capabilities."""

    # ---- hooks (worker thread unless noted) -----------------------------

    def card_items(self) -> list[CardItem]:
        return []

    def invoke_action(self, item_id: str, action_id: str, args: dict) -> str:
        return action_result(False, "unknown action")

    def share_targets(self) -> list[ShareTarget]:
        return []

    def send_files(self, target_id: str, paths: list[str]) -> dict:
        return {"ok": False, "message": "sending is not supported", "job": None}

    # ---- emitting (main loop) -------------------------------------------

    def emit_card_changed(self) -> None:
        self._to_main(self.CardChanged)

    def emit_notify(
        self, title: str, body: str, icon: str, action_label: str = "", action_id: str = "",
    ) -> None:
        values = (clip(title, MAX_TITLE), clip(body, MAX_SUBTITLE), icon,
                  clip(action_label, MAX_LABEL), action_id)
        self._to_main(lambda: self.Notify(*values))

    # ---- card -----------------------------------------------------------

    @dbus.service.method(
        PLUGIN_INTERFACE, in_signature="", out_signature="s",
        async_callbacks=("reply", "error"), sender_keyword="sender",
    )
    def GetCardItems(self, reply, error, sender=None) -> None:
        self.admit(sender)
        self.run_async(
            lambda: json.dumps({"items": [i.to_json() for i in self.card_items()[:MAX_ITEMS]]}),
            reply, error,
        )

    @dbus.service.method(
        PLUGIN_INTERFACE, in_signature="sss", out_signature="s",
        async_callbacks=("reply", "error"), sender_keyword="sender",
    )
    def InvokeAction(self, item_id, action_id, args_json, reply, error, sender=None) -> None:
        self.admit(sender)
        item, action, raw = str(item_id)[:128], str(action_id)[:128], str(args_json)[:16384]

        def work() -> str:
            try:
                args = json.loads(raw or "{}")
            except ValueError:
                args = {}
            return self.invoke_action(item, action, args if isinstance(args, dict) else {})

        self.run_async(work, reply, error)

    @dbus.service.signal(PLUGIN_INTERFACE, signature="")
    def CardChanged(self) -> None:
        """Content-free; the core calls GetCardItems again."""

    # ---- share ----------------------------------------------------------

    @dbus.service.method(
        PLUGIN_INTERFACE, in_signature="", out_signature="s",
        async_callbacks=("reply", "error"), sender_keyword="sender",
    )
    def ShareTargets(self, reply, error, sender=None) -> None:
        self.admit(sender)
        self.run_async(
            lambda: json.dumps({"targets": [t.to_json() for t in self.share_targets()]}),
            reply, error,
        )

    @dbus.service.method(
        PLUGIN_INTERFACE, in_signature="sas", out_signature="s",
        async_callbacks=("reply", "error"), sender_keyword="sender",
    )
    def SendFiles(self, target_id, paths, reply, error, sender=None) -> None:
        self.admit(sender)
        target = str(target_id)[:128]
        files = [str(p) for p in list(paths)[:MAX_PATHS]]
        self.run_async(lambda: json.dumps(self.send_files(target, files)), reply, error)

    # ---- notify ---------------------------------------------------------

    @dbus.service.signal(PLUGIN_INTERFACE, signature="sssss")
    def Notify(self, title, body, icon, action_label, action_id) -> None:
        """A desktop notification request; the core applies its policy."""
