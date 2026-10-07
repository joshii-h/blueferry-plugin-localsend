"""The kit's FakeHost, with this suite's names.

:class:`blueferry_plugin_kit.testing.FakeHost` plays the BlueFerry core side
of PLUGIN-SURFACES v1.2: it calls the plugin's D-Bus methods in-process (no
bus), checks every reply against the limits of the spec, and records the
content-free ``CardChanged()`` and the ``Notify(...)`` signals.
"""
from __future__ import annotations

from blueferry.plugin_api import manifest as manifest_module
from blueferry_plugin_kit import testing

SURFACE_CAPABILITIES = frozenset({"card", "share", "notify"})


def accept_api_1_2(monkeypatch) -> None:
    """Make the installed plugin_api parse ``card;share;notify`` like a 1.2 core."""
    known = manifest_module.KNOWN_CAPABILITIES | SURFACE_CAPABILITIES
    monkeypatch.setattr(manifest_module, "KNOWN_CAPABILITIES", known)


class FakeHost(testing.FakeHost):
    def item(self, prefix: str) -> dict | None:  # type: ignore[override]
        """The first card item whose id starts with ``prefix`` (the kit's ``find``)."""
        return self.find(prefix)
