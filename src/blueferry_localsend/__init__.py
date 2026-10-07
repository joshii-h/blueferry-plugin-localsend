"""BlueFerry plugin: the LocalSend protocol, natively.

Imports only ``blueferry.plugin_api`` from BlueFerry.
"""
from __future__ import annotations

from importlib import resources

PLUGIN_ID = "io.weirdware.blueferry.localsend"
__version__ = "0.1.2"


def manifest_text() -> str:
    return (
        resources.files(__name__).joinpath(f"{PLUGIN_ID}.plugin").read_text(encoding="utf-8")
    )
