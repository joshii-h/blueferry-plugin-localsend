"""How the bus, BlueFerry and the session start this plugin.

The D-Bus service file and the manifest name the command; the optional
autostart entry starts the receiver at login, so the iPhone finds this
computer before any BlueFerry client has asked the plugin for its card.
"""
from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path

from blueferry_localsend import PLUGIN_ID

ENTRY_POINT = "blueferry-localsend"


def config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def command() -> list[str]:
    """How the bus and BlueFerry should start this plugin."""
    beside = Path(sys.executable).parent / ENTRY_POINT
    if beside.is_file() and os.access(beside, os.X_OK):
        return [str(beside)]
    installed = shutil.which(ENTRY_POINT)
    if installed:
        return [installed]
    import blueferry.plugin_api as api

    roots = [
        str(Path(__file__).resolve().parents[1]),
        str(Path(api.__file__).resolve().parents[2]),
    ]
    return [
        "/usr/bin/env", "PYTHONPATH=" + ":".join(dict.fromkeys(roots)),
        sys.executable, "-m", "blueferry_localsend",
    ]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.chmod(0o644)
    os.replace(temporary, path)


def autostart_path(home: Path | None = None) -> Path:
    return (home or config_home()) / "autostart" / f"{PLUGIN_ID}.desktop"


def autostart_enabled(home: Path | None = None) -> bool:
    return autostart_path(home).exists()


def set_autostart(enabled: bool, home: Path | None = None) -> Path:
    """Receiving needs the process running from login, not only on first use."""
    path = autostart_path(home)
    if not enabled:
        path.unlink(missing_ok=True)
        return path
    write(path, "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Name=BlueFerry LocalSend",
        "Comment=Receive files from LocalSend devices",
        "Exec=" + shlex.join([*command(), "serve"]),
        "NoDisplay=true",
        "X-KDE-autostart-phase=2",
        "",
    ]))
    return path
