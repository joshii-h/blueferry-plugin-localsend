"""``blueferry-localsend serve|install|status|trusted|autostart``."""
from __future__ import annotations

import argparse
import logging
import os
import shlex
import sys
from pathlib import Path

from blueferry.plugin_api.manifest import ManifestError, default_directories, parse_manifest
from blueferry_plugin_kit.netaddr import lan_interfaces, parse_interface_list

from blueferry_localsend import PLUGIN_ID, manifest_text
from blueferry_localsend.autostart import (
    ENTRY_POINT,
    autostart_path,
    set_autostart,
)
from blueferry_localsend.autostart import command as _command
from blueferry_localsend.autostart import write as _write
from blueferry_localsend.settings import SettingsError, SettingsStore
from blueferry_localsend.tls import IdentityError, load_identity

# The receiver must keep running; the base class would exit after 10 idle minutes.
FOREVER = 10 ** 9


def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")


def load_manifest(text: str | None = None):
    try:
        return parse_manifest(text or manifest_text())
    except ManifestError as error:
        raise ManifestError(
            f"{error} (this plugin needs a BlueFerry with plugin API 1.4: card actions "
            "that send files, ReplacesTools and the plugin log)"
        ) from None


def install_activation(data_home: Path | None = None) -> list[Path]:
    """Write the user manifest and D-Bus service file unless the system has them."""
    data_home = data_home or _data_home()
    template = load_manifest()
    written: list[Path] = []
    system = [d for d in default_directories() if not str(d).startswith(str(data_home))]
    if not any((directory / f"{PLUGIN_ID}.plugin").exists() for directory in system):
        command = _command()
        text = manifest_text().replace(
            f"Exec={ENTRY_POINT} serve", "Exec=" + shlex.join([*command, "serve"]),
        ).replace(f"Cli={ENTRY_POINT}", "Cli=" + shlex.join(command))
        load_manifest(text)
        target = data_home / "blueferry" / "plugins" / f"{PLUGIN_ID}.plugin"
        _write(target, text)
        written.append(target)
        service = data_home / "dbus-1" / "services" / f"{template.bus_name}.service"
        _write(service, "[D-BUS Service]\nName={}\nExec={}\n".format(
            template.bus_name, shlex.join([*command, "serve"]),
        ))
        written.append(service)
    return written


def serve() -> int:
    from blueferry.plugin_api.service import run

    from blueferry_localsend.service import LocalSendService

    try:
        manifest = load_manifest()
    except ManifestError as error:
        print(error, file=sys.stderr)
        return 1

    def make(bus):
        from gi.repository import GLib

        service = LocalSendService(manifest, bus)

        def start() -> bool:
            # Runs once the bus name is ours: a second copy never binds ports.
            service.start()
            return False

        GLib.idle_add(start)
        return service

    return run(make, idle_seconds=FOREVER)


def status(store: SettingsStore) -> int:
    try:
        settings = store.load()
        identity = load_identity(store.identity_dir)
    except (SettingsError, IdentityError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    print(f"Name:        {settings.alias}")
    print(f"Visible:     {'yes' if settings.visible else 'no'}")
    print(f"Fingerprint: {identity.fingerprint}")
    print(f"Port:        {settings.port}")
    print(f"Folder:      {settings.target_dir}")
    interfaces = lan_interfaces(parse_interface_list(settings.interfaces))
    print("Interfaces:  " + (", ".join(f"{i.name} ({i.address})" for i in interfaces)
                             or "none"))
    print(f"Trusted:     {len(settings.trusted)} device(s)")
    print(f"Autostart:   {'on' if autostart_path().exists() else 'off'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=ENTRY_POINT, description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve", help="serve on the session bus and the LAN")
    install = commands.add_parser("install", help="install the manifest and D-Bus activation")
    install.add_argument("--autostart", action="store_true", help="also start at login")
    commands.add_parser("status", help="show name, fingerprint, interfaces and folder")
    trusted = commands.add_parser("trusted", help="list or remove trusted devices")
    trusted.add_argument("--remove", metavar="FINGERPRINT")
    auto = commands.add_parser("autostart", help="start the receiver at login")
    auto.add_argument("state", choices=["on", "off"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    store = SettingsStore()

    if args.command == "serve":
        return serve()
    if args.command == "install":
        try:
            for path in install_activation():
                print(f"Installed {path}")
        except ManifestError as error:
            print(error, file=sys.stderr)
            return 1
        if args.autostart:
            print(f"Installed {set_autostart(True)}")
        return 0
    if args.command == "status":
        return status(store)
    if args.command == "autostart":
        path = set_autostart(args.state == "on")
        print(("Installed " if args.state == "on" else "Removed ") + str(path))
        return 0
    try:
        if args.remove:
            store.untrust(args.remove)
            print("Removed.")
            return 0
        for fingerprint, alias in store.load().trusted.items():
            print(f"{fingerprint}  {alias}")
    except (SettingsError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
