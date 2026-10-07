"""Settings and trusted devices in an owner-only ``config.json``.

The optional PIN is the only secret. It is a short LAN code, not an account
credential, so it lives in the same 0600 file (the fallback PLUGINS.md
allows) and never appears in logs, D-Bus replies or the manifest.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from blueferry_localsend import PLUGIN_ID
from blueferry_localsend.protocol import DEFAULT_PORT

MAX_FILE_BYTES = 64 * 1024
MAX_TRUSTED = 64


class SettingsError(Exception):
    pass


def config_dir() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return Path(config_home) / "blueferry" / "plugins" / PLUGIN_ID


def default_download_dir() -> Path:
    return Path(os.path.expanduser("~")) / "Downloads" / "iPhone"


def default_device_name() -> str:
    return (socket.gethostname().split(".")[0] or "BlueFerry")[:64]


@dataclass(frozen=True, slots=True)
class Settings:
    device_name: str = ""
    visible: bool = True
    port: int = DEFAULT_PORT
    interfaces: str = ""
    download_dir: str = ""
    max_size_mb: int = 4096
    pin: str = ""
    require_pin: bool = False
    auto_accept_trusted: bool = False
    http_scan: bool = False
    # Plain HTTP pins no certificate: anyone on the LAN can claim the device.
    allow_http_send: bool = False
    # fingerprint (uppercase hex) -> alias at the time it was trusted
    trusted: dict[str, str] = field(default_factory=dict)

    @property
    def alias(self) -> str:
        return self.device_name or default_device_name()

    @property
    def target_dir(self) -> Path:
        if self.download_dir:
            return Path(os.path.expanduser(self.download_dir))
        return default_download_dir()

    @property
    def max_bytes(self) -> int:
        return self.max_size_mb * 1024 * 1024

    def is_trusted(self, fingerprint: str) -> bool:
        return fingerprint.upper() in self.trusted


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise SettingsError("config directory has the wrong owner or type")
    path.chmod(0o700)


class SettingsStore:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or config_dir()
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self.directory / "config.json"

    @property
    def identity_dir(self) -> Path:
        return self.directory / "identity"

    def load(self) -> Settings:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return Settings()
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise SettingsError("config.json has the wrong owner or type")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise SettingsError("config.json is readable by other users")
            text = stream.read(MAX_FILE_BYTES + 1)
        if len(text) > MAX_FILE_BYTES:
            raise SettingsError("config.json is too large")
        try:
            raw = json.loads(text)
        except ValueError:
            raise SettingsError("config.json is not valid JSON") from None
        if not isinstance(raw, dict):
            raise SettingsError("config.json is not an object")
        return _from_dict(raw)

    def save(self, settings: Settings) -> None:
        with self._lock:
            _private_dir(self.directory)
            descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.directory)
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                    descriptor = -1
                    json.dump(asdict(settings), stream, indent=2)
                    stream.write("\n")
                os.replace(temporary, self.path)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                Path(temporary).unlink(missing_ok=True)

    def trust(self, fingerprint: str, alias: str) -> Settings:
        settings = self.load()
        trusted = dict(settings.trusted)
        trusted[fingerprint.upper()] = alias[:64]
        if len(trusted) > MAX_TRUSTED:
            raise SettingsError("too many trusted devices")
        settings = replace(settings, trusted=trusted)
        self.save(settings)
        return settings

    def untrust(self, fingerprint: str) -> Settings:
        settings = self.load()
        trusted = {k: v for k, v in settings.trusted.items() if k != fingerprint.upper()}
        settings = replace(settings, trusted=trusted)
        self.save(settings)
        return settings


def _from_dict(raw: dict) -> Settings:
    defaults = Settings()

    def pick(key: str, kind: type):
        value = raw.get(key, getattr(defaults, key))
        if kind is int and (isinstance(value, bool) or not isinstance(value, int)):
            return getattr(defaults, key)
        if not isinstance(value, kind):
            return getattr(defaults, key)
        return value

    trusted_raw = raw.get("trusted", {})
    trusted = {
        str(k).upper(): str(v)[:64]
        for k, v in (trusted_raw.items() if isinstance(trusted_raw, dict) else ())
        if isinstance(k, str) and 0 < len(k) <= 128
    }
    port = pick("port", int)
    return Settings(
        device_name=pick("device_name", str)[:64],
        visible=pick("visible", bool),
        port=port if 1024 <= port <= 65535 else DEFAULT_PORT,
        interfaces=pick("interfaces", str),
        download_dir=pick("download_dir", str),
        max_size_mb=max(1, pick("max_size_mb", int)),
        pin=pick("pin", str),
        require_pin=pick("require_pin", bool),
        auto_accept_trusted=pick("auto_accept_trusted", bool),
        http_scan=pick("http_scan", bool),
        allow_http_send=pick("allow_http_send", bool),
        trusted=dict(list(trusted.items())[:MAX_TRUSTED]),
    )
