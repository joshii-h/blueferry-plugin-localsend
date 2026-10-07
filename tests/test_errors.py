"""The kit's file errors surface under this plugin's own names."""
from __future__ import annotations

import os

import pytest

from blueferry_localsend.settings import SettingsError, SettingsStore
from blueferry_localsend.tls import IdentityError, load_identity


def test_unsafe_config_raises_settings_error(tmp_path) -> None:
    directory = tmp_path / "conf"
    directory.mkdir(mode=0o700)
    path = directory / "config.json"
    path.write_text("{}")
    os.chmod(path, 0o644)
    with pytest.raises(SettingsError) as caught:
        SettingsStore(directory).load()
    assert type(caught.value).__name__ == "SettingsError"


def test_unsafe_identity_raises_identity_error(tmp_path) -> None:
    directory = tmp_path / "identity"
    load_identity(directory)
    os.chmod(directory / "key.pem", 0o644)
    with pytest.raises(IdentityError) as caught:
        load_identity(directory)
    assert type(caught.value).__name__ == "IdentityError"
