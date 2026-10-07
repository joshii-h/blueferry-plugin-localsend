"""Keep tests away from the user's configuration, session bus and LAN."""
from __future__ import annotations

import os

from blueferry_plugin_kit.testing import isolate_environment

_scratch = isolate_environment(
    "blueferry-localsend-tests-", bus_name="blueferry-localsend-tests",
)
os.environ["HOME"] = os.path.join(_scratch, "home")
os.makedirs(os.environ["HOME"], exist_ok=True)
for _variable in ("LC_ALL", "LC_MESSAGES", "LANGUAGE"):
    os.environ.pop(_variable, None)
os.environ["LANG"] = "C.UTF-8"
