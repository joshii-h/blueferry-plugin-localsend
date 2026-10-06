"""Keep tests away from the user's configuration, session bus and LAN."""
from __future__ import annotations

import os
import tempfile

_scratch = tempfile.mkdtemp(prefix="blueferry-localsend-tests-")
for _variable in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
    os.environ[_variable] = os.path.join(_scratch, _variable.lower())
    os.makedirs(os.environ[_variable], mode=0o700, exist_ok=True)
os.environ["XDG_DATA_DIRS"] = os.path.join(_scratch, "system")
os.environ["HOME"] = os.path.join(_scratch, "home")
os.makedirs(os.environ["HOME"], exist_ok=True)
# No test may reach a real bus: the plugin is exercised in-process.
os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/nonexistent/blueferry-localsend-tests"
for _variable in ("LC_ALL", "LC_MESSAGES", "LANGUAGE"):
    os.environ.pop(_variable, None)
os.environ["LANG"] = "C.UTF-8"
