# blueferry-plugin-localsend

Native LocalSend protocol for BlueFerry: send and receive files without the
LocalSend app.

A plugin for [BlueFerry](https://github.com/joshii-h/blueferry) that speaks
the [LocalSend protocol v2](https://github.com/localsend/protocol) itself.
Your iPhone (or any device running LocalSend) sees this computer as a
LocalSend device, and BlueFerry can send files to it. It runs as its own
process on the session bus and talks to BlueFerry only through
`blueferry.plugin_api` (plugin API 1.3: capabilities `card`, `share` and
`notify`, a guided settings form with "Test connection"; see `PLUGINS.md`
in the BlueFerry repository).

> **On the iPhone, LocalSend must be open (in the foreground) to receive.**
> iOS suspends the app in the background, so it neither announces itself nor
> accepts files. Sending *from* the iPhone works whenever this computer is
> visible.

## What it does

- **Receiving.** An HTTPS server on port 53317 (configurable) answers
  LocalSend's `register`, `info`, `prepare-upload`, `upload` and `cancel`.
  A request shows up as a BlueFerry notification ("iPhone wants to send 3
  files (12 MB)") with *Accept*, and as an item on the phone card with
  *Accept* and *Decline*. Without an answer it is declined after 60 seconds.
  Files go to `~/Downloads/iPhone` (configurable).
- **Sending.** The devices LocalSend discovered are BlueFerry share targets,
  e.g. "Joshua's iPhone (LocalSend)" in *Send to…*, the tray, the terminal
  client or `blueferry send FILE --to localsend`. Progress appears on the
  card; the transfer can be cancelled there.
- **Card.** *Discovered devices* (with *Trust device*), *Recent transfers*
  (with *Open folder*), pending requests and running transfers.
- **Discovery.** Multicast announcements on `224.0.0.167:53317`, answered with
  `POST /api/localsend/v2/register` (multicast answer as fallback).
  Optionally a legacy HTTP scan of the own subnet (at most a /22) when
  multicast finds nothing.

Not implemented: the download API (section 5 of the spec, browser downloads
over plain HTTP) and sending to devices that require a PIN.

**Protocol version.** The plugin speaks v2.2 and announces `"version":
"2.2"`. The only change from 2.1 is the `422` answer to an upload whose
SHA-256 does not match the one sent in `prepare-upload`; the receiver
already checks it, and the sender now reports it as a damaged file. Peers
announcing any 2.x are accepted. The v3 draft (nonce exchange, signed
tokens, `/api/localsend/v3`) is not implemented: devices announcing 3.x are
ignored until LocalSend apps ship it.

## Install

```sh
blueferry plugins install https://github.com/joshii-h/blueferry-plugin-localsend
```

or pick "LocalSend" in BlueFerry's settings, Plugins. BlueFerry shows source,
version, capabilities and the command it will run, and installs only after
you confirm. This plugin needs a BlueFerry with plugin API 1.3 (0.8.1 or
newer from the branch with guided settings).

BlueFerry starts plugins on first use. To be reachable right after login,
also start the receiver with the session:

```sh
blueferry plugins localsend autostart on
```

Open TCP and UDP port 53317 for your LAN if you run a host firewall.

## Configure

In BlueFerry's settings, Plugins > LocalSend > Settings, or
`blueferry plugins config io.weirdware.blueferry.localsend --set KEY=VALUE`.

| Setting | Meaning |
| --- | --- |
| `device_name` | Name shown to other devices; empty uses the host name. |
| `visible` | Answer discovery and accept requests. Off: the computer is invisible and receives nothing; discovered devices can still be sent to. |
| `download_dir` | Target folder; empty uses `~/Downloads/iPhone`. |
| `max_size_mb` | Requests above this total size are declined (default 4096). |
| `auto_accept_trusted` | Accept devices marked with *Trust device* without asking. |
| `require_pin`, `pin` | Senders must enter this PIN (4 to 12 digits); the PIN field shows only while `require_pin` is on. |
| `port` | TCP and UDP port (default 53317, like LocalSend). |
| `interfaces` | Comma-separated interface names; empty picks the LAN automatically. |
| `http_scan` | Legacy subnet scan when multicast finds nothing. |
| `allow_http_send` | Also send to devices that only offer plain HTTP (default off; nothing pins their identity). |

`blueferry plugins localsend status` shows the name, the certificate
fingerprint, the interfaces in use and the folder;
`blueferry plugins localsend trusted [--remove FINGERPRINT]` lists or removes
trusted devices.

The form groups the settings into Options, Security and Advanced (folded).
**Test connection** checks without saving that a LAN interface is usable,
that the port is free (or already this plugin's: another LocalSend app on
53317 is the usual culprit) and lists the devices it finds, e.g. "Ready on
wlp7s0, port 53317. 1 device(s) found: iPhone." Device names appear only in
that answer, never in the log.

## Security

- **LAN only.** The server binds only to the chosen interfaces. Automatic
  choice takes interfaces that are up, backed by hardware and not
  point-to-point, so loopback, Docker (`docker*`, `br-*`, `veth*`), libvirt and
  VPN tunnels (WireGuard, tun, PPP) are never used; a hard deny-list applies
  even to configured names. Connections and multicast packets from outside
  those interfaces' subnets are dropped.
- **Nothing is received without consent.** Every request needs *Accept*
  unless you trusted the device *and* turned on automatic acceptance. The
  default after 60 seconds is to decline.
- **Trust is bound to a certificate.** Each device has a self-signed
  certificate; its SHA-256 is the LocalSend fingerprint. A request only
  *claims* a fingerprint, so before accepting a trusted device automatically
  the plugin connects back to it and checks that it presents the matching
  certificate. When sending, the receiver's certificate is pinned to the
  announced fingerprint; on a mismatch nothing is sent. Devices that announce
  plain HTTP are not offered as targets (nothing could be pinned) unless
  `allow_http_send` is on.
- **Verified devices.** A device counts as verified only after this plugin
  connected to it over HTTPS and saw the certificate matching its
  fingerprint. Only verified devices get the *trusted* badge and the *Trust
  device* action; an announcement, register or upload request alone never
  replaces or evicts a verified device, so a LAN attacker announcing a
  trusted device's fingerprint with `protocol: "http"` gets neither the badge
  nor the files. The first contact is
  trust-on-first-use: anyone on your LAN can announce a name like "Joshua's
  iPhone", so check the device before you trust it.
- **No overwrites, no escapes.** File names from the sender are cleaned
  (no `..`, no absolute paths, no hidden files, no control characters, no
  symlinked folders); files are written to an owner-only temp file and linked
  to a free name (`photo (1).jpg`), never over an existing file. The size
  announced per file is enforced while receiving, a SHA-256 sent along is
  verified, and the total is limited by `max_size_mb` and free disk space.
- **Limits.** One session at a time, ten upload requests and twenty
  registrations per minute per address, 32 connections and at most four per
  address (a sending phone keeps idle keep-alive connections from discovery
  and the earlier requests, runs the upload on one and cancels on another). Every request has a total deadline (30 s for the request line,
  headers and JSON bodies; uploads get 60 s plus one second per 16 KiB), so a
  client trickling bytes cannot hold a connection open. Card updates caused by discovery are sent at most once a second.
- **Secrets.** The private key and the settings (including the PIN) are in
  owner-only files below
  `~/.config/blueferry/plugins/io.weirdware.blueferry.localsend/`. Logs never
  contain file names, device names or addresses of transfers.
- The PIN is checked over TLS but is a convenience, not strong
  authentication: a LAN attacker can watch you type. Five wrong PINs lock the
  sender's address out for ten minutes.

## Develop

```sh
python3 -m venv --system-site-packages .venv   # dbus-python, PyGObject from the system
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/python -m pytest -q
```

The tests run two plugin instances against each other over HTTPS on
localhost, with an in-memory multicast bus and a fake BlueFerry core
(`tests/fakehost.py`) that checks every reply against the plugin API 1.3
limits. They use the JSON examples of the LocalSend spec and LocalSend's own
certificate test vector. Compatibility with the real LocalSend apps has not
been tested yet.

## License

GPL-2.0-or-later, like BlueFerry. See `LICENSE`.
