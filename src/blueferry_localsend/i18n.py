"""User-visible strings in German and English, picked from the locale."""
from __future__ import annotations

import os

_DE = {
    "devices": "Entdeckte Geräte",
    "no_devices": "Keine. Öffne LocalSend auf dem iPhone.",
    "invisible": "Unsichtbar: dieses Gerät antwortet nicht.",
    "recent": "Letzte Übertragungen",
    "no_recent": "Noch nichts übertragen.",
    "open_folder": "Ordner öffnen",
    "trust": "Gerät vertrauen",
    "untrust": "Nicht mehr vertrauen",
    "trusted": "vertraut",
    "accept": "Annehmen",
    "reject": "Ablehnen",
    "cancel": "Abbrechen",
    "wants_to_send": "{name} möchte {count} Dateien senden ({size})",
    "wants_to_send_one": "{name} möchte 1 Datei senden ({size})",
    "received": "{count} Dateien von {name} empfangen ({size})",
    "received_one": "1 Datei von {name} empfangen ({size})",
    "sent": "{count} Dateien an {name} gesendet ({size})",
    "sent_one": "1 Datei an {name} gesendet ({size})",
    "receiving": "Empfange von {name}: {percent} % ({done} von {size})",
    "sending": "Sende an {name}: {percent} % ({done} von {size})",
    "waiting": "Warte auf {name}: Anfrage auf dem Gerät annehmen",
    "failed_send": "Senden an {name} fehlgeschlagen: {reason}",
    "failed_receive": "Empfang von {name} abgebrochen",
    "accepted": "Angenommen",
    "rejected": "Abgelehnt",
    "trusted_now": "{name} wird vertraut",
    "untrusted_now": "{name} wird nicht mehr vertraut",
    "target_label": "{name} (LocalSend)",
    "sending_started": "Sende {count} Datei(en) an {name}",
    "unknown_target": "Gerät nicht mehr im Netz; LocalSend auf dem Gerät öffnen",
    "no_files": "Keine lesbaren Dateien",
    "busy": "Es läuft schon eine Übertragung",
    "reason_rejected": "abgelehnt",
    "reason_pin": "das Gerät verlangt eine PIN",
    "reason_busy": "das Gerät ist beschäftigt",
    "reason_network": "Gerät nicht erreichbar",
    "reason_fingerprint": "Zertifikat passt nicht zum Gerät",
    "reason_cancelled": "abgebrochen",
    "reason_error": "Fehler beim Gerät",
    "ok_listening": "Empfang auf {where}",
    "no_interface": "Keine LAN-Schnittstelle gefunden",
    "localsend": "LocalSend",
}

_EN = {
    "devices": "Discovered devices",
    "no_devices": "None. Open LocalSend on the iPhone.",
    "invisible": "Hidden: this computer does not answer.",
    "recent": "Recent transfers",
    "no_recent": "Nothing transferred yet.",
    "open_folder": "Open folder",
    "trust": "Trust device",
    "untrust": "Stop trusting",
    "trusted": "trusted",
    "accept": "Accept",
    "reject": "Decline",
    "cancel": "Cancel",
    "wants_to_send": "{name} wants to send {count} files ({size})",
    "wants_to_send_one": "{name} wants to send 1 file ({size})",
    "received": "Received {count} files from {name} ({size})",
    "received_one": "Received 1 file from {name} ({size})",
    "sent": "Sent {count} files to {name} ({size})",
    "sent_one": "Sent 1 file to {name} ({size})",
    "receiving": "Receiving from {name}: {percent}% ({done} of {size})",
    "sending": "Sending to {name}: {percent}% ({done} of {size})",
    "waiting": "Waiting for {name}: accept the request on the device",
    "failed_send": "Sending to {name} failed: {reason}",
    "failed_receive": "Receiving from {name} was cancelled",
    "accepted": "Accepted",
    "rejected": "Declined",
    "trusted_now": "{name} is trusted",
    "untrusted_now": "{name} is no longer trusted",
    "target_label": "{name} (LocalSend)",
    "sending_started": "Sending {count} file(s) to {name}",
    "unknown_target": "Device is gone; open LocalSend on it",
    "no_files": "No readable files",
    "busy": "A transfer is already running",
    "reason_rejected": "declined",
    "reason_pin": "the device requires a PIN",
    "reason_busy": "the device is busy",
    "reason_network": "device not reachable",
    "reason_fingerprint": "certificate does not match the device",
    "reason_cancelled": "cancelled",
    "reason_error": "the device reported an error",
    "ok_listening": "Receiving on {where}",
    "no_interface": "No LAN interface found",
    "localsend": "LocalSend",
}


def german() -> bool:
    for variable in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        value = os.environ.get(variable)
        if value:
            return value.split(":")[0].lower().startswith("de")
    return False


def t(key: str, **values: object) -> str:
    table = _DE if german() else _EN
    return table.get(key, _EN.get(key, key)).format(**values)
