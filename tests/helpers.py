"""Shared test helpers."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _request(files: dict, fingerprint: str = "PEER") -> bytes:
    info = {**json.loads(fixture("register.json")), "fingerprint": fingerprint}
    return json.dumps({"info": info, "files": files}).encode()


def _offer(file_id: str, name: str, data: bytes, *, sha: bool = True) -> dict:
    offer = {"id": file_id, "fileName": name, "size": len(data), "fileType": "text/plain"}
    if sha:
        offer["sha256"] = hashlib.sha256(data).hexdigest()
    return offer


