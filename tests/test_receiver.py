"""Receiving without sockets: safe names, limits, tokens, PIN."""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
from helpers import _offer, _request, fixture

from blueferry_localsend import files as fs
from blueferry_localsend.protocol import DeviceInfo
from blueferry_localsend.server import Policy, Receiver

# ---- file names and limits --------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("photo.jpg", "photo.jpg"),
    ("../../.ssh/authorized_keys", "_ssh/authorized_keys"),
    ("/etc/passwd", "etc/passwd"),
    ("a/../../b.txt", "a/b.txt"),
    ("..\\..\\windows\\win.ini", "windows/win.ini"),
    (".bashrc", "_bashrc"),
    ("bad\x1bname\u202e.txt", "bad_name_.txt"),
    ("..", None),
    ("/", None),
    ("x\x00y", None),
])
def test_file_names_cannot_escape(name, expected) -> None:
    if expected is None:
        with pytest.raises(fs.UnsafePath):
            fs.safe_relative_path(name)
    else:
        assert str(fs.safe_relative_path(name)) == expected


def test_long_names_keep_their_suffix() -> None:
    name = str(fs.safe_relative_path("x" * 500 + ".jpeg"))
    assert name.endswith(".jpeg") and len(name.encode()) <= fs.MAX_COMPONENT_BYTES


def test_symlinked_subdirectory_is_refused(tmp_path) -> None:
    root, outside = tmp_path / "in", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "sub").symlink_to(outside)
    with pytest.raises(fs.UnsafePath):
        fs.target_parent(root, fs.safe_relative_path("sub/evil.txt"))


def test_existing_files_are_never_overwritten(tmp_path) -> None:
    (tmp_path / "a.jpg").write_text("old")
    (tmp_path / "a (1).jpg").write_text("older")
    descriptor, temporary = fs.open_temporary(tmp_path)
    os.write(descriptor, b"new")
    os.close(descriptor)
    path = fs.commit(temporary, tmp_path, "a.jpg")
    assert path.name == "a (2).jpg" and path.read_bytes() == b"new"
    assert (tmp_path / "a.jpg").read_text() == "old"
    assert not temporary.exists()


def test_human_sizes() -> None:
    assert fs.human_size(12_000_000) == "12 MB"
    assert fs.human_size(1_500_000, german=True) == "1,5 MB"


# ---- receiver without sockets -----------------------------------------------


class _Recv:
    def __init__(self, tmp_path: Path, *, accept: bool = True, max_bytes: int = 10_000,
                 pin: str = "", visible: bool = True) -> None:
        self.root = tmp_path / "inbox"
        self.asked: list = []
        self.changes = 0
        self.receiver = Receiver(
            me=lambda: DeviceInfo(alias="me", fingerprint="ME"),
            policy=lambda: Policy(self.root, max_bytes, pin, visible),
            decide=lambda request, address: self.asked.append(request) or accept,
            on_register=lambda info, address: None,
            on_change=lambda session: setattr(self, "changes", self.changes + 1),
        )

    def prepare(self, files: dict, address: str = "10.0.0.2", query: dict | None = None):
        return self.receiver.prepare_upload(_request(files), address, query or {})

    def upload(self, session, file_id, token, data, *, address="10.0.0.2", length=None):
        return self.receiver.upload(
            {"sessionId": session, "fileId": file_id, "token": token}, address,
            io.BytesIO(data), len(data) if length is None else length, False,
        )


def test_upload_lands_in_the_target_folder_under_a_safe_name(tmp_path) -> None:
    recv = _Recv(tmp_path)
    data = b"hello"
    status, answer = recv.prepare({"f1": _offer("f1", "../../../evil.sh", data)})
    assert status == 200
    assert recv.upload(answer["sessionId"], "f1", answer["files"]["f1"], data) == 200
    assert (recv.root / "evil.sh").read_bytes() == data
    assert not list(tmp_path.glob("evil.sh"))
    assert recv.receiver.active is None  # session finished


def test_request_over_the_size_limit_is_declined_without_asking(tmp_path) -> None:
    recv = _Recv(tmp_path, max_bytes=100)
    status, _ = recv.prepare({"f1": {"id": "f1", "fileName": "big", "size": 101}})
    assert status == 403 and recv.asked == []


def test_more_bytes_than_announced_are_refused(tmp_path) -> None:
    recv = _Recv(tmp_path)
    _, answer = recv.prepare({"f1": _offer("f1", "a.txt", b"abc", sha=False)})
    token = answer["files"]["f1"]
    # Content-Length must match the announced size …
    assert recv.upload(answer["sessionId"], "f1", token, b"abcdef") == 400
    # … and a chunked body cannot smuggle more either.
    chunked = io.BytesIO(b"6\r\nabcdef\r\n0\r\n\r\n")
    status = recv.receiver.upload(
        {"sessionId": answer["sessionId"], "fileId": "f1", "token": token}, "10.0.0.2",
        chunked, None, True,
    )
    assert status == 400
    assert not [p for p in recv.root.iterdir() if p.is_file()]


def test_checksum_token_address_and_pin_are_enforced(tmp_path) -> None:
    recv = _Recv(tmp_path)
    _, answer = recv.prepare({"f1": _offer("f1", "a.txt", b"abc")})
    session, token = answer["sessionId"], answer["files"]["f1"]
    assert recv.upload(session, "f1", "wrong", b"abc") == 403
    assert recv.upload(session, "f1", token, b"abc", address="10.0.0.9") == 403
    assert recv.upload(session, "f1", token, b"abd") == 422
    assert not [p for p in recv.root.iterdir() if p.is_file()]
    assert recv.upload(session, "f1", token, b"abc") == 200

    pinned = _Recv(tmp_path / "pin", pin="4711")
    files = {"f1": _offer("f1", "a.txt", b"abc")}
    assert pinned.prepare(files)[0] == 401
    assert pinned.prepare(files, query={"pin": "1234"})[0] == 401
    assert pinned.prepare(files, query={"pin": "4711"})[0] == 200


def test_second_session_is_blocked_and_cancel_ends_the_first(tmp_path) -> None:
    recv = _Recv(tmp_path)
    _, first = recv.prepare({"f1": _offer("f1", "a.txt", b"abc")})
    assert recv.prepare({"f1": _offer("f1", "b.txt", b"abc")}, address="10.0.0.3")[0] == 409
    assert recv.receiver.cancel({"sessionId": first["sessionId"]}, "10.0.0.3") == 403
    assert recv.receiver.cancel({"sessionId": first["sessionId"]}, "10.0.0.2") == 200
    assert recv.prepare({"f1": _offer("f1", "b.txt", b"abc")}, address="10.0.0.3")[0] == 200


def test_declined_and_rate_limited_requests(tmp_path) -> None:
    recv = _Recv(tmp_path, accept=False)
    statuses = [recv.prepare({"f1": _offer("f1", "a", b"x")})[0] for _ in range(12)]
    assert statuses[:10] == [403] * 10 and statuses[10:] == [429, 429]


def test_hidden_receiver_does_not_answer_discovery(tmp_path) -> None:
    recv = _Recv(tmp_path, visible=False)
    assert recv.receiver.info()[0] == 404
    assert recv.receiver.register(fixture("register.json"), "10.0.0.2")[0] == 404
