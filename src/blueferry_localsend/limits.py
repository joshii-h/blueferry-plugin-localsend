"""Limits against slow clients: a total deadline per request and a cap on
connections per address.

A socket timeout alone restarts with every byte, so a client that trickles
one byte every few seconds ("slowloris") keeps a connection, and with it one
of the few server slots, open forever. :class:`DeadlineReader` sets the
socket timeout to the time that is *left* before each read instead.
"""
from __future__ import annotations

import io
import math
import socket
import threading
import time
from collections.abc import Callable


class DeadlineReader(io.RawIOBase):
    """Raw reader over a socket that gives up at a deadline.

    :meth:`start` sets a fixed deadline (request line, headers, small
    bodies). :meth:`stream` is for large bodies: the deadline is ``grace``
    seconds plus one second per ``min_rate`` bytes received, so a real
    transfer of any size finishes, but a trickle does not.
    """

    def __init__(
        self, sock: socket.socket, idle: float, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        self._sock = sock
        self._idle = idle
        self._clock = clock
        self._deadline = math.inf
        self._rate = 0.0
        self._streamed = 0

    def start(self, seconds: float) -> None:
        self._deadline = self._clock() + seconds
        self._rate = 0.0

    def stream(self, grace: float, min_rate: float) -> None:
        self._deadline = self._clock() + grace
        self._rate = min_rate
        self._streamed = 0

    def remaining(self) -> float:
        extra = self._streamed / self._rate if self._rate else 0.0
        return self._deadline + extra - self._clock()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:  # type: ignore[override]
        remaining = self.remaining()
        if remaining <= 0:
            raise TimeoutError("request deadline passed")
        self._sock.settimeout(min(remaining, self._idle))
        count = self._sock.recv_into(buffer)
        self._streamed += count
        return count


def deadline_rfile(sock: socket.socket, idle: float) -> tuple[DeadlineReader, io.BufferedReader]:
    reader = DeadlineReader(sock, idle)
    return reader, io.BufferedReader(reader)


class ConnectionsPerAddress:
    """At most ``limit`` open connections per client address."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self._open: dict[str, int] = {}

    def acquire(self, address: str) -> bool:
        with self._lock:
            count = self._open.get(address, 0)
            if count >= self._limit:
                return False
            self._open[address] = count + 1
            return True

    def release(self, address: str) -> None:
        with self._lock:
            count = self._open.get(address, 0) - 1
            if count > 0:
                self._open[address] = count
            else:
                self._open.pop(address, None)
