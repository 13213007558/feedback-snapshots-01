"""Deterministic fixtures for the OLE boundary matrix.

The production encryption path draws randomness from ``secrets`` via
``msoffcrypto.method.ecma376_agile._random_buffer``. We never replace the
production CSPRNG globally: tests patch ``_random_buffer`` *only* for the
duration of a single fixture build, inside a context manager that restores the
original function afterwards. Outside that window the production randomness is
untouched.

The deterministic source itself is a simple counter-based keystream (SHA-256
in counter mode over a seed), so byte ``i`` of any requested buffer is fully
reproducible from the seed without relying on the library under test.
"""

from __future__ import annotations

import hashlib
import io
from contextlib import contextmanager
from datetime import datetime

from msoffcrypto.method import ecma376_agile as agile
from msoffcrypto.method.container import ecma376_encrypted as container

#: Fixed password used for every fixture.
PASSWORD = "Password1234_"

#: Fixed key-data / verifier salt (16 bytes, the agile salt size).
FIXED_SALT = bytes(range(16))

#: Reduced spin count keeps the matrix fast while still exercising the full
#: password-hashing iteration logic. Production default (100000) is untouched.
FAST_SPIN_COUNT = 2000

#: A 32-byte marker that must never appear in an unused/free sector or in the
#: slack space at the end of a stream's last sector. It is injected into the
#: payload of a *previous* fixture so that any recycled-buffer leak would be
#: observable.
TASK_MARKER = b"PREV-TASK-MARKER-7f3a9c2e1b84d605"[:32].ljust(32, b"!")


class DeterministicRandom:
    """Counter-mode SHA-256 keystream used in place of the production RNG.

    Produces reproducible, well-distributed bytes. It is only ever installed
    temporarily via :func:`deterministic_randomness`.
    """

    def __init__(self, seed: bytes):
        self._seed = seed
        self._counter = 0

    def __call__(self, size: int) -> bytes:
        out = bytearray()
        while len(out) < size:
            block = hashlib.sha256(self._seed + self._counter.to_bytes(8, "little")).digest()
            self._counter += 1
            out.extend(block)
        return bytes(out[:size])


@contextmanager
def deterministic_randomness(seed: bytes):
    """Temporarily route the agile module's RNG through a deterministic source.

    Restores the original :func:`secrets.token_bytes` backed function on exit,
    so production encryption randomness is never altered outside this block.
    """
    original = agile._random_buffer
    rng = DeterministicRandom(seed)
    agile._random_buffer = rng
    try:
        yield rng
    finally:
        agile._random_buffer = original


def make_payload(size: int, seed: bytes = b"payload-seed") -> bytes:
    """Reproducible plaintext 'package' bytes of exactly ``size`` length."""
    return DeterministicRandom(seed + b"::payload")(size)


def encrypt_fixture(payload: bytes, *, marker: bool = False,
                    spin_count: int = FAST_SPIN_COUNT) -> bytes:
    """Encrypt ``payload`` into a complete OLE container deterministically.

    Uses a fixed salt and, for the duration of the call, a deterministic RNG so
    the whole container is reproducible. ``marker`` folds :data:`TASK_MARKER`
    into the payload so a later fixture can prove free sectors carry no trace.
    """
    if marker:
        payload = bytearray(payload)
        for i in range(0, len(payload), max(1, len(payload) // 8 or 1)):
            payload[i:i + len(TASK_MARKER)] = TASK_MARKER
        payload = bytes(payload)

    # The salt argument fixes the password verifier salt; the key-data salt and
    # the random secrets still go through _random_buffer, which we pin here.
    # Directory entries also stamp datetime.now(); freeze it for the call so the
    # whole container (including file times) is reproducible.
    frozen = datetime(2026, 11, 17, 0, 0, 0)

    class _FrozenDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return frozen if tz is None else frozen.replace(tzinfo=tz)

    original_datetime = container.datetime
    container.datetime = _FrozenDatetime
    try:
        with deterministic_randomness(b"agile-rng-seed"):
            return agile.ECMA376Agile.encrypt(
                PASSWORD, io.BytesIO(payload),
                salt_value=FIXED_SALT, spin_count=spin_count,
            )
    finally:
        container.datetime = original_datetime
