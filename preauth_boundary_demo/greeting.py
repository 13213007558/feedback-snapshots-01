"""IMAP greeting parsing: the server's *self-reported* connection status.

RFC 9051 section 3: on a fresh connection the server sends exactly one
greeting, which is one of:

* ``* OK ...``   -> the connection is not authenticated (``NONAUTH``), a
  LOGIN/AUTHENTICATE exchange is still required;
* ``* PREAUTH ...`` -> the server *claims* the connection is already
  authenticated (``AUTH``);
* ``* BYE ...``  -> the server refuses the connection.

Two things matter for security and are easy to get wrong:

1. ``PREAUTH`` carries no independently verifiable user proof. The free text
   after the status token is just human-readable commentary. It must never be
   parsed into a username or treated as an identity assertion -- note how
   ``PREAUTH as admin`` and ``PREAUTH user=root`` prove nothing by
   themselves. The guarantee, if any, comes from the *transport* the greeting
   arrived on, and from local policy about that transport.
2. The greeting status is orthogonal to the transport. A plaintext, an
   unverified-TLS and a verified-TLS connection can all send any of the three
   greetings. This module therefore reports what the server said and leaves
   the trust decision to :mod:`preauth_boundary_demo.policy`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class GreetingStatus(str, Enum):
    OK = "OK"
    PREAUTH = "PREAUTH"
    BYE = "BYE"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class Greeting:
    """A parsed connection greeting.

    ``raw`` is kept for logging/auditing. ``asserted_user`` is always
    ``None`` on purpose: identity is intentionally *not* extracted from the
    welcome text, however tempting (e.g. ``PREAUTH user=alice``).
    """

    status: GreetingStatus
    raw: str
    asserted_user: Optional[str] = None

    @property
    def server_claims_preauth(self) -> bool:
        return self.status is GreetingStatus.PREAUTH


def parse_greeting(raw_line: bytes | str) -> Greeting:
    """Parse the first server line into a :class:`Greeting`.

    The parser only recognises the RFC status token in its proper position.
    Substrings elsewhere (for example ``OK`` appearing inside commentary) do
    not count, and the human-readable text is never turned into a user.
    """

    if isinstance(raw_line, bytes):
        text = raw_line.decode("utf-8", errors="replace")
    else:
        text = raw_line
    line = text.strip()

    if not line.startswith("*"):
        return Greeting(GreetingStatus.MALFORMED, line)

    tokens = line.split(None, 2)
    # tokens[0] == "*", tokens[1] == status token
    if len(tokens) < 2:
        return Greeting(GreetingStatus.MALFORMED, line)

    status_token = tokens[1].upper()
    try:
        status = GreetingStatus(status_token)
    except ValueError:
        return Greeting(GreetingStatus.MALFORMED, line)

    return Greeting(status=status, raw=line)
