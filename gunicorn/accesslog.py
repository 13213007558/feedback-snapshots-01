#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Access log redaction.

The access log format is chosen by the application, so the fields it can
write are not known in advance. This module applies one policy to the atoms
the logger builds, whatever format is configured:

- credential-bearing headers are always replaced with ``[REDACTED]``,
  however they are named and whichever way the format refers to them
  (``{authorization}i``, ``{http_authorization}e``, ``{x-api-key}i`` ...);
- fields the operator selects with ``access_log_redact`` are replaced too,
  including the standard atoms and any named request header, response
  header, environment variable or query parameter;
- a selected field redacts the fields derived from it, so choosing the
  query string also covers the request line that contains it and choosing
  one duration atom covers all four.

The request and response objects are only read. Their headers and the
application's environ are never changed.
"""

import re
from urllib.parse import unquote_plus

REDACTED = "[REDACTED]"

# Standard access_log_format atoms (the table in the access_log_format
# setting). These are the one-character entries access_log_redact accepts.
STANDARD_ATOMS = frozenset("hlutrsmUqHbfaTDMLp")

_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_CUSTOM_ATOM_RE = re.compile(r"\{(%s)\}([ioe])" % _TOKEN)
_NAME_RE = re.compile(_TOKEN)
_CUSTOM_KEY_RE = re.compile(r"\{(%s)\}([ioe])$" % _TOKEN)

# Atoms that show the same value or the same request information, and names
# they are also reachable under. Selecting either side selects the other.
_ATOM_NAMES = {
    "u": ("user", "authorization"),
    "f": ("referer",),
    "a": ("user-agent",),
    "h": ("remote-addr",),
    "r": ("raw-uri", "request-uri"),
    "U": ("path-info",),
    "q": ("query-string",),
    "m": ("request-method",),
    "H": ("server-protocol",),
}
_NAME_ATOMS = {
    "user": ("u",),
    "remote-user": ("u",),
    "authorization": ("u",),
    "referer": ("f",),
    "user-agent": ("a",),
    "remote-addr": ("h",),
    "raw-uri": ("r",),
    "request-uri": ("r",),
    "path-info": ("U",),
    "query-string": ("q",),
    "request-method": ("m",),
    "server-protocol": ("H",),
    "response-length": ("B", "b"),
    "duration": ("T", "D", "M", "L"),
}

# One value carries the whole duration, so hiding any of the four hides all.
_DURATION_ATOMS = frozenset("TDML")
# The same response length, written as a number or as the CLF value.
_LENGTH_ATOMS = frozenset("Bb")
# The request line holds the path and the query string.
_URI_ATOMS = frozenset("rUq")

# Name pieces that mark a credential. A header, environment variable or
# query parameter whose name contains one of these is always redacted.
_CREDENTIAL_TOKENS = frozenset("""
    auth authentication authorization bearer credential credentials cookie
    cookies csrf jwt passphrase passwd password secret secrets session
    sessionid sig signature token tokens xsrf
""".split())
_CREDENTIAL_NAMES = frozenset("""
    apikey accesstoken refreshtoken idtoken csrftoken xsrftoken
""".split())


def normalize_name(name):
    """Case-fold a header, environ or query name for comparison."""
    return name.strip().lower().replace("_", "-")


def header_name_for_env(name):
    """The header a WSGI environ name is derived from, if any."""
    if name.startswith("http-"):
        return name[len("http-"):]
    return name


def _name_tokens(name):
    """Split a field name into lowercase words for credential matching."""
    # authToken, sessionID and password2 name the same thing as auth_token,
    # session-id and password.
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", name)
    return set(part for part in re.split(r"[-._\d]+", name.lower()) if part)


def is_credential_name(name):
    """Whether a header, environ or query name carries a credential."""
    # Keep the case here: it is what tells authToken apart from authtoken.
    name = name.strip().replace("_", "-")
    if not name:
        return False
    if name.lower() in _CREDENTIAL_NAMES:
        return True
    parts = _name_tokens(name)
    if parts & _CREDENTIAL_TOKENS:
        return True
    # api_key / apiKey / x-goog-api-key and friends.
    if "api" in parts and "key" in parts:
        return True
    return False


def validate_access_log_redaction(val):
    """Validate the access_log_redact setting.

    Accepts a comma-separated string or a list of entries. An entry is a
    standard atom (``u``, ``q``, ``U``, ``r`` ...), a header, environment or
    query name (``authorization``, ``x-api-key`` ...), or an explicit custom
    atom (``{authorization}i``, ``{set-cookie}o``, ``{http_authorization}e``).
    """
    if val is None:
        return []
    if isinstance(val, str):
        entries = val.split(",")
    elif isinstance(val, (list, tuple)):
        entries = []
        for item in val:
            if not isinstance(item, str):
                raise TypeError("Not a string: %s" % (item,))
            entries.extend(item.split(","))
    else:
        raise TypeError("Invalid type for casting: %s" % (val,))

    fields = []
    seen = set()
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if len(entry) == 1:
            if entry not in STANDARD_ATOMS:
                raise ValueError(
                    "Unknown access log atom %r; name a field instead, "
                    "such as 'authorization'" % (entry,))
            field = entry
        elif _CUSTOM_ATOM_RE.fullmatch(entry):
            field = entry.lower()
        elif _NAME_RE.fullmatch(entry):
            field = entry.lower()
        else:
            raise ValueError(
                "Invalid access log redaction field: %r" % (entry,))
        if field not in seen:
            seen.add(field)
            fields.append(field)
    return fields


class AccessLogRedactor:
    """Apply the access log redaction policy to a set of atoms."""

    def __init__(self, fields=()):
        self.fields = tuple(fields or ())
        self.atoms = set()
        self.names = set()
        for field in self.fields:
            if len(field) == 1 and field in STANDARD_ATOMS:
                self.atoms.add(field)
            elif _CUSTOM_ATOM_RE.fullmatch(field):
                name, _kind = _CUSTOM_ATOM_RE.fullmatch(field).groups()
                self.names.add(normalize_name(name))
            else:
                self.names.add(normalize_name(field))
        self._expand()

    def _expand(self):
        """Close selected atoms and names over the fields they cover."""
        changed = True
        while changed:
            changed = False
            before = (len(self.atoms), len(self.names))

            for atom in list(self.atoms):
                for name in _ATOM_NAMES.get(atom, ()):
                    self.names.add(normalize_name(name))
            for name in list(self.names):
                for atom in _NAME_ATOMS.get(name, ()):
                    self.atoms.add(atom)

            # The request line, the path and the query string expose the
            # same URI data: hiding one hides the others.
            if self.atoms & _URI_ATOMS:
                self.atoms |= _URI_ATOMS

            # Duration and length atoms are the same value under different
            # units or formats.
            if self.atoms & _DURATION_ATOMS:
                self.atoms |= _DURATION_ATOMS
            if self.atoms & _LENGTH_ATOMS:
                self.atoms |= _LENGTH_ATOMS

            if before != (len(self.atoms), len(self.names)):
                changed = True

        # An operator naming an environ form selects the header form too.
        for name in list(self.names):
            header = header_name_for_env(name)
            if header != name:
                self.names.add(header)

    @staticmethod
    def _placeholder(value):
        return value is None or value == "" or value == "-"

    def _custom_redacted(self, key):
        match = _CUSTOM_KEY_RE.fullmatch(key)
        if match is None:
            return False
        name, kind = match.groups()
        name = normalize_name(name)
        if name in self.names:
            return True
        if kind == "e":
            header = header_name_for_env(name)
            if header in self.names:
                return True
            # REMOTE_ADDR and HTTP_X_API_KEY appear as remote-addr and
            # x-api-key in a log, and are matched the same way.
            if is_credential_name(name):
                return True
            return header != name and is_credential_name(header)
        return is_credential_name(name)

    def _query_name_redacted(self, name):
        try:
            name = unquote_plus(name)
        except Exception:
            pass
        normalized = normalize_name(name)
        return (normalized in self.names
                or is_credential_name(normalized))

    def _scrub_query(self, query):
        """Redact sensitive values in a query string, keeping its names.

        Keeping the parameter names and the other values means a log line
        still tells an operator which endpoint was called with which
        non-sensitive parameters, without recording the credential.
        """
        if not query:
            return query
        parts = re.split(r"([&;])", query)
        changed = False
        for index in range(0, len(parts), 2):
            segment = parts[index]
            if not segment or "=" not in segment:
                continue
            name, value = segment.split("=", 1)
            if value and self._query_name_redacted(name):
                parts[index] = name + "=" + REDACTED
                changed = True
        return "".join(parts) if changed else query

    def _scrub_target(self, target):
        if "?" not in target:
            return target
        path, query = target.split("?", 1)
        scrubbed = self._scrub_query(query)
        if scrubbed == query:
            return target
        return path + "?" + scrubbed

    def _scrub_atom(self, key, value):
        if not isinstance(value, str):
            return value
        if key == "q":
            return self._scrub_query(value)
        if key == "r":
            parts = value.split(" ")
            if len(parts) < 3:
                return value
            parts[-2] = self._scrub_target(parts[-2])
            return " ".join(parts)
        if key.startswith("{"):
            match = _CUSTOM_KEY_RE.fullmatch(key)
            if match is None or match.group(2) != "e":
                return value
            name = normalize_name(match.group(1))
            if name == "query-string":
                return self._scrub_query(value)
            if name in ("raw-uri", "request-uri"):
                return self._scrub_target(value)
        return value

    def redact(self, atoms):
        """Return a copy of ``atoms`` with the policy applied."""
        if not atoms:
            return atoms
        redacted = dict(atoms)
        for key, value in atoms.items():
            if key.startswith("{"):
                if self._custom_redacted(key):
                    if not self._placeholder(value):
                        redacted[key] = REDACTED
                    continue
            else:
                # The user name is decoded from the Authorization header.
                # That header is credential-bearing whichever way a format
                # writes it, so the derived atom goes with it.
                selected = key in self.atoms or key == "u"
                if selected:
                    if not self._placeholder(value):
                        redacted[key] = REDACTED
                    continue
            scrubbed = self._scrub_atom(key, value)
            if scrubbed != value:
                redacted[key] = scrubbed
        return redacted
