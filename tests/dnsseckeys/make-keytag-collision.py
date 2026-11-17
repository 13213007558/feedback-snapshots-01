# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Generate a pair of DNSKEYs with colliding key tags.

The DNSKEY key tag (RFC 4034 appendix B) is a 16-bit checksum, so it is
not a unique identity for a key.  This script generates ECDSAP256SHA256
keys for a fixed owner name until two keys with *different* public keys
share the same key tag, and writes them as BIND-style key files into the
``keytag-collision`` directory next to this script:

    K<name>.+013+<tag>-a.key / .private   (the "legitimate" key)
    K<name>.+013+<tag>-b.key / .private   (the "confusable" key)

The ``-a``/``-b`` suffixes are needed because the usual BIND file name
``K<name>+<alg>+<tag>`` would be identical for both keys -- which is
exactly the point of the regression test using these fixtures.

The generated files are committed test material; this script only needs
to be re-run if the fixtures ever need to be regenerated.
"""

import sys
from pathlib import Path

import dns.dnssec
import dns.name
from dns.dnssecalgs.ecdsa import PrivateECDSAP256SHA256
from dns.dnssecalgs.serialization import Key

OWNER = dns.name.from_text("keytag-collision.example")
OUTPUT_DIRECTORY = Path(__file__).parent / "keytag-collision"


def make_key() -> Key:
    private = PrivateECDSAP256SHA256.generate()
    public = private.public_key()
    dnskey = public.to_dnskey()
    return Key(name=OWNER, private=private, public=public, dnskey=dnskey)


def find_collision() -> tuple[Key, Key, int]:
    seen: dict[int, Key] = {}
    attempts = 0
    while True:
        attempts += 1
        key = make_key()
        tag = key.key_id()
        other = seen.get(tag)
        if other is not None and other.dnskey.key != key.dnskey.key:
            return other, key, attempts
        seen.setdefault(tag, key)


def write_key(key: Key, suffix: str) -> None:
    base = OUTPUT_DIRECTORY / (
        f"K{OWNER.to_text()[:-1]}.+{key.dnskey.algorithm.value:03}"
        f"+{key.key_id():05}-{suffix}"
    )
    # Key.to_bind() cannot be used directly as both keys share the same
    # canonical BIND file name, so render through a temporary stand-in.
    # Note: the base name contains dots, so pathlib suffix manipulation is
    # not safe here; append the extensions as plain strings.
    tmpdir = OUTPUT_DIRECTORY / ".tmp-generate"
    tmpdir.mkdir(exist_ok=True)
    key.to_bind(tmpdir, overwrite=True)
    (tmpdir / key.get_bind_public_key_filename()).replace(Path(str(base) + ".key"))
    (tmpdir / key.get_bind_private_key_filename()).replace(Path(str(base) + ".private"))
    tmpdir.rmdir()


def main() -> None:
    first, second, attempts = find_collision()
    tag = first.key_id()
    assert tag == second.key_id()
    assert first.dnskey.key != second.dnskey.key
    OUTPUT_DIRECTORY.mkdir(exist_ok=True)
    write_key(first, "a")
    write_key(second, "b")
    print(
        f"found collision on key tag {tag} after {attempts} keys; "
        f"wrote fixtures to {OUTPUT_DIRECTORY}"
    )
    # Sanity check: reload from disk and verify the collision survived.
    # Key.from_bind() enforces the canonical BIND file name, which the
    # "-a"/"-b" suffixes intentionally violate, so load the bytes directly.
    stem = f"K{OWNER.to_text()[:-1]}.+013+{tag:05}"
    for suffix in ("a", "b"):
        reloaded = Key.from_bind_bytes(
            private_data=(OUTPUT_DIRECTORY / f"{stem}-{suffix}.private").read_bytes(),
            public_data=(OUTPUT_DIRECTORY / f"{stem}-{suffix}.key").read_bytes(),
        )
        assert reloaded.key_id() == tag
        assert reloaded.private is not None
        assert reloaded.private.public_key().to_dnskey() == reloaded.dnskey
    print("reloaded fixtures verified", file=sys.stderr)


if __name__ == "__main__":
    main()
