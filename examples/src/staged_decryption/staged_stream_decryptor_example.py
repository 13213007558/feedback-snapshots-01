# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Local demonstration of authenticity-gated staged decryption.

The standard streaming decryptor (``client.stream(mode="d", ...)``) emits each
frame's plaintext as soon as that frame is processed, before the whole archive
has been authenticated.  Some archives may only be *published* once the entire
message (including its message-level signature, when present) has been verified.

``client.stream(mode="decrypt-staged", ...)`` returns a
:class:`aws_encryption_sdk.StagedStreamDecryptor`.  Decrypted plaintext is kept in
a controlled staging area (an in-memory buffer that spills to a private temporary
file once a configurable memory threshold is crossed) and the caller can read
nothing until final authentication succeeds.  On interruption or verification
failure the staging data is destroyed and no publishable plaintext is produced.

Everything in this script runs locally: the "archive" is generated in a temporary
directory and a static raw AES master key provider is used, so no network or AWS
calls are required.

Run it directly::

    python examples/src/staged_decryption/staged_stream_decryptor_example.py
"""
import glob
import io
import os
import secrets
import tempfile

import attr

import aws_encryption_sdk
from aws_encryption_sdk.identifiers import (
    Algorithm,
    CommitmentPolicy,
    EncryptionKeyType,
    WrappingAlgorithm,
)
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKeyProviderConfig
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider


# A deliberately small threshold so a normal-sized archive demonstrably spills to disk.
MEMORY_THRESHOLD = 1024


@attr.s(hash=False)
class StaticRawMasterKeyProviderConfig(MasterKeyProviderConfig):
    static_key = attr.ib()


class StaticRawMasterKeyProvider(RawMasterKeyProvider):
    """Raw master key provider backed by a single locally held static AES key."""

    provider_id = "local-static"
    _config_class = StaticRawMasterKeyProviderConfig

    def _get_raw_key(self, key_id):
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=self.config.static_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def build_key_provider(static_key):
    provider = StaticRawMasterKeyProvider(static_key=static_key)
    provider.add_master_key(b"archive-key")
    return provider


def make_archive(client, key_provider, plaintext):
    """Encrypt an in-memory archive with a *signed* algorithm suite."""
    # A signed suite makes "final authentication" observable: the signature in the
    # message footer is the last thing verified before any staged data is released.
    ciphertext, header = client.encrypt(
        source=plaintext,
        key_provider=key_provider,
        frame_length=256,
        algorithm=Algorithm.AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384,
    )
    return ciphertext, header


def print_publishable(label, first_data_at, staged):
    """Report when the caller first receives publishable data."""
    print("  {:<28} first publishable byte at: {}".format(label, first_data_at))
    print("  {:<28} authenticated={} staged_bytes={} on_disk={}".format(
        "state", staged.authenticated, staged.staged_bytes, staged.staging_on_disk
    ))


def demo_legacy_streaming(client, key_provider, ciphertext):
    """Show that the legacy streaming path yields plaintext before end-of-message."""
    print("\n[1] Legacy streaming (mode='d'): plaintext flows frame by frame")
    seen = 0
    first_byte_at = None
    with client.stream(mode="d", source=io.BytesIO(ciphertext), key_provider=key_provider) as decryptor:
        for chunk in decryptor:
            if first_byte_at is None and chunk:
                first_byte_at = decryptor.tell()
            seen += len(chunk)
    print("  first publishable byte at: {} (well before the {} byte message ends)".format(
        first_byte_at, seen
    ))


def demo_staged_success(client, key_provider, ciphertext, staging_dir):
    """Show that staged decryption releases data only after full authentication."""
    print("\n[2] Staged streaming (mode='decrypt-staged'): gated until authenticated")
    staged = client.stream(
        mode="decrypt-staged",
        source=io.BytesIO(ciphertext),
        key_provider=key_provider,
        staging_spool_size=MEMORY_THRESHOLD,
        staging_dir=staging_dir,
    )

    # Before the first read nothing has been demanded and no plaintext is publishable.
    print("  before read():               authenticated={} publishable_bytes=0".format(staged.authenticated))

    # The first read drives the entire underlying message to completion internally;
    # it only returns once the footer signature has been verified.
    first = staged.read(64)
    print_publishable("first read(64) ->", len(first), staged)
    print("  staging file while open:     {}".format(staged.staging_path))
    print("  spill beyond {} byte threshold: {}".format(MEMORY_THRESHOLD, staged.staging_on_disk))

    rest = staged.read()
    staged.close()
    print("  total published bytes:       {}".format(len(first) + len(rest)))
    print("  staging files after close:   {}".format(glob.glob(os.path.join(staging_dir, "*")) or "none"))
    return first + rest


def demo_staged_truncation(client, key_provider, ciphertext, staging_dir):
    """An interrupted (truncated) archive never produces publishable data."""
    print("\n[3] Staged streaming on an interrupted (truncated) archive")
    truncated = ciphertext[: len(ciphertext) // 2]
    error = None
    published = None
    staging_path = None
    try:
        with client.stream(
            mode="decrypt-staged",
            source=io.BytesIO(truncated),
            key_provider=key_provider,
            staging_spool_size=MEMORY_THRESHOLD,
            staging_dir=staging_dir,
        ) as staged:
            try:
                published = staged.read()
            except Exception as exc:  # noqa: broad-except; the demo only reports the failure type
                error = "{}: {}".format(type(exc).__name__, str(exc).splitlines()[0][:70])
            staging_path = staged.staging_path
    except Exception as exc:  # noqa: broad-except; close() surfaces the unfinished message
        error = error or "{} on close: {}".format(type(exc).__name__, str(exc).splitlines()[0][:60])
    # Exiting the with block always closes and removes the staging data, even on failure.
    print("  verification result:         {}".format(error or "unexpectedly succeeded"))
    print("  bytes the caller could read: {}".format(0 if published is None else len(published)))
    print("  staging file cleaned up:     {}".format(
        staging_path is None or not os.path.exists(staging_path)
    ))


def demo_staged_bad_signature(client, key_provider, ciphertext, staging_dir):
    """A tampered footer signature fails final authentication; staged data is discarded."""
    print("\n[4] Staged streaming on a message whose final signature is invalid")
    # Discover the footer signature region from a good parse, then flip a byte
    # inside the signature so every frame still verifies but final auth fails.
    with client.stream(mode="d", source=io.BytesIO(ciphertext), key_provider=key_provider) as probe:
        probe.read()
        signature_length = len(probe.footer.signature)
    signature_offset = len(ciphertext) - signature_length
    tampered = bytearray(ciphertext)
    tampered[signature_offset + signature_length // 2] ^= 0xFF
    error = None
    published = None
    spilled_while_open = False
    staging_path = None
    try:
        with client.stream(
            mode="decrypt-staged",
            source=io.BytesIO(bytes(tampered)),
            key_provider=key_provider,
            staging_spool_size=MEMORY_THRESHOLD,
            staging_dir=staging_dir,
        ) as staged:
            try:
                published = staged.read()
            except Exception as exc:  # noqa: broad-except; the demo only reports the failure type
                # Final authentication (footer signature verification) fails on read().
                error = "{}: signature verification rejected the message".format(type(exc).__name__)
            spilled_while_open = staged.staging_on_disk
            staging_path = staged.staging_path
    except Exception as exc:  # noqa: broad-except; close() reports the unfinished message
        close_error = "{} on close".format(type(exc).__name__)
        error = error or close_error
    # Exiting the with block discards the staged plaintext regardless of the failure.
    print("  verification result:         {}".format(error or "unexpectedly succeeded"))
    print("  data had spilled to disk:    {}".format(spilled_while_open))
    print("  bytes the caller could read: {}".format(0 if published is None else len(published)))
    print("  staging file cleaned up:     {}".format(
        staging_path is None or not os.path.exists(staging_path)
    ))


def main():
    static_key = secrets.token_bytes(32)
    key_provider = build_key_provider(static_key)
    client = aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )

    # ~16 KB archive: larger than the 1 KB staging threshold, so it spills to disk,
    # but trivially generated and processed locally.
    plaintext = (b"compliance-archive-record-" + b"0123456789abcdef" * 4) * 200
    ciphertext, _ = make_archive(client, key_provider, plaintext)
    print("Generated local archive: {} plaintext bytes -> {} ciphertext bytes".format(
        len(plaintext), len(ciphertext)
    ))

    staging_dir = tempfile.mkdtemp(prefix="esdk-staged-demo-")
    print("Controlled staging directory: {}".format(staging_dir))

    demo_legacy_streaming(client, key_provider, ciphertext)
    recovered = demo_staged_success(client, key_provider, ciphertext, staging_dir)
    demo_staged_truncation(client, key_provider, ciphertext, staging_dir)
    demo_staged_bad_signature(client, key_provider, ciphertext, staging_dir)

    assert recovered == plaintext, "staged decryption must return the exact original archive"
    print("\nAll staging files removed: {}".format(glob.glob(os.path.join(staging_dir, "*")) == []))
    print("Observation: legacy streaming exposes data during processing; staged streaming")
    print("exposes the first publishable byte only after the entire archive authenticates.")


if __name__ == "__main__":
    main()
