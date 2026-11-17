# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import asyncio as aio
import os
from collections import deque
from datetime import UTC, datetime
from hashlib import sha256
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from ndn import encoding as enc, types, utils
from ndn.app_support.light_versec import (
    Checker,
    LvsValidatorSwitch,
    compile_lvs,
)
from ndn.app_support.security_v2 import derive_cert
from ndn.security import KeychainSqlite3, TpmFile


LVS_TEXT = r'''
#KEY: "KEY"/_/_/_
#article: "lvs-test"/"article"/author/post <= #author
#author: "lvs-test"/"author"/author/#KEY <= #root
#root: "lvs-test"/#KEY
'''

# A distinct policy domain: different site prefix, so packets of the old
# ``lvs-test`` domain no longer satisfy the policy.
LVS_TEXT_V2 = r'''
#KEY: "KEY"/_/_/_
#article: "lvs-test-v2"/"article"/author/post <= #author
#author: "lvs-test-v2"/"author"/author/#KEY <= #root
#root: "lvs-test-v2"/#KEY
'''

# Pinned so two independently built domains produce byte-identical cert names.
FIXED_VERSION = 1_700_000_000_000
FIXED_KEY_ID = b'fixedkey'


def build_domain(
    base_dir: str,
    identity: str = '/lvs-test',
    author: str = 'alice',
    cert_version: int | None = None,
    key_id: bytes | None = None,
):
    pib_file = os.path.join(base_dir, 'pib.db')
    tpm_dir = os.path.join(base_dir, 'privKeys')
    KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))

    root = keychain.touch_identity(identity)
    root_cert = root.default_key().default_cert()
    root_signer = keychain.get_signer({'cert': root_cert.name})

    author_identity = keychain.touch_identity(f'{identity}/author/{author}')
    if key_id is not None:
        # Recreate the author key with a caller-chosen key id so two domains
        # can carry certificate names that are byte-for-byte identical.
        fixed_key_id = enc.Component.from_bytes(
            key_id, enc.Component.TYPE_GENERIC
        )
        author_key = keychain.new_key(
            author_identity.name, key_id=fixed_key_id
        )
    else:
        author_key = author_identity.default_key()
    patcher = (
        patch(
            'ndn.app_support.security_v2.timestamp',
            return_value=cert_version,
        )
        if cert_version is not None
        else None
    )
    if patcher is not None:
        patcher.start()
    try:
        author_cert_name, author_cert_data = derive_cert(
            author_key.name,
            enc.Component.from_str('root'),
            author_key.key_bits,
            root_signer,
            datetime.now(UTC),
            3600,
        )
    finally:
        if patcher is not None:
            patcher.stop()
    keychain.import_cert(author_key.name, author_cert_name, author_cert_data)
    author_signer = keychain.get_signer({'cert': author_cert_name})

    data_packet = enc.make_data(
        f'{identity}/article/{author}/post',
        enc.MetaInfo(),
        b'content',
        author_signer,
    )
    return keychain, root_cert.data, author_cert_data, data_packet, author_signer


class PendingFetch:
    def __init__(self, name, validator, kwargs, packet):
        self.name = name
        self.validator = validator
        self.kwargs = kwargs
        self.packet = packet
        self.entered = aio.Event()
        self.allow = aio.Event()


class GateApp:
    """An app whose certificate fetches block until the test releases them."""

    def __init__(self, packets: list[enc.BinaryStr] | None = None, gated: bool = False):
        self.packets = self._index(packets or [])
        self.gated = gated
        self.expressed: list[enc.FormalName] = []
        self.pending: deque[PendingFetch] = deque()
        # Append-only log, so a fetch that stays blocked is still visible and
        # later fetches can be awaited without confusing the two.
        self.fetches: list[PendingFetch] = []

    @staticmethod
    def _index(packets):
        return {
            enc.Name.to_bytes(enc.parse_data(packet)[0]): packet
            for packet in packets
        }

    async def wait_for_fetch(self, after: int = 0) -> PendingFetch:
        while len(self.fetches) <= after:
            await aio.sleep(0)
        return self.fetches[after]

    @staticmethod
    def release(fetch: PendingFetch) -> None:
        fetch.allow.set()

    async def express(self, name, validator, **kwargs):
        name = enc.Name.normalize(name)
        self.expressed.append(name)
        lookup_name = name
        implicit_digest = None
        if (
            name
            and enc.Component.get_type(name[-1])
            == enc.Component.TYPE_IMPLICIT_SHA256
        ):
            lookup_name = name[:-1]
            implicit_digest = bytes(enc.Component.get_value(name[-1]))
        try:
            packet = self.packets[enc.Name.to_bytes(lookup_name)]
        except KeyError:
            raise types.InterestTimeout()
        if (
            implicit_digest is not None
            and sha256(bytes(packet)).digest() != implicit_digest
        ):
            raise types.InterestTimeout()

        # Capture the packet before pausing: swapping ``self.packets`` while a
        # fetch is suspended must not change what this fetch validates.
        fetch = PendingFetch(name, validator, kwargs, packet)
        self.fetches.append(fetch)
        if self.gated:
            self.pending.append(fetch)
        fetch.entered.set()
        if self.gated:
            await fetch.allow.wait()
        else:
            fetch.allow.set()
        if self.gated:
            self.pending.remove(fetch)

        data_name, meta_info, content, sig_ptrs = enc.parse_data(fetch.packet)
        context = {
            'meta_info': meta_info,
            'sig_ptrs': sig_ptrs,
            'raw_packet': fetch.packet,
            'deadline': utils.timestamp() + kwargs.get('lifetime', 4000),
        }
        result = await validator(data_name, sig_ptrs, context)
        if result not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
            raise types.ValidationFailure(
                data_name, meta_info, content, sig_ptrs, result
            )
        return data_name, content, context


def checker(text: str = LVS_TEXT) -> Checker:
    return Checker(compile_lvs(text), {})


def parse(packet):
    name, _, _, sig_ptrs = enc.parse_data(packet)
    return name, sig_ptrs, {'deadline': utils.timestamp() + 4000}


class TestLvsValidatorSwitch:
    @staticmethod
    def test_each_request_pins_current_generation_and_uses_own_cache():
        async def scenario():
            with TemporaryDirectory() as base:
                keychain, anchor, author_cert, data_packet, _ = build_domain(base)
                try:
                    app = GateApp([author_cert])
                    switch = LvsValidatorSwitch(checker(), app, anchor)
                    name, sig_ptrs, context = parse(data_packet)
                    gen_one = switch.generation_id

                    assert await switch(name, sig_ptrs, context) is types.ValidResult.PASS
                    assert len(app.expressed) == 1
                    first_storage = switch.current_generation.storage
                    assert first_storage.load(
                        enc.parse_data(author_cert)[0]
                    ) is not None

                    # A no-argument switch still starts a fresh, empty generation.
                    gen_two = switch.switch()
                    assert gen_two == gen_one + 1
                    assert switch.generation(gen_one) is None
                    second_storage = switch.current_generation.storage
                    assert second_storage is not first_storage
                    assert second_storage.load(
                        enc.parse_data(author_cert)[0]
                    ) is None

                    # New request must re-fetch instead of reusing the old cache.
                    assert await switch(name, sig_ptrs, context) is types.ValidResult.PASS
                    assert len(app.expressed) == 2
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_same_named_cert_is_independent_across_trust_domains():
        async def scenario():
            with TemporaryDirectory() as base_one, TemporaryDirectory() as base_two:
                kc1, anchor1, cert1, packet1, _ = build_domain(
                    base_one, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                kc2, anchor2, cert2, packet2, _ = build_domain(
                    base_two, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                try:
                    # The two domains use identical certificate names but
                    # different key material, so the cached key bits differ.
                    assert enc.Name.to_bytes(
                        enc.parse_data(cert1)[0]
                    ) == enc.Name.to_bytes(enc.parse_data(cert2)[0])
                    assert cert1 != cert2

                    cert_name = enc.parse_data(cert1)[0]
                    app = GateApp([cert1])
                    switch = LvsValidatorSwitch(checker(), app, anchor1)
                    name1, sig1, ctx1 = parse(packet1)
                    assert await switch(name1, sig1, ctx1) is types.ValidResult.PASS
                    old_storage = switch.generation(switch.generation_id).storage
                    old_key = old_storage.load(cert_name)
                    assert old_key is not None

                    # Rotate only the trust anchor (policy model stays valid);
                    # point the app at the new domain's certificates.
                    gen_two = switch.switch(trust_anchor=anchor2)
                    app.packets = app._index([cert2])
                    new_storage = switch.generation(gen_two).storage
                    assert new_storage is not old_storage
                    assert new_storage.load(cert_name) is None

                    name2, sig2, ctx2 = parse(packet2)
                    assert await switch(name2, sig2, ctx2) is types.ValidResult.PASS
                    new_key = new_storage.load(cert_name)
                    assert new_key is not None
                    # Same certificate name, separately cached key material.
                    assert new_key != old_key
                    assert old_storage.load(cert_name) == old_key
                finally:
                    kc1.shutdown()
                    kc2.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_stale_anchor_key_cannot_bypass_new_domain():
        async def scenario():
            with TemporaryDirectory() as base_one, TemporaryDirectory() as base_two:
                kc1, anchor1, cert1, packet1, _ = build_domain(base_one)
                kc2, anchor2, cert2, _, _ = build_domain(base_two)
                try:
                    app = GateApp([cert1])
                    switch = LvsValidatorSwitch(checker(), app, anchor1)
                    name, sig_ptrs, context = parse(packet1)
                    assert await switch(name, sig_ptrs, context) is types.ValidResult.PASS
                    old_generation = switch.generation(switch.generation_id)
                    cert_name = enc.parse_data(cert1)[0]
                    assert old_generation.storage.load(cert_name) is not None

                    gen_two = switch.switch(trust_anchor=anchor2)
                    new_generation = switch.generation(gen_two)
                    expressed_before = len(app.expressed)
                    # The new domain still serves the OLD certificate. It cannot
                    # validate against the new anchor; the request never passes.
                    assert await switch(
                        name, sig_ptrs, context
                    ) is not types.ValidResult.PASS
                    assert len(app.expressed) > expressed_before
                    # Nothing fetched under the old anchor is written into the
                    # new generation's cache, so the stale public key cannot be
                    # reused to bypass the new policy.
                    assert new_generation.storage.load(cert_name) is None
                    # The previous generation's cache is left untouched rather
                    # than being globally cleared.
                    assert old_generation.storage.load(cert_name) is not None
                finally:
                    kc1.shutdown()
                    kc2.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_policy_switch_has_no_implicit_fallback():
        async def scenario():
            with TemporaryDirectory() as base_one, TemporaryDirectory() as base_two:
                kc1, anchor1, cert1, packet1, _ = build_domain(base_one)
                kc2, anchor2, cert2, packet2, _ = build_domain(
                    base_two, identity='/lvs-test-v2'
                )
                try:
                    app = GateApp([cert1])
                    switch = LvsValidatorSwitch(checker(), app, anchor1)
                    name, sig_ptrs, context = parse(packet1)
                    assert await switch(name, sig_ptrs, context) is types.ValidResult.PASS

                    new_id = switch.switch(
                        checker=checker(LVS_TEXT_V2), trust_anchor=anchor2
                    )
                    # An old-domain packet fails the new policy before any key
                    # lookup; nothing is fetched and no old cache is consulted.
                    expressed_before = len(app.expressed)
                    assert await switch(name, sig_ptrs, context) is types.ValidResult.FAIL
                    assert len(app.expressed) == expressed_before

                    # A packet of the new domain passes under the new checker and
                    # anchor, fetched into the new generation's empty cache.
                    name2, sig2, ctx2 = parse(packet2)
                    app.packets = app._index([cert2])
                    assert await switch(name2, sig2, ctx2) is types.ValidResult.PASS
                    assert switch.generation_id == new_id
                    new_storage = switch.generation(new_id).storage
                    assert new_storage.load(enc.parse_data(cert2)[0]) is not None
                finally:
                    kc1.shutdown()
                    kc2.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_invalid_switch_keeps_current_generation_serving():
        async def scenario():
            with TemporaryDirectory() as base:
                keychain, anchor, author_cert, data_packet, _ = build_domain(base)
                try:
                    app = GateApp([author_cert])
                    switch = LvsValidatorSwitch(checker(), app, anchor)
                    current_id = switch.generation_id
                    tampered = bytearray(anchor)
                    tampered[-1] ^= 0x01

                    with pytest.raises(ValueError, match='self-signed'):
                        switch.switch(trust_anchor=bytes(tampered))

                    assert switch.generation_id == current_id
                    name, sig_ptrs, context = parse(data_packet)
                    assert await switch(name, sig_ptrs, context) is types.ValidResult.PASS
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_resume_order_a_old_request_finishes_before_new_one():
        async def scenario():
            with TemporaryDirectory() as base_one, TemporaryDirectory() as base_two:
                kc1, anchor1, cert1, packet1, _ = build_domain(
                    base_one, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                kc2, anchor2, cert2, packet2, _ = build_domain(
                    base_two, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                try:
                    assert enc.Name.to_bytes(
                        enc.parse_data(cert1)[0]
                    ) == enc.Name.to_bytes(enc.parse_data(cert2)[0])
                    cert_name = enc.parse_data(cert1)[0]
                    app = GateApp([cert1], gated=True)
                    switch = LvsValidatorSwitch(checker(), app, anchor1)
                    name, sig_ptrs, context = parse(packet1)

                    old_task = aio.ensure_future(
                        switch(name, sig_ptrs, context)
                    )
                    old_fetch = await aio.wait_for(app.wait_for_fetch(), timeout=2)
                    old_id = switch.generation_id
                    old_generation = switch.generation(old_id)
                    old_storage = old_generation.storage

                    # Switch while the old certificate fetch is paused.
                    new_id = switch.switch(trust_anchor=anchor2)
                    assert old_generation.retired is True
                    assert old_generation.in_flight == 1
                    assert switch.generation(old_id) is old_generation
                    app.packets = app._index([cert2])

                    # Order A: let the old request finish first, against the
                    # old anchor/policy and into the old generation's cache.
                    app.release(old_fetch)
                    assert await old_task is types.ValidResult.PASS

                    # The retired generation is released once idle; its cache
                    # never became the new generation's cache.
                    assert switch.generation(old_id) is None
                    new_generation = switch.generation(new_id)
                    assert new_generation.storage is not old_storage
                    assert new_generation.storage.load(cert_name) is None
                    assert old_storage.load(cert_name) is not None

                    # Then the new request runs entirely on the new generation.
                    name2, sig2, ctx2 = parse(packet2)
                    new_task = aio.ensure_future(
                        switch(name2, sig2, ctx2)
                    )
                    new_fetch = await aio.wait_for(
                        app.wait_for_fetch(after=1), timeout=2
                    )
                    assert switch.generation_id == new_id
                    app.release(new_fetch)
                    assert await new_task is types.ValidResult.PASS
                    assert new_generation.storage.load(cert_name) is not None
                    assert old_storage.load(cert_name) != new_generation.storage.load(
                        cert_name
                    )
                finally:
                    kc1.shutdown()
                    kc2.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_resume_order_b_new_request_finishes_before_late_old_one():
        async def scenario():
            with TemporaryDirectory() as base_one, TemporaryDirectory() as base_two:
                kc1, anchor1, cert1, packet1, _ = build_domain(
                    base_one, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                kc2, anchor2, cert2, packet2, _ = build_domain(
                    base_two, cert_version=FIXED_VERSION, key_id=FIXED_KEY_ID
                )
                try:
                    cert_name = enc.parse_data(cert1)[0]
                    app = GateApp([cert1], gated=True)
                    switch = LvsValidatorSwitch(checker(), app, anchor1)
                    name, sig_ptrs, context = parse(packet1)

                    old_task = aio.ensure_future(
                        switch(name, sig_ptrs, context)
                    )
                    old_fetch = await aio.wait_for(app.wait_for_fetch(), timeout=2)
                    old_id = switch.generation_id
                    old_generation = switch.generation(old_id)
                    old_storage = old_generation.storage

                    new_id = switch.switch(trust_anchor=anchor2)
                    app.packets = app._index([cert2])
                    new_generation = switch.generation(new_id)
                    new_storage = new_generation.storage

                    # Order B: start and finish the new request while the old
                    # fetch is still suspended.
                    name2, sig2, ctx2 = parse(packet2)
                    new_task = aio.ensure_future(
                        switch(name2, sig2, ctx2)
                    )
                    new_fetch = await aio.wait_for(
                        app.wait_for_fetch(after=1), timeout=2
                    )
                    app.release(new_fetch)
                    assert await new_task is types.ValidResult.PASS
                    new_key = new_storage.load(cert_name)
                    assert new_key is not None

                    # Now the old request returns late. It writes only into its
                    # own generation's cache, never into the new one.
                    app.release(old_fetch)
                    assert await old_task is types.ValidResult.PASS
                    assert new_storage.load(cert_name) == new_key
                    assert old_storage is not new_storage
                    assert old_storage.load(cert_name) is not None
                    assert old_storage.load(cert_name) != new_key
                    # Old generation is retired only after its late request ends.
                    assert switch.generation(old_id) is None
                    assert switch.generation_id == new_id
                finally:
                    kc1.shutdown()
                    kc2.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_close_retires_generations_and_blocks_further_switching():
        async def scenario():
            with TemporaryDirectory() as base:
                keychain, anchor, author_cert, _, _ = build_domain(base)
                try:
                    switch = LvsValidatorSwitch(
                        checker(), GateApp([author_cert]), anchor
                    )
                    gen_id = switch.generation_id
                    await switch.aclose()
                    assert switch.generation(gen_id) is None
                    with pytest.raises(RuntimeError):
                        switch.switch()
                finally:
                    keychain.shutdown()

        aio.run(scenario())
