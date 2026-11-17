# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
import hashlib

from ndn import app as ndn_app
from ndn import types
from ndn.app_support.rdr_segmented_fetcher import (
    FetchOptions, FetchResult, SegmentedObjectFetcher,
    VersionConflictError, FinalBlockConflictError, MissingSegmentError,
    SegmentStructureError, ResourceLimitError,
)
from ndn.encoding import Name, Component
from ndn.encoding import ndn_format_0_3 as fmt
from ndn.security import HmacSha256Signer
from ndn.security.validator.known_key_validator import verify_hmac
from ndn.transport.face import Face

SECRET = b'test-publisher-secret-key-0123456'
KEY_LOCATOR = '/publisher/KEY/1'


def make_validator(validated_names: list | None = None):
    async def validator(name, sig_ptrs, _context):
        if validated_names is not None:
            validated_names.append(Name.to_str(name))
        ok = verify_hmac(SECRET, sig_ptrs)
        return types.ValidResult.PASS if ok else types.ValidResult.FAIL
    return validator


class Publisher:
    """Signs segmented object versions with one key, like a real producer."""

    def __init__(self, object_name: str):
        self.object_name = Name.from_str(object_name)
        self.signer = HmacSha256Signer(KEY_LOCATOR, SECRET)
        self.versions: dict[int, list[bytes]] = {}
        self.wires: dict[str, bytes] = {}

    def publish(self, version: int, chunks: list[bytes],
                final_override: dict[int, int] | None = None,
                drop_final_on: set[int] | None = None):
        self.versions[version] = chunks
        last = len(chunks) - 1
        for seg, chunk in enumerate(chunks):
            final_seg = last
            if final_override and seg in final_override:
                final_seg = final_override[seg]
            meta = fmt.MetaInfo(freshness_period=1000)
            if drop_final_on is None or seg not in drop_final_on:
                meta.final_block_id = Component.from_segment(final_seg)
            name = self.object_name + [Component.from_version(version),
                                       Component.from_segment(seg)]
            self.wires[Name.to_str(name)] = bytes(
                fmt.make_data(name, meta, content=chunk, signer=self.signer))

    def wire(self, name_str: str) -> bytes | None:
        return self.wires.get(name_str)

    def lookup(self, name_str: str) -> bytes | None:
        # Emulate forwarder matching: exact name first, then CanBePrefix.
        exact = self.wires.get(name_str)
        if exact is not None:
            return exact
        interest_name = Name.from_str(name_str)
        for stored in sorted(self.wires):
            if Name.is_prefix(interest_name, Name.from_str(stored)):
                return self.wires[stored]
        return None


class ScriptedFace(Face):
    """A face answering Interests from a callback, like a hostile cache."""

    def __init__(self, handler):
        super().__init__()
        self.handler = handler

    async def open(self):
        self.running = True

    def shutdown(self):
        self.running = False

    def send(self, data: bytes):
        name, _params, _app_param, _sig = fmt.parse_interest(data)
        aio.get_running_loop().create_task(self._respond(name))

    async def _respond(self, name):
        wire = await self.handler(Name.to_str(name))
        if wire is not None and self.running:
            await self.callback(0x06, wire)

    async def run(self):
        while self.running:
            await aio.sleep(0.005)

    def isLocalFace(self):
        return True


def run_fetch(handler, name, options=None, validated=None):
    """Run one fetch end-to-end through NDNApp and a ScriptedFace."""
    options = options or FetchOptions(lifetime=100, retries=2, max_in_flight=4)
    result_box = {}
    error_box = {}

    async def app_main():
        face = ScriptedFace(handler)
        app = ndn_app.NDNApp(face)
        face.app = app
        validator = make_validator(validated)

        async def main():
            fetcher = SegmentedObjectFetcher.from_app(app, validator, options)
            try:
                result_box['result'] = await fetcher.fetch(name)
            except Exception as e:
                error_box['error'] = e
            finally:
                app.shutdown()

        await app.main_loop(main())

    aio.run(app_main())
    if error_box:
        raise error_box['error']
    return result_box['result']


def fetch_or_exc(handler, name, options=None, validated=None):
    try:
        return run_fetch(handler, name, options, validated)
    except Exception as e:
        return e


BODY_A = [b'alpha-0|', b'alpha-1|', b'alpha-2|', b'alpha-3|']
BODY_B = [b'beta--0|', b'beta--1|', b'beta--2|', b'beta--3|']


class TestSegmentedObjectFetcher:

    def test_happy_path_stable_digest(self):
        pub = Publisher('/audit/log')
        pub.publish(1, BODY_A)

        async def handler(name_str):
            return pub.lookup(name_str)

        validated = []
        res = run_fetch(handler, '/audit/log', validated=validated)
        expected = b''.join(BODY_A)
        assert isinstance(res, FetchResult)
        assert res.content == expected
        assert res.segment_count == 4
        assert res.digest == hashlib.sha256(expected).digest()
        assert res.name == Name.from_str('/audit/log/v=1')
        # Every segment was individually validated by the policy.
        assert len(validated) == 4
        # A second fetch of the same object yields the same digest.
        res2 = run_fetch(handler, '/audit/log')
        assert res2.digest == res.digest
        assert res2.content == res.content

    def test_out_of_order_delivery_same_digest(self):
        pub = Publisher('/audit/log')
        pub.publish(1, BODY_A)

        async def handler(name_str):
            # Later segments answer faster, forcing out-of-order arrival.
            last = Name.from_str(name_str)[-1]
            if Component.get_type(last) == Component.TYPE_SEGMENT:
                await aio.sleep(0.02 * (3 - Component.to_number(last)))
            return pub.lookup(name_str)

        res = run_fetch(handler, '/audit/log')
        assert res.content == b''.join(BODY_A)
        assert res.digest == hashlib.sha256(b''.join(BODY_A)).digest()

    def test_interleaved_legit_versions_rejected(self):
        # Two bodies, two legitimate versions, one publisher key: every
        # segment validates, but the mixture must still be rejected.
        pub = Publisher('/audit/log')
        pub.publish(1, BODY_A)
        pub.publish(2, BODY_B)
        validated = []

        async def express(name, can_be_prefix):
            name_str = Name.to_str(name)
            # Malicious/cache-confused lower layer: mixes v=1 and v=2 segments.
            if name_str == '/audit/log':
                wire = pub.wire('/audit/log/v=1/seg=0')
            elif name_str.endswith('seg=0') or name_str.endswith('seg=1'):
                wire = pub.wire(name_str)
            else:
                wire = pub.wire(name_str.replace('/v=1/', '/v=2/'))
            if wire is None:
                raise types.InterestTimeout()
            data_name, meta, content, sig_ptrs = fmt.parse_data(wire)
            # Prove each delivered segment is individually legitimate.
            result = await make_validator(validated)(data_name, sig_ptrs, None)
            assert result == types.ValidResult.PASS
            return data_name, content, meta

        fetcher = SegmentedObjectFetcher(
            express, FetchOptions(lifetime=100, retries=1, max_in_flight=2))

        async def main():
            return await fetcher.fetch('/audit/log')

        exc = None
        try:
            aio.run(main())
        except VersionConflictError as e:
            exc = e
        assert exc is not None, 'mixed-version assembly must be rejected'
        assert exc.evidence is not None
        assert exc.evidence.pinned_prefix == '/audit/log/v=1'
        # Partial evidence exposes digests only, never content.
        assert all(len(s.sha256) == 64 for s in exc.evidence.segments)
        assert not hasattr(exc.evidence, 'content')
        for seg_ev in exc.evidence.segments:
            assert BODY_A[0] not in seg_ev.sha256.encode()
        # All served segments really did pass the signature policy.
        assert len(validated) >= 2

    def test_missing_last_segment_no_prefix_masquerade(self):
        pub = Publisher('/audit/log')
        pub.publish(1, BODY_A)

        async def handler(name_str):
            if name_str.endswith('seg=3'):
                return None  # last segment deleted: Interest times out
            return pub.lookup(name_str)

        exc = fetch_or_exc(handler, '/audit/log')
        assert isinstance(exc, MissingSegmentError)
        # The fetched prefix must not be delivered as a complete object.
        assert exc.evidence is not None
        assert sorted(s.segment for s in exc.evidence.segments) == [0, 1, 2]
        assert exc.evidence.final_segment == 3
        assert all(len(s.sha256) == 64 for s in exc.evidence.segments)
        assert not hasattr(exc, 'content')

    def test_conflicting_final_block_id_rejected(self):
        pub = Publisher('/audit/log')
        # Segment 1 claims a different FinalBlockId than segment 0.
        pub.publish(1, BODY_A, final_override={1: 7})

        async def handler(name_str):
            return pub.lookup(name_str)

        exc = fetch_or_exc(handler, '/audit/log')
        assert isinstance(exc, FinalBlockConflictError)
        assert exc.evidence is not None
        assert not hasattr(exc, 'content')

    def test_unconfirmed_final_segment_rejected(self):
        pub = Publisher('/audit/log')
        # The last segment carries no FinalBlockId: truncation must not
        # be deliverable as a complete object.
        pub.publish(1, BODY_A, drop_final_on={3})

        async def handler(name_str):
            return pub.lookup(name_str)

        exc = fetch_or_exc(handler, '/audit/log')
        assert isinstance(exc, SegmentStructureError)
        assert exc.evidence is not None

    def test_resource_limits_enforced(self):
        pub = Publisher('/audit/log')
        pub.publish(1, BODY_A)

        async def handler(name_str):
            return pub.lookup(name_str)

        tiny = FetchOptions(lifetime=100, retries=1, max_content_size=4)
        exc = fetch_or_exc(handler, '/audit/log', options=tiny)
        assert isinstance(exc, ResourceLimitError)
