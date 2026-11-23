# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""
Unit test suite for version pinned reads in aws_secretsmanager_caching
"""
import unittest
from datetime import datetime, timedelta, timezone

import botocore
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_secretsmanager_caching.config import SecretCacheConfig
from aws_secretsmanager_caching.secret_cache import SecretCache

pytestmark = [pytest.mark.unit, pytest.mark.local]

CURRENT_VERSION = '01234567890123456789012345678901'
PREVIOUS_VERSION = '11234567890123456789012345678901'
PINNED_VERSION = '21234567890123456789012345678901'


class RecordingClient:
    """A client wrapper that records every operation issued through it."""

    def __init__(self, client, can_describe):
        self._client = client
        self._can_describe = can_describe
        self.calls = []

    def describe_secret(self, **kwargs):
        self.calls.append(('describe_secret', kwargs))
        if not self._can_describe:
            raise ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}},
                'DescribeSecret',
            )
        return self._client.describe_secret(**kwargs)

    def get_secret_value(self, **kwargs):
        self.calls.append(('get_secret_value', kwargs))
        return self._client.get_secret_value(**kwargs)

    def operations(self):
        return [operation for operation, _ in self.calls]


class TestVersionPinning(unittest.TestCase):

    def setUp(self):
        self.client = botocore.session.get_session().create_client(
            'secretsmanager', region_name='us-west-2')
        self.stubber = Stubber(self.client)
        self.stubber.activate()

    def tearDown(self):
        self.stubber.deactivate()

    def _add_stage_warmup(self):
        self.stubber.add_response(
            'describe_secret',
            {'VersionIdsToStages': {
                CURRENT_VERSION: ['AWSCURRENT'],
                PREVIOUS_VERSION: ['AWSPREVIOUS'],
            }},
            {'SecretId': 'test'},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'current', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'previous', 'VersionId': PREVIOUS_VERSION},
            {'SecretId': 'test', 'VersionId': PREVIOUS_VERSION},
        )

    def _add_stage_warmup_current_only(self):
        self.stubber.add_response(
            'describe_secret',
            {'VersionIdsToStages': {
                CURRENT_VERSION: ['AWSCURRENT'],
                PREVIOUS_VERSION: ['AWSPREVIOUS'],
            }},
            {'SecretId': 'test'},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'current', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )

    def test_pinned_read_never_describes(self):
        client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=client)
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': PINNED_VERSION},
            {'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )

        self.assertEqual('pinned', cache.get_secret_string('test', version_id=PINNED_VERSION))
        self.assertEqual(['get_secret_value'], client.operations())
        self.stubber.assert_no_pending_responses()

    def test_pinned_read_served_from_cache(self):
        client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=client, config=SecretCacheConfig(secret_refresh_interval=3600))
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': PINNED_VERSION},
            {'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )

        for _ in range(5):
            self.assertEqual('pinned', cache.get_secret_string('test', version_id=PINNED_VERSION))
        self.assertEqual(['get_secret_value'], client.operations())
        self.stubber.assert_no_pending_responses()

    def test_pinned_read_ignores_warmed_stage(self):
        wide = RecordingClient(self.client, can_describe=True)
        narrow = RecordingClient(self.client, can_describe=False)
        wide_cache = SecretCache(client=wide)
        narrow_cache = SecretCache(client=narrow)
        self._add_stage_warmup()

        self.assertEqual('current', wide_cache.get_secret_string('test'))
        self.assertEqual('previous', wide_cache.get_secret_string('test', 'AWSPREVIOUS'))

        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )
        # Same secret id and same version text as the warmed stage value, but a
        # different role must neither reuse the value nor call DescribeSecret.
        self.assertEqual('pinned', narrow_cache.get_secret_string('test', version_id=CURRENT_VERSION))
        self.assertEqual(['get_secret_value'], narrow.operations())
        self.stubber.assert_no_pending_responses()

    def test_pinned_read_not_shared_across_authorization_contexts(self):
        client = RecordingClient(self.client, can_describe=True)
        cache = SecretCache(client=client)
        self._add_stage_warmup_current_only()
        self.assertEqual('current', cache.get_secret_string('test', authorization_context='wide'))

        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': PREVIOUS_VERSION},
            {'SecretId': 'test', 'VersionId': PREVIOUS_VERSION},
        )
        self.assertEqual(
            'pinned',
            cache.get_secret_string(
                'test',
                version_id=PREVIOUS_VERSION,
                authorization_context='narrow',
            ),
        )
        self.assertEqual(
            ['describe_secret', 'get_secret_value', 'get_secret_value'],
            client.operations(),
        )
        self.stubber.assert_no_pending_responses()

    def test_stage_mode_still_available(self):
        client = RecordingClient(self.client, can_describe=True)
        cache = SecretCache(client=client)
        self._add_stage_warmup()

        self.assertEqual('current', cache.get_secret_string('test'))
        self.assertEqual('previous', cache.get_secret_string('test', 'AWSPREVIOUS'))
        self.assertEqual(
            ['describe_secret', 'get_secret_value', 'get_secret_value'],
            client.operations(),
        )
        self.stubber.assert_no_pending_responses()

    def test_revoked_pinned_value_is_not_served(self):
        client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=client)
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': PINNED_VERSION},
            {'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )
        self.assertEqual('pinned', cache.get_secret_string('test', version_id=PINNED_VERSION))

        entry = cache._get_cached_version('test', PINNED_VERSION)
        entry._next_refresh_time = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.stubber.add_client_error(
            'get_secret_value',
            'AccessDeniedException',
            expected_params={'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )

        with self.assertRaises(ClientError):
            cache.get_secret_string('test', version_id=PINNED_VERSION)
        self.assertIsNone(entry._get_result())
        self.assertEqual(
            ['get_secret_value', 'get_secret_value'],
            client.operations(),
        )
        self.stubber.assert_no_pending_responses()

    def test_revoked_stage_value_is_not_served(self):
        client = RecordingClient(self.client, can_describe=True)
        cache = SecretCache(client=client)
        self._add_stage_warmup_current_only()
        self.assertEqual('current', cache.get_secret_string('test'))

        entry = cache._get_cached_secret('test')
        entry._next_refresh_time = datetime.now(timezone.utc) - timedelta(seconds=1)
        self.stubber.add_client_error(
            'describe_secret',
            'AccessDeniedException',
            expected_params={'SecretId': 'test'},
        )

        with self.assertRaises(ClientError):
            cache.get_secret_string('test')
        self.assertIsNone(entry._get_result())
        self.stubber.assert_no_pending_responses()

    def test_pinned_version_mismatch_is_rejected(self):
        client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=client)
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'wrong', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )

        with self.assertRaises(ValueError):
            cache.get_secret_string('test', version_id=PINNED_VERSION)
        self.stubber.assert_no_pending_responses()

    def test_pinned_binary_read(self):
        client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=client)
        self.stubber.add_response(
            'get_secret_value',
            {'SecretBinary': b'pinned', 'VersionId': PINNED_VERSION},
            {'SecretId': 'test', 'VersionId': PINNED_VERSION},
        )

        self.assertEqual(b'pinned', cache.get_secret_binary('test', version_id=PINNED_VERSION))
        self.assertEqual(['get_secret_value'], client.operations())
        self.stubber.assert_no_pending_responses()


class TestPinnedRevocationWindow(unittest.TestCase):
    """Acceptance flow: warm with a wide role, then switch to a narrow role."""

    def setUp(self):
        self.client = botocore.session.get_session().create_client(
            'secretsmanager', region_name='us-west-2')
        self.stubber = Stubber(self.client)
        self.stubber.activate()

    def tearDown(self):
        self.stubber.deactivate()

    def test_wide_then_narrow_with_revocation(self):
        wide_calls = []
        narrow_calls = []

        class RoleClient:
            def __init__(self, inner, can_describe, calls):
                self._inner = inner
                self._can_describe = can_describe
                self.calls = calls

            def describe_secret(self, **kwargs):
                self.calls.append(('describe_secret', kwargs))
                if not self._can_describe:
                    raise ClientError(
                        {'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}},
                        'DescribeSecret',
                    )
                return self._inner.describe_secret(**kwargs)

            def get_secret_value(self, **kwargs):
                self.calls.append(('get_secret_value', kwargs))
                return self._inner.get_secret_value(**kwargs)

        wide = SecretCache(client=RoleClient(self.client, True, wide_calls))
        narrow = SecretCache(
            client=RoleClient(self.client, False, narrow_calls),
            config=SecretCacheConfig(secret_refresh_interval=0),
        )

        self.stubber.add_response(
            'describe_secret',
            {'VersionIdsToStages': {
                CURRENT_VERSION: ['AWSCURRENT'],
                PREVIOUS_VERSION: ['AWSPREVIOUS'],
            }},
            {'SecretId': 'test'},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'current', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'previous', 'VersionId': PREVIOUS_VERSION},
            {'SecretId': 'test', 'VersionId': PREVIOUS_VERSION},
        )
        self.assertEqual('current', wide.get_secret_string('test'))
        self.assertEqual('previous', wide.get_secret_string('test', 'AWSPREVIOUS'))

        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': PREVIOUS_VERSION},
            {'SecretId': 'test', 'VersionId': PREVIOUS_VERSION},
        )
        self.assertEqual('pinned', narrow.get_secret_string('test', version_id=PREVIOUS_VERSION))

        self.assertEqual(
            ['get_secret_value'],
            [operation for operation, _ in narrow_calls],
        )

        # The backend now reports the authorization as revoked.
        self.stubber.add_client_error(
            'get_secret_value',
            'AccessDeniedException',
            expected_params={'SecretId': 'test', 'VersionId': PREVIOUS_VERSION},
        )
        with self.assertRaises(ClientError):
            narrow.get_secret_string('test', version_id=PREVIOUS_VERSION)

        entry = narrow._get_cached_version('test', PREVIOUS_VERSION)
        self.assertIsNone(entry._get_result())
        self.assertEqual(
            ['get_secret_value', 'get_secret_value'],
            [operation for operation, _ in narrow_calls],
        )
        self.assertNotIn('describe_secret', [operation for operation, _ in narrow_calls])
        self.stubber.assert_no_pending_responses()


class TestSharedCacheRoleSwitch(unittest.TestCase):
    """A single cache instance serving two roles through injected clients."""

    def setUp(self):
        self.client = botocore.session.get_session().create_client(
            'secretsmanager', region_name='us-west-2')
        self.stubber = Stubber(self.client)
        self.stubber.activate()

    def tearDown(self):
        self.stubber.deactivate()

    def test_shared_cache_isolates_roles_by_client(self):
        wide_client = RecordingClient(self.client, can_describe=True)
        narrow_client = RecordingClient(self.client, can_describe=False)
        cache = SecretCache(client=wide_client)

        self.stubber.add_response(
            'describe_secret',
            {'VersionIdsToStages': {CURRENT_VERSION: ['AWSCURRENT']}},
            {'SecretId': 'test'},
        )
        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'current', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )
        self.assertEqual('current', cache.get_secret_string('test'))

        self.stubber.add_response(
            'get_secret_value',
            {'SecretString': 'pinned', 'VersionId': CURRENT_VERSION},
            {'SecretId': 'test', 'VersionId': CURRENT_VERSION},
        )
        self.assertEqual(
            'pinned',
            cache.get_secret_string('test', version_id=CURRENT_VERSION, client=narrow_client),
        )
        self.assertEqual(['get_secret_value'], narrow_client.operations())
        self.stubber.assert_no_pending_responses()
