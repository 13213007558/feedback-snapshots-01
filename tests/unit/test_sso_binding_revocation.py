import threading
import unittest
from unittest import mock

import pytest

from botocore.credentials import (
    SSOBindingRegistry,
    SSOBindingScope,
    SSOCredentialFetcher,
    SSOProvider,
)
from botocore.exceptions import SSOAuthorizationRequiredError
from botocore.session import Session

FAR_FUTURE = '2999-01-01T00:00:00Z'


def role_response(role_name, suffix='current'):
    return {
        'roleCredentials': {
            'accessKeyId': f'{role_name}-{suffix}-ak',
            'secretAccessKey': 'secret',
            'sessionToken': f'{role_name}-{suffix}-token',
            'expiration': 4070908800000,
        }
    }


def cached_role_response(account_id, access_key):
    return {
        'ProviderType': 'sso',
        'Credentials': {
            'AccessKeyId': access_key,
            'SecretAccessKey': 'secret',
            'SessionToken': 'cached-session-token',
            'Expiration': FAR_FUTURE,
            'AccountId': account_id,
        },
    }


class SSOBindingRevocationTest(unittest.TestCase):
    def setUp(self):
        self.credential_cache = {}
        self.state_cache = {}
        self.registry = SSOBindingRegistry(
            cache=self.state_cache,
            credential_cache=self.credential_cache,
        )
        self.client = mock.Mock()
        self.client_creator = mock.Mock(return_value=self.client)
        frozen_token = mock.Mock(token='shared-sso-token')
        self.token_provider = mock.Mock()
        frozen_token_result = mock.Mock(token='shared-sso-token')
        frozen_token = (
            self.token_provider.load_token.return_value.get_frozen_token
        )
        frozen_token.return_value = frozen_token_result

    def make_fetcher(
        self,
        role_name,
        account_id,
        profile_name=None,
        registry=None,
    ):
        return SSOCredentialFetcher(
            'https://example.awsapps.com/start',
            'us-east-1',
            role_name,
            account_id,
            self.client_creator,
            token_provider=self.token_provider,
            cache=self.credential_cache,
            binding_registry=registry or self.registry,
            profile_name=profile_name,
        )

    def test_account_role_scopes_are_stable_and_distinct(self):
        role_a = self.make_fetcher('role-a', '111111111111', 'profile-a')
        role_b = self.make_fetcher('role-b', '222222222222', 'profile-b')

        self.assertEqual(role_a.binding_scope, role_a._cache_key)
        self.assertEqual(role_b.binding_scope, role_b._cache_key)
        self.assertNotEqual(role_a.binding_scope, role_b.binding_scope)

        scope = SSOBindingScope(
            account_id='111111111111',
            role_name='role-a',
            start_url='https://example.awsapps.com/start',
        )
        self.assertEqual(scope.cache_key, role_a._cache_key)

    def test_revoked_cached_binding_stops_but_other_binding_remains(self):
        role_a = self.make_fetcher('role-a', '111111111111', 'profile-a')
        role_b = self.make_fetcher('role-b', '222222222222', 'profile-b')
        self.credential_cache[role_a._cache_key] = cached_role_response(
            '111111111111',
            'cached-a',
        )
        self.credential_cache[role_b._cache_key] = cached_role_response(
            '222222222222',
            'cached-b',
        )

        role_a.revoke_binding()

        with pytest.raises(SSOAuthorizationRequiredError) as exc_info:
            role_a.fetch_credentials()
        self.assertTrue(exc_info.value.interaction_required)
        self.assertEqual(exc_info.value.profile_name, 'profile-a')
        self.assertIn('aws sso login --profile profile-a', str(exc_info.value))
        self.assertNotIn(role_a._cache_key, self.credential_cache)

        credentials_b = role_b.fetch_credentials()
        self.assertEqual(credentials_b['access_key'], 'cached-b')
        self.client_creator.assert_not_called()

    def test_revocation_persists_for_new_fetcher_instances(self):
        role_a = self.make_fetcher('role-a', '111111111111', 'profile-a')
        role_a.revoke_binding()

        replacement_registry = SSOBindingRegistry(cache=self.state_cache)
        replacement_a = self.make_fetcher(
            'role-a',
            '111111111111',
            'profile-a',
            registry=replacement_registry,
        )

        with pytest.raises(SSOAuthorizationRequiredError):
            replacement_a.fetch_credentials()

    def test_late_response_for_revoked_in_flight_refresh_is_not_stored(self):
        role_a = self.make_fetcher('role-a', '111111111111', 'profile-a')
        role_b = self.make_fetcher('role-b', '222222222222', 'profile-b')

        request_started = threading.Event()
        release_a = threading.Event()

        def get_role_credentials(**kwargs):
            if kwargs['roleName'] == 'role-a':
                request_started.set()
                if not release_a.wait(5):
                    raise AssertionError('timed out waiting for release')
                return role_response('role-a', 'late')
            return role_response('role-b')

        self.client.get_role_credentials.side_effect = get_role_credentials
        outcome = {}

        def refresh_a():
            try:
                outcome['credentials'] = role_a.fetch_credentials()
            except BaseException as exc:  # pragma: no cover - asserted below
                outcome['error'] = exc

        worker = threading.Thread(target=refresh_a)
        worker.start()
        self.assertTrue(request_started.wait(5))

        role_a.revoke_binding()
        release_a.set()
        worker.join(5)

        self.assertFalse(worker.is_alive())
        self.assertIsInstance(
            outcome['error'],
            SSOAuthorizationRequiredError,
        )
        self.assertNotIn('credentials', outcome)
        self.assertNotIn(role_a._cache_key, self.credential_cache)

        credentials_b = role_b.fetch_credentials()
        self.assertEqual(credentials_b['access_key'], 'role-b-current-ak')
        self.assertIn(role_b._cache_key, self.credential_cache)
        requested_roles = [
            call.kwargs['roleName']
            for call in self.client.get_role_credentials.call_args_list
        ]
        self.assertEqual(requested_roles, ['role-a', 'role-b'])

    def test_reapproval_fences_stale_response_and_allows_new_material(self):
        role_a = self.make_fetcher('role-a', '111111111111', 'profile-a')
        request_started = threading.Event()
        release_first = threading.Event()
        call_count = 0

        def get_role_credentials(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                request_started.set()
                if not release_first.wait(5):
                    raise AssertionError('timed out waiting for release')
                return role_response('role-a', 'stale')
            return role_response('role-a', 'approved')

        self.client.get_role_credentials.side_effect = get_role_credentials
        outcome = {}

        def refresh_a():
            try:
                outcome['credentials'] = role_a.fetch_credentials()
            except BaseException as exc:  # pragma: no cover
                outcome['error'] = exc

        worker = threading.Thread(target=refresh_a)
        worker.start()
        self.assertTrue(request_started.wait(5))

        role_a.revoke_binding()
        role_a.approve_binding()
        release_first.set()
        worker.join(5)

        self.assertFalse(worker.is_alive())
        self.assertNotIn('error', outcome)
        self.assertEqual(
            outcome['credentials']['access_key'],
            'role-a-approved-ak',
        )
        cached = self.credential_cache[role_a._cache_key]
        self.assertEqual(
            cached['Credentials']['AccessKeyId'],
            'role-a-approved-ak',
        )
        self.assertEqual(call_count, 2)


class SSOProviderLiveCredentialTest(unittest.TestCase):
    def test_revocation_immediately_blocks_live_credentials_object(self):
        account_id = '111111111111'
        role_name = 'role-a'
        config = {
            'profiles': {
                'profile-a': {
                    'sso_role_name': role_name,
                    'sso_account_id': account_id,
                    'sso_start_url': 'https://example.awsapps.com/start',
                    'sso_region': 'us-east-1',
                }
            }
        }
        scope = SSOBindingScope(
            account_id=account_id,
            role_name=role_name,
            start_url='https://example.awsapps.com/start',
        )
        credential_cache = {
            scope.cache_key: cached_role_response(account_id, 'cached-a')
        }
        registry = SSOBindingRegistry(credential_cache=credential_cache)
        provider = SSOProvider(
            load_config=lambda: config,
            client_creator=mock.Mock(),
            profile_name='profile-a',
            cache=credential_cache,
            token_cache={},
            binding_registry=registry,
        )

        credentials = provider.load()
        frozen = credentials.get_frozen_credentials()
        self.assertEqual(frozen.access_key, 'cached-a')

        provider.revoke_binding()

        with pytest.raises(SSOAuthorizationRequiredError):
            credentials.get_frozen_credentials()
        with pytest.raises(SSOAuthorizationRequiredError):
            credentials.access_key
        self.assertIsNone(credentials._frozen_credentials)
        self.assertNotIn(scope.cache_key, credential_cache)

    def test_revocation_does_not_delete_shared_sso_token(self):
        account_id = '111111111111'
        config = {
            'profiles': {
                'profile-a': {
                    'sso_role_name': 'role-a',
                    'sso_account_id': account_id,
                    'sso_start_url': 'https://example.awsapps.com/start',
                    'sso_region': 'us-east-1',
                }
            }
        }
        scope = SSOBindingScope(
            account_id=account_id,
            role_name='role-a',
            start_url='https://example.awsapps.com/start',
        )
        shared_cache = {
            scope.cache_key: cached_role_response(account_id, 'cached-a'),
            'shared-session-token-key': {
                'accessToken': 'shared-access-token',
                'expiresAt': FAR_FUTURE,
            },
        }
        registry = SSOBindingRegistry(
            cache=shared_cache,
            credential_cache=shared_cache,
        )
        provider = SSOProvider(
            load_config=lambda: config,
            client_creator=mock.Mock(),
            profile_name='profile-a',
            cache=shared_cache,
            token_cache=shared_cache,
            binding_registry=registry,
        )

        provider.revoke_binding()

        self.assertNotIn(scope.cache_key, shared_cache)
        self.assertIn('shared-session-token-key', shared_cache)
        self.assertEqual(
            shared_cache['shared-session-token-key']['accessToken'],
            'shared-access-token',
        )


class SessionSSOBindingTest(unittest.TestCase):
    def test_session_revokes_named_profile_binding(self):
        config = {
            'profiles': {
                'profile-a': {
                    'sso_role_name': 'role-a',
                    'sso_account_id': '111111111111',
                    'sso_start_url': 'https://example.awsapps.com/start',
                    'sso_region': 'us-east-1',
                }
            }
        }
        session = Session()
        session._sso_binding_registry = SSOBindingRegistry(
            credential_cache=session._credential_cache
        )
        scope = SSOBindingScope(
            account_id='111111111111',
            role_name='role-a',
            start_url='https://example.awsapps.com/start',
        )

        with mock.patch.object(
            Session,
            'full_config',
            new_callable=mock.PropertyMock,
            return_value=config,
        ):
            state = session.revoke_sso_binding('profile-a')

        self.assertEqual(state['status'], 'revoked')
        self.assertTrue(session.sso_binding_registry.is_revoked(scope))

        with mock.patch.object(
            Session,
            'full_config',
            new_callable=mock.PropertyMock,
            return_value=config,
        ):
            session.approve_sso_binding('profile-a')
        self.assertFalse(session.sso_binding_registry.is_revoked(scope))


if __name__ == '__main__':
    unittest.main()
