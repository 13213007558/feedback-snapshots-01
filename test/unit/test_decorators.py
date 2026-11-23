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
Unit test suite for decorators module
"""
import asyncio
import inspect
import json
import unittest

import botocore
from aws_secretsmanager_caching.decorators import InjectKeywordedSecretString, InjectSecretString
from aws_secretsmanager_caching.secret_cache import SecretCache
from botocore.stub import Stubber


class TestAwsSecretsManagerCachingInjectKeywordedSecretStringDecorator(unittest.TestCase):

    def get_client(self, response={}, versions=None, version_response=None):
        client = botocore.session.get_session().create_client('secretsmanager', region_name='us-west-2')
        stubber = Stubber(client)
        expected_params = {'SecretId': 'test'}
        if versions:
            response['VersionIdsToStages'] = versions
        stubber.add_response('describe_secret', response, expected_params)
        if version_response is not None:
            stubber.add_response('get_secret_value', version_response)
        stubber.activate()
        return client

    def test_valid_json(self):
        secret = {
            'username': 'secret_username',
            'password': 'secret_password'
        }

        secret_string = json.dumps(secret)

        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret_string}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        @InjectKeywordedSecretString(secret_id='test', cache=cache, func_username='username', func_password='password')
        def function_to_be_decorated(func_username, func_password, keyworded_argument='foo'):
            self.assertEqual(secret['username'], func_username)
            self.assertEqual(secret['password'], func_password)
            self.assertEqual(keyworded_argument, 'foo')
            return 'OK'

        self.assertEqual(function_to_be_decorated(), 'OK')

    def test_valid_json_with_mixed_args(self):
        secret = {
            'username': 'secret_username',
            'password': 'secret_password'
        }

        secret_string = json.dumps(secret)

        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret_string}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        @InjectKeywordedSecretString(secret_id='test', cache=cache, arg2='username', arg3='password')
        def function_to_be_decorated(arg1, arg2, arg3, arg4='bar'):
            self.assertEqual(arg1, 'foo')
            self.assertEqual(secret['username'], arg2)
            self.assertEqual(secret['password'], arg3)
            self.assertEqual(arg4, 'bar')

        function_to_be_decorated('foo')

    def test_valid_json_with_no_secret_kwarg(self):
        secret = {
            'username': 'secret_username',
            'password': 'secret_password'
        }

        secret_string = json.dumps(secret)

        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret_string}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        @InjectKeywordedSecretString('test', cache=cache, func_username='username', func_password='password')
        def function_to_be_decorated(func_username, func_password, keyworded_argument='foo'):
            self.assertEqual(secret['username'], func_username)
            self.assertEqual(secret['password'], func_password)
            self.assertEqual(keyworded_argument, 'foo')

        function_to_be_decorated()

    def test_invalid_json(self):
        secret = 'not json'
        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        with self.assertRaises((RuntimeError, json.decoder.JSONDecodeError)):
            @InjectKeywordedSecretString(secret_id='test', cache=cache, func_username='username',
                                         func_passsword='password')
            def function_to_be_decorated(func_username, func_password, keyworded_argument='foo'):
                return

            function_to_be_decorated()

    def test_missing_key(self):
        secret = {'username': 'secret_username'}
        secret_string = json.dumps(secret)
        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret_string}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        with self.assertRaises((RuntimeError, ValueError)):
            @InjectKeywordedSecretString(secret_id='test', cache=cache, func_username='username',
                                         func_passsword='password')
            def function_to_be_decorated(func_username, func_password, keyworded_argument='foo'):
                return

            function_to_be_decorated()


class TestAwsSecretsManagerCachingInjectSecretStringDecorator(unittest.TestCase):

    def get_client(self, response={}, versions=None, version_response=None):
        client = botocore.session.get_session().create_client('secretsmanager', region_name='us-west-2')
        stubber = Stubber(client)
        expected_params = {'SecretId': 'test'}
        if versions:
            response['VersionIdsToStages'] = versions
        stubber.add_response('describe_secret', response, expected_params)
        if version_response is not None:
            stubber.add_response('get_secret_value', version_response)
        stubber.activate()
        return client

    def test_string(self):
        secret = 'not json'
        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        @InjectSecretString('test', cache)
        def function_to_be_decorated(arg1, arg2, arg3):
            self.assertEqual(arg1, secret)
            self.assertEqual(arg2, 'foo')
            self.assertEqual(arg3, 'bar')
            return 'OK'

        self.assertEqual(function_to_be_decorated('foo', 'bar'), 'OK')

    def test_string_with_additional_kwargs(self):
        secret = 'not json'
        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        @InjectSecretString('test', cache)
        def function_to_be_decorated(arg1, arg2, arg3):
            self.assertEqual(arg1, secret)
            self.assertEqual(arg2, 'foo')
            self.assertEqual(arg3, 'bar')

        function_to_be_decorated(arg2='foo', arg3='bar')

    def test_string_with_class_method(self):
        secret = 'not json'
        response = {}
        versions = {
            '01234567890123456789012345678901': ['AWSCURRENT']
        }
        version_response = {'SecretString': secret}
        cache = SecretCache(client=self.get_client(response, versions, version_response))

        class TestClass(unittest.TestCase):
            @InjectSecretString('test', cache)
            def class_method(self, arg1, arg2, arg3):
                self.assertEqual(arg1, secret)
                self.assertEqual(arg2, 'foo')
                self.assertEqual(arg3, 'bar')

        t = TestClass()
        t.class_method(arg2="foo", arg3="bar")


class RecordingCache:
    """
    Business test double standing in for SecretCache.

    It records every cache access with only non-sensitive metadata (secret id
    and the version served) so assertions can explain how often the secret was
    fetched without the records themselves holding any secret material. The
    current value can be rotated to emulate secret rotation during a task's
    lifetime.
    """

    def __init__(self, secret_id, initial_value):
        self.secret_id = secret_id
        self._current_value = initial_value
        self.version = 1
        self.access_log = []

    def rotate(self, new_value):
        self._current_value = new_value
        self.version += 1

    def get_secret_string(self, secret_id, version_stage=None):
        self.access_log.append({'secret_id': secret_id, 'version': self.version})
        return self._current_value


def build_keyworded_service(cache):
    """Business stand-in whose class methods receive injected JSON secret keys."""

    class KeywordedService:

        def __init__(self):
            self.executed = []
            self.results = []

        @InjectKeywordedSecretString(
            secret_id='test', cache=cache,
            func_username='username', func_password='password')
        async def call(self, request_id, func_username, func_password, label='default'):
            self.executed.append(request_id)
            self.results.append({
                'request_id': request_id,
                'username': func_username,
                'password': func_password,
                'label': label,
            })
            return request_id, func_username, func_password, label

    return KeywordedService()


def build_positional_service(cache):
    """Business stand-in whose class method receives the raw secret positionally."""

    class PositionalService:

        def __init__(self):
            self.executed = []

        @InjectSecretString('test', cache)
        async def call(self, secret, request_id, *extra, mode='sync-style'):
            self.executed.append(request_id)
            return secret, request_id, extra, mode

    return PositionalService()


class TestAwsSecretsManagerCachingAsyncDecorators(unittest.TestCase):

    def test_deferred_fetch_rotation_cancel_and_signature(self):
        cache = RecordingCache('test', json.dumps({
            'username': 'user-a', 'password': 'pass-a'}))
        service = build_keyworded_service(cache)

        # Build A then B. Creating the coroutines must not touch the cache yet.
        coro_a = service.call('A', label='alpha')
        coro_b = service.call('B', label='beta')
        self.assertEqual(cache.access_log, [])
        self.assertNotIn('A', service.executed)
        self.assertNotIn('B', service.executed)

        # Rotate before either task runs; execution must use the authorization
        # available at run time, not anything pinned at creation time.
        cache.rotate(json.dumps({'username': 'user-b', 'password': 'pass-b'}))

        async def scenario():
            task_a = asyncio.ensure_future(coro_a)
            task_b = asyncio.ensure_future(coro_b)

            # Cancel A before it gets a chance to start, then drive B first.
            task_a.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task_a
            result_b = await task_b
            return result_b

        result_b = asyncio.run(scenario())

        # Only B executed: a single cache access, after the rotation.
        self.assertEqual(cache.access_log, [{'secret_id': 'test', 'version': 2}])
        self.assertEqual(service.executed, ['B'])

        # Caller still sees a result matching the original coroutine signature.
        self.assertEqual(result_b, ('B', 'user-b', 'pass-b', 'beta'))
        self.assertEqual(service.results, [{
            'request_id': 'B',
            'username': 'user-b',
            'password': 'pass-b',
            'label': 'beta',
        }])

        # The wrapper preserves the original function signature.
        signature = inspect.signature(type(service).call)
        self.assertEqual(
            list(signature.parameters),
            ['self', 'request_id', 'func_username', 'func_password', 'label'])
        self.assertEqual(signature.parameters['label'].default, 'default')

    def test_interleaved_tasks_have_independent_injected_state(self):
        cache = RecordingCache('test', json.dumps({
            'username': 'user-x', 'password': 'pass-x'}))
        service = build_keyworded_service(cache)

        gate_a = asyncio.Event()
        gate_b = asyncio.Event()

        original_call = service.call

        async def call_a():
            result = await original_call('A', label='alpha')
            await gate_a.wait()
            return result

        async def call_b():
            result = await original_call('B', label='beta')
            await gate_b.wait()
            return result

        async def scenario():
            task_a = asyncio.ensure_future(call_a())
            await asyncio.sleep(0)  # let A resolve its secret and park on the gate
            task_b = asyncio.ensure_future(call_b())
            await asyncio.sleep(0)  # B resolves its own independent copy

            self.assertEqual(len(cache.access_log), 2)
            self.assertEqual(service.results[0]['request_id'], 'A')
            self.assertEqual(service.results[1]['request_id'], 'B')
            self.assertIsNot(service.results[0], service.results[1])
            self.assertEqual(service.results[0]['password'], 'pass-x')
            self.assertEqual(service.results[1]['password'], 'pass-x')

            # Releasing one task cannot mutate the other task's injected kwargs.
            gate_b.set()
            result_b = await task_b
            self.assertEqual(service.results[0]['request_id'], 'A')
            gate_a.set()
            result_a = await task_a
            return result_a, result_b

        result_a, result_b = asyncio.run(scenario())
        self.assertEqual(result_a, ('A', 'user-x', 'pass-x', 'alpha'))
        self.assertEqual(result_b, ('B', 'user-x', 'pass-x', 'beta'))
        self.assertEqual(len(cache.access_log), 2)

    def test_positional_injection_keeps_self_and_extra_args(self):
        cache = RecordingCache('test', 'raw-secret-value')
        service = build_positional_service(cache)

        coro = service.call('req', 'extra-1', mode='async')
        self.assertEqual(cache.access_log, [])  # no fetch until driven

        result = asyncio.run(coro)
        self.assertEqual(result, ('raw-secret-value', 'req', ('extra-1',), 'async'))
        self.assertEqual(cache.access_log, [{'secret_id': 'test', 'version': 1}])
        self.assertEqual(service.executed, ['req'])

    def test_sync_wrapper_still_works_after_async_changes(self):
        cache = RecordingCache('test', 'plain-secret')

        @InjectSecretString('test', cache)
        def sync_call(secret, value, keyword='kw'):
            return secret, value, keyword

        self.assertEqual(sync_call('v', keyword='kw2'), ('plain-secret', 'v', 'kw2'))
        self.assertEqual(len(cache.access_log), 1)
        self.assertEqual(
            list(inspect.signature(sync_call).parameters),
            ['secret', 'value', 'keyword'])

    def test_wrapper_does_not_retain_secret_on_public_attributes(self):
        secret_doc = {'username': 'user-leak', 'password': 'pass-leak'}
        cache = RecordingCache('test', json.dumps(secret_doc))
        service = build_keyworded_service(cache)

        asyncio.run(service.call('Z'))
        secret_material = ['user-leak', 'pass-leak']

        wrapper = type(service).call
        public_attrs = {
            key: value for key, value in vars(wrapper).items()
            if not key.startswith('__')
        }
        for value in public_attrs.values():
            for material in secret_material:
                self.assertNotIn(material, str(value))

        # The underlying wrapped function and its closure hold no resolved secret.
        wrapped = wrapper.__wrapped__
        for material in secret_material:
            self.assertNotIn(material, str(vars(wrapped)))
        closure_values = [
            cell.cell_contents for cell in (wrapped.__closure__ or [])
            if cell.cell_contents is not None
        ]
        for value in closure_values:
            for material in secret_material:
                self.assertNotIn(material, str(getattr(value, '__dict__', value)))

    def test_errors_carry_no_secret_material(self):
        cache = RecordingCache('test', 'not-json-at-all')

        @InjectKeywordedSecretString(secret_id='test', cache=cache,
                                     func_username='username')
        async def broken(func_username):
            return func_username

        coro = broken()
        self.assertEqual(cache.access_log, [])
        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(coro)
        self.assertEqual(str(ctx.exception), "Cached secret is not valid JSON")
        self.assertTrue(ctx.exception.__suppress_context__)
        self.assertNotIn('not-json-at-all', str(ctx.exception))

        cache.rotate(json.dumps({'other': 'present'}))
        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(broken())
        self.assertEqual(str(ctx.exception), "Cached secret does not contain key username")
        self.assertNotIn('present', str(ctx.exception))
