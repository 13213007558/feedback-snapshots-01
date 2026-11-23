# Test cases for https://identitydivision.visualstudio.com/devex/_git/AuthLibrariesApiReview?version=GBdev&path=%2FService%20protection%2FIntial%20set%20of%20protection%20measures.md&_a=preview&anchor=common-test-cases
import json
import pickle
from time import sleep
from random import random
import logging

from msal.throttled_http_client import (
    ThrottledHttpClientBase, ThrottledHttpClient, NormalizedResponse)
from msal.exceptions import MsalServiceError

from tests import unittest
from tests.http_client import MinimalResponse as _MinimalResponse


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class MinimalResponse(_MinimalResponse):
    SIGNATURE = str(random()).encode("utf-8")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ = (  # Only an instance attribute will be stored in pickled instance
            self.__class__.SIGNATURE)  # Useful for testing its presence in pickled instance


class DummyHttpClient(object):
    def __init__(self, status_code=None, response_headers=None, response_text=None):
        self._status_code = status_code
        self._response_headers = response_headers
        self._response_text = response_text

    def _build_dummy_response(self):
        return MinimalResponse(
            status_code=self._status_code,
            headers=self._response_headers,
            text=self._response_text if self._response_text is not None else str(
                random()  # So that we'd know whether a new response is received
            ),
        )

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        return self._build_dummy_response()

    def get(self, url, params=None, headers=None, **kwargs):
        return self._build_dummy_response()

    def close(self):
        raise CloseMethodCalled("Not used by MSAL, but our customers may use it")


class CloseMethodCalled(Exception):
    pass


class NormalizedResponseTestCase(unittest.TestCase):
    def test_pickled_minimal_response_should_contain_signature(self):
        self.assertIn(MinimalResponse.SIGNATURE, pickle.dumps(MinimalResponse(
            status_code=200, headers={}, text="foo")))

    def test_normalized_response_should_not_contain_signature(self):
        response = NormalizedResponse(MinimalResponse(
            status_code=200, headers={}, text="foo"))
        self.assertNotIn(
            MinimalResponse.SIGNATURE, pickle.dumps(response),
            "A pickled object should not contain undesirable data")
        self.assertEqual(response.text, "foo", "Should return the same response text")

    def test_normalized_response_raise_for_status_should_raise(self):
        response = NormalizedResponse(MinimalResponse(
            status_code=400, headers={}, text="foo"))
        with self.assertRaises(MsalServiceError):
            response.raise_for_status()


class ThrottledHttpClientBaseTestCase(unittest.TestCase):

    def assertCleanPickle(self, obj):
        self.assertTrue(bool(obj), "The object should not be empty")
        self.assertNotIn(
            MinimalResponse.SIGNATURE, pickle.dumps(obj),
            "A pickled object should not contain undesirable data")

    def assertValidResponse(self, response):
        self.assertIsInstance(response, NormalizedResponse)
        self.assertCleanPickle(response)

    def test_throttled_http_client_base_response_should_tolerate_headerless_response(self):
        # MSAL Python 1.32.1 had a regression that caused it to require headers in the response.
        # This was fixed in 1.32.2
        # https://github.com/AzureAD/microsoft-authentication-library-for-python/compare/1.32.1...1.32.2
        # This test case is to ensure that we can tolerate headerless response.
        http_client = DummyHttpClient(status_code=200, response_text="foo")
        raw_response = http_client.post("https://example.com")
        self.assertFalse(hasattr(raw_response, "headers"), "Should not contain headers")
        response = ThrottledHttpClientBase(http_client).post("https://example.com")
        self.assertEqual(response.text, "foo", "Should return the same response text")

    def test_throttled_http_client_base_response_should_not_contain_signature(self):
        http_client = ThrottledHttpClientBase(DummyHttpClient(status_code=200))
        response = http_client.post("https://example.com")
        self.assertValidResponse(response)

    def assertNotAlteringOriginalHttpClient(self, ThrottledHttpClientClass):
        original_http_client = DummyHttpClient()
        original_get = original_http_client.get
        original_post = original_http_client.post
        throttled_http_client = ThrottledHttpClientClass(original_http_client)
        goal = """The implementation should wrap original http_client
            and keep it intact, instead of monkey-patching it"""
        self.assertNotEqual(throttled_http_client, original_http_client, goal)
        self.assertEqual(original_post, original_http_client.post)
        self.assertEqual(original_get, original_http_client.get)

    def test_throttled_http_client_base_should_not_alter_original_http_client(self):
        self.assertNotAlteringOriginalHttpClient(ThrottledHttpClientBase)

    def test_throttled_http_client_base_should_not_nest_http_client(self):
        original_http_client = DummyHttpClient()
        throttled_http_client = ThrottledHttpClientBase(original_http_client)
        self.assertIs(original_http_client, throttled_http_client.http_client)
        nested_throttled_http_client = ThrottledHttpClientBase(throttled_http_client)
        self.assertIs(original_http_client, nested_throttled_http_client.http_client)


class ThrottledHttpClientTestCase(ThrottledHttpClientBaseTestCase):

    def test_throttled_http_client_should_not_alter_original_http_client(self):
        self.assertNotAlteringOriginalHttpClient(ThrottledHttpClient)

    def _test_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(
            self, http_client, retry_after):
        http_cache = {}
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)
        resp1 = http_client.post("https://example.com")  # We implemented POST only
        resp2 = http_client.post("https://example.com")  # We implemented POST only
        logger.debug(http_cache)
        self.assertEqual(resp1.text, resp2.text, "Should return a cached response")
        sleep(retry_after + 1)
        resp3 = http_client.post("https://example.com")  # We implemented POST only
        self.assertNotEqual(resp1.text, resp3.text, "Should return a new response")

    def test_429_with_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(self):
        retry_after = 1
        self._test_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(
            DummyHttpClient(
                status_code=429, response_headers={"Retry-After": retry_after}),
            retry_after)

    def test_5xx_with_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(self):
        retry_after = 1
        self._test_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(
            DummyHttpClient(
                status_code=503, response_headers={"Retry-After": retry_after}),
            retry_after)

    def test_400_with_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(self):
        """Retry-After is supposed to only shown in http 429/5xx,
        but we choose to support Retry-After for arbitrary http response."""
        retry_after = 1
        self._test_RetryAfter_N_seconds_should_keep_entry_for_N_seconds(
            DummyHttpClient(
                status_code=400, response_headers={"Retry-After": retry_after}),
            retry_after)

    def test_one_RetryAfter_request_should_block_a_similar_request(self):
        http_cache = {}
        http_client = DummyHttpClient(
            status_code=429, response_headers={"Retry-After": 2})
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)
        resp1 = http_client.post("https://example.com", data={
            "scope": "one", "claims": "bar", "grant_type": "authorization_code"})
        resp2 = http_client.post("https://example.com", data={
            "scope": "one", "claims": "foo", "grant_type": "password"})
        logger.debug(http_cache)
        self.assertEqual(resp1.text, resp2.text, "Should return a cached response")

    def test_one_RetryAfter_request_should_not_block_a_different_request(self):
        http_cache = {}
        http_client = DummyHttpClient(
            status_code=429, response_headers={"Retry-After": 2})
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)
        resp1 = http_client.post("https://example.com", data={"scope": "one"})
        resp2 = http_client.post("https://example.com", data={"scope": "two"})
        logger.debug(http_cache)
        self.assertNotEqual(resp1.text, resp2.text, "Should return a new response")

    def test_one_invalid_grant_should_block_a_similar_request(self):
        http_cache = {}
        http_client = DummyHttpClient(
            status_code=400)  # It covers invalid_grant and interaction_required
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)

        resp1 = http_client.post("https://example.com", data={"claims": "foo"})
        logger.debug(http_cache)
        self.assertValidResponse(resp1)
        resp1_again = http_client.post("https://example.com", data={"claims": "foo"})
        self.assertValidResponse(resp1_again)
        self.assertEqual(resp1.text, resp1_again.text, "Should return a cached response")

        resp2 = http_client.post("https://example.com", data={"claims": "bar"})
        self.assertValidResponse(resp2)
        self.assertNotEqual(resp1.text, resp2.text, "Should return a new response")
        resp2_again = http_client.post("https://example.com", data={"claims": "bar"})
        self.assertValidResponse(resp2_again)
        self.assertEqual(resp2.text, resp2_again.text, "Should return a cached response")

        self.assertCleanPickle(http_cache)

    def test_one_foci_app_recovering_from_invalid_grant_should_also_unblock_another(self):
        """
        Need not test multiple FOCI app's acquire_token_silent() here. By design,
        one FOCI app's successful populating token cache would result in another
        FOCI app's acquire_token_silent() to hit a token without invoking http request.
        """

    def test_forcefresh_behavior(self):
        """
        The implementation let token cache and http cache operate in different
        layers. They do not couple with each other.
        Therefore, acquire_token_silent(..., force_refresh=True)
        would bypass the token cache yet technically still hit the http cache.

        But that is OK, cause the customer need no force_refresh in the first place.
        After a successful AT/RT acquisition, AT/RT will be in the token cache,
        and a normal acquire_token_silent(...) without force_refresh would just work.
        This was discussed in https://identitydivision.visualstudio.com/DevEx/_git/AuthLibrariesApiReview/pullrequest/3618?_a=files
        """

    def test_http_get_200_should_be_cached(self):
        http_cache = {}
        http_client = DummyHttpClient(
            status_code=200)  # It covers UserRealm discovery and OIDC discovery
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)
        resp1 = http_client.get("https://example.com?foo=bar")
        resp2 = http_client.get("https://example.com?foo=bar")
        logger.debug(http_cache)
        self.assertEqual(resp1.text, resp2.text, "Should return a cached response")

    def test_device_flow_retry_should_not_be_cached(self):
        DEVICE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
        http_cache = {}
        http_client = DummyHttpClient(status_code=400)
        http_client = ThrottledHttpClient(http_client, http_cache=http_cache)
        resp1 = http_client.post(
            "https://example.com", data={"grant_type": DEVICE_AUTH_GRANT})
        resp2 = http_client.post(
            "https://example.com", data={"grant_type": DEVICE_AUTH_GRANT})
        logger.debug(http_cache)
        self.assertNotEqual(resp1.text, resp2.text, "Should return a new response")

    def test_throttled_http_client_should_provide_close(self):
        http_client = DummyHttpClient(status_code=200)
        http_client = ThrottledHttpClient(http_client)
        with self.assertRaises(CloseMethodCalled):
            http_client.close()



class FakeClock(object):
    def __init__(self, now=1_700_000_000):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class ScriptedHttpClient(object):
    """A transport whose responses are scripted per (host, tenant).

    It counts only real transport attempts, which is what the acceptance
    evidence needs: a locally throttled request must not appear as a send.
    """
    def __init__(self, responses):
        self.responses = responses
        self.sent = []

    def _respond(self, url, data):
        host = url.split("://", 1)[-1].split("/", 1)[0]
        segments = [s for s in url.split("://", 1)[-1].split("/", 1)[-1].split("/") if s]
        tenant = segments[0] if segments else ""
        self.sent.append((host, tenant))
        status, headers, text = self.responses.get(
            (host, tenant), (200, {}, '{"access_token": "AT-%s-%s"}' % (host, tenant)))
        return MinimalResponse(status_code=status, headers=headers, text=text)

    def post(self, url, params=None, data=None, headers=None, **kwargs):
        return self._respond(url, data)

    def get(self, url, params=None, headers=None, **kwargs):
        return self._respond(url, None)

    def close(self):
        pass


class ScopedThrottleClockTestCase(unittest.TestCase):
    """Clock-driven evidence for tenant, service, and release behavior."""

    TENANT_A = "tenant-a"
    TENANT_B = "tenant-b"

    def setUp(self):
        self.clock = FakeClock()
        self.cache = {}
        self.transport = ScriptedHttpClient({
            # Alias one for tenant A: a tenant-scoped 429 for 30 seconds.
            ("login.windows.net", self.TENANT_A):
                (429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, ""),
        })
        self.client = ThrottledHttpClient(
            self.transport, http_cache=self.cache, clock=self.clock)

    def _post(self, host, tenant):
        return self.client.post(
            "https://{}/{}/oauth2/v2.0/token".format(host, tenant),
            data={"client_id": "c", "scope": "s", "grant_type": "client_credentials"})

    def _hosts_sent(self):
        return [(host, tenant) for host, tenant in self.transport.sent]

    def test_tenant_throttle_blocks_both_aliases_of_that_tenant_only(self):
        first = self._post("login.windows.net", self.TENANT_A)
        self.assertEqual(429, first.status_code)

        # Same tenant through a different, equivalent host: still local clock.
        alias_two = self._post("login.microsoftonline.com", self.TENANT_A)
        self.assertEqual(429, alias_two.status_code)

        # Another tenant on the very same host keeps going.
        other = self._post("login.windows.net", self.TENANT_B)
        self.assertEqual(200, other.status_code)
        self.assertEqual(
            [("login.windows.net", self.TENANT_A),
             ("login.windows.net", self.TENANT_B)],
            self._hosts_sent(),
            "Only the first tenant-A send and the tenant-B send reached transport")

    def test_tenant_throttle_does_not_block_a_shared_global_tenant(self):
        self._post("login.windows.net", self.TENANT_A)
        common = self._post("login.microsoftonline.com", "common")
        self.assertEqual(200, common.status_code)

    def test_concrete_tenant_url_attributes_a_429_without_a_scope_header(self):
        self.transport.responses[("login.windows.net", "tenant-c")] = (
            429, {"Retry-After": "30"}, "")
        self.assertEqual(429, self._post("login.windows.net", "tenant-c").status_code)
        # A concrete tenant in the URL makes it attributable, so its aliases wait...
        self.assertEqual(
            429, self._post("login.microsoftonline.com", "tenant-c").status_code)
        # ...but a different tenant on the same host continues.
        self.assertEqual(
            200, self._post("login.windows.net", "tenant-d").status_code)
        self.assertEqual(2, len(self._hosts_sent()))

    def test_service_throttle_blocks_every_tenant_and_alias(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            503, {"Retry-After": "20"}, "")
        self.assertEqual(503, self._post("login.windows.net", self.TENANT_A).status_code)

        # The identical request may be served from the per-request cache, but
        # in any case it must not reach the transport again.
        self.assertIn(
            self._post("login.windows.net", self.TENANT_A).status_code, (429, 503))
        for host, tenant in [
                ("login.microsoftonline.com", self.TENANT_A),
                ("login.microsoftonline.com", self.TENANT_B),
                ("login.microsoft.com", self.TENANT_B),
                ]:
            self.assertEqual(429, self._post(host, tenant).status_code)

        self.assertEqual(
            [("login.windows.net", self.TENANT_A)], self._hosts_sent(),
            "A platform failure must stop every qualified request for this service")

    def test_global_scope_429_blocks_every_tenant_and_alias(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            429, {"Retry-After": "20", "x-ms-throttle-scope": "global"}, "")
        self._post("login.windows.net", self.TENANT_A)
        self.assertEqual(
            429, self._post("login.microsoftonline.com", self.TENANT_B).status_code)
        self.assertEqual(
            [("login.windows.net", self.TENANT_A)], self._hosts_sent())

    def test_release_times_are_honored_per_scope(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, "")
        self._post("login.windows.net", self.TENANT_A)

        self.clock.advance(10)
        diagnostics = self.client.throttle_diagnostics()
        self.assertEqual(20, diagnostics["tenant"]["release_in"])
        self.assertEqual(0, diagnostics["service"]["release_in"])

        self.clock.advance(20)  # Exactly at the deadline: next send is allowed
        self.assertEqual(200, self._post("login.microsoftonline.com", self.TENANT_A).status_code)
        self.assertEqual(2, len(self._hosts_sent()))

    def test_stacked_tenant_then_service_deadlines_each_hold(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, "")
        self._post("login.windows.net", self.TENANT_A)

        self.clock.advance(5)
        self.transport.responses[("login.microsoftonline.com", self.TENANT_B)] = (
            500, {"Retry-After": "60"}, "")
        self.assertEqual(500, self._post("login.microsoftonline.com", self.TENANT_B).status_code)

        self.clock.advance(25)  # Tenant A released, service still holds
        self.assertEqual(429, self._post("login.microsoftonline.com", self.TENANT_A).status_code)
        self.assertEqual(429, self._post("login.microsoft.com", self.TENANT_B).status_code)
        self.assertEqual(35, self.client.throttle_diagnostics()["service"]["release_in"])

        self.clock.advance(35)
        self.assertEqual(200, self._post("login.microsoft.com", self.TENANT_B).status_code)
        self.assertEqual(200, self._post("login.microsoftonline.com", self.TENANT_A).status_code)

    def test_local_block_does_not_extend_its_own_deadline(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, "")
        self._post("login.windows.net", self.TENANT_A)
        self.clock.advance(10)
        self.assertEqual(429, self._post("login.windows.net", self.TENANT_A).status_code)
        # If a synthetic block were cached, it would now extend past 30.
        self.assertEqual(20, self.client.throttle_diagnostics()["tenant"]["release_in"])

    def test_cached_error_replay_does_not_rearm_the_deadline(self):
        self.transport.responses[("login.windows.net", self.TENANT_A)] = (
            429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, "")
        self._post("login.windows.net", self.TENANT_A)
        self.clock.advance(10)
        # This identical request is served from the per-request cache, not
        # from transport, and must not move the upstream release time.
        self.assertEqual(429, self._post("login.windows.net", self.TENANT_A).status_code)
        self.assertEqual(20, self.client.throttle_diagnostics()["tenant"]["release_in"])
        self.assertEqual(1, len(self._hosts_sent()))

    def test_diagnostics_expose_only_allowed_categories(self):
        self._post("login.windows.net", self.TENANT_A)
        payload = json.dumps(self.client.throttle_diagnostics())
        self.assertEqual({"tenant", "service"}, set(self.client.throttle_diagnostics()))
        for forbidden in (self.TENANT_A, "login.windows.net", "client_id",
                          "retry-after", "token"):
            self.assertNotIn(forbidden, payload)

    def test_alias_group_can_come_from_caller_supplied_metadata(self):
        clock = FakeClock()
        transport = ScriptedHttpClient({
            ("private-alias-1.example", "tenant-a"):
                (429, {"Retry-After": "30", "x-ms-throttle-scope": "tenant"}, ""),
        })
        client = ThrottledHttpClient(
            transport, clock=clock,
            authority_aliases={"private-alias-1.example": "private-auth.example",
                               "private-alias-2.example": "private-auth.example"})
        client.post("https://private-alias-1.example/tenant-a/token", data={})
        self.assertEqual(
            429,
            client.post("https://private-alias-2.example/tenant-a/token", data={}).status_code)
        self.assertEqual(
            200,
            client.post("https://private-alias-2.example/tenant-b/token", data={}).status_code)
        self.assertEqual(2, len(transport.sent))
