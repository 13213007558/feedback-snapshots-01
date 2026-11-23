"""Acceptance tests for per-request Proof-of-Possession (PoP) binding.

Scenario (from the security review that motivated this change):

A terminal-management tool only needs a bound Proof-of-Possession credential
for a few mutating or sensitive actions, while most of its traffic keeps using
plain bearer access tokens. The business may issue two operations against the
same account and the same scopes at once -- e.g. a status query (GET) and a
change submission (POST), each carrying its own resource challenge nonce.

The two operations must never share or swap their bound credentials, even when
the responses come back out of order. These tests use a fake in-memory broker
(``tests.fake_pymsalruntime``) and two locally pre-approved requests to record,
for each operation:

* the actual broker method that served it;
* which challenge (method/host/path/nonce) the credential was bound to;
* the type of credential returned (``pop`` vs ``bearer``);
* the calling eligibility -- whether the result is still valid for the
  originating operation once results are matched in reverse order.

Everything runs offline; the native ``pymsalruntime`` package is never needed.
"""
import importlib
import json
import sys
import threading
from unittest.mock import patch, Mock

from msal.oauth2cli.oidc import decode_part

from tests import unittest
from tests import fake_pymsalruntime as fake_broker


CLIENT_ID = "fake-terminal-management-client"
AUTHORITY = "https://login.microsoftonline.com/contoso"
SCOPES = ["https://terminal.contoso.com/.default"]

# Two operations sharing account + scopes, distinguished only by their binding.
STATUS_OPERATION = {
    "name": "status-query",
    "http_method": "GET",
    "url": "https://terminal.contoso.com/v1/devices/42/status?verbose=true",
    "nonce": "nonce-status-0001",
}
CHANGE_OPERATION = {
    "name": "change-submission",
    "http_method": "POST",
    "url": "https://terminal.contoso.com/v1/devices/42/config",
    "nonce": "nonce-change-0002",
}

_OIDC_DISCOVERY_MOCK = Mock(return_value={
    "authorization_endpoint": "https://login.microsoftonline.com/placeholder",
    "token_endpoint": "https://login.microsoftonline.com/placeholder",
    "issuer": "https://login.microsoftonline.com/placeholder",
})


def _auth_scheme(operation):
    import msal
    return msal.PopAuthScheme(
        http_method=operation["http_method"],
        url=operation["url"],
        nonce=operation["nonce"],
    )


def _decode_shr(access_token):
    return json.loads(decode_part(access_token.split(".")[1]))


class PopBindingTestCase(unittest.TestCase):

    def setUp(self):
        # Class-level @patch decorators do not run while setUp() executes, so
        # the patches that app construction depends on are started explicitly.
        self._patchers = [
            patch("sys.platform", new="darwin"),
            patch("msal.application.platform.machine",
                  new=Mock(return_value="arm64")),
            patch("msal.authority.tenant_discovery", new=_OIDC_DISCOVERY_MOCK),
        ]
        for patcher in self._patchers:
            patcher.start()
        self.addCleanup(self._stop_patchers)
        # Install the fake broker and bind msal.broker to it. The native
        # pymsalruntime package does not exist in this offline environment, so
        # the fake stays registered for the whole test session; its mutable
        # state is reset here before every test.
        fake_broker.FakeRuntimeState.reset()
        sys.modules["pymsalruntime"] = fake_broker
        import msal.broker
        importlib.reload(msal.broker)
        for operation in (STATUS_OPERATION, CHANGE_OPERATION):
            scheme = _auth_scheme(operation)
            fake_broker.FakeRuntimeState.approve(
                scheme._http_method, scheme._url.netloc,
                scheme._url.path, scheme._nonce)
        import msal
        self.app = msal.PublicClientApplication(
            CLIENT_ID, authority=AUTHORITY,
            instance_discovery=False,  # Keep the acceptance fully offline
            enable_broker_on_mac=True)
        self.assertTrue(self.app._enable_broker)
        self.account = self._establish_broker_account()

    def _stop_patchers(self):
        for patcher in self._patchers:
            patcher.stop()

    def _establish_broker_account(self):
        """Run one interactive sign-in so a broker account exists locally."""
        result = self.app.acquire_token_interactive(
            SCOPES,
            parent_window_handle=self.app.CONSOLE_WINDOW_HANDLE,
            )
        self.assertNotIn("error", result, result)
        accounts = self.app.get_accounts()
        self.assertEqual(1, len(accounts))
        return accounts[0]

    def _acquire_pop_silently(self, operation):
        return self.app.acquire_token_silent(
            SCOPES, account=self.account, auth_scheme=_auth_scheme(operation))

    def _binding_from_call(self, operation):
        scheme = _auth_scheme(operation)
        return (scheme._http_method, scheme._url.netloc,
                scheme._url.path, scheme._nonce)

    def _record_outcome(self, operation, result):
        """Build the four-field acceptance record for one operation."""
        shr = _decode_shr(result["access_token"])
        expected_binding = self._binding_from_call(operation)
        broker_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "acquire_token_silently"
            and call["pop"]
            and (call["pop"]["http_method"], call["pop"]["host"],
                 call["pop"]["path"], call["pop"]["nonce"]) == expected_binding
            )
        eligibility = (
            result["token_type"] == "pop"
            and (shr["m"], shr["u"], shr["p"], shr["nonce"])
                == expected_binding
        )
        return {
            "operation": operation["name"],
            "actual_method": broker_call["method"],
            "challenge_owner": (
                broker_call["pop"]["http_method"],
                broker_call["pop"]["host"],
                broker_call["pop"]["path"],
                broker_call["pop"]["nonce"],
            ),
            "credential_type": result["token_type"],
            "eligible_for_this_operation": eligibility,
            "shr": shr,
        }

    def test_two_approved_requests_keep_distinct_bound_credentials(self):
        records = [
            self._record_outcome(
                STATUS_OPERATION, self._acquire_pop_silently(STATUS_OPERATION)),
            self._record_outcome(
                CHANGE_OPERATION, self._acquire_pop_silently(CHANGE_OPERATION)),
        ]
        for record, operation in zip(records, (STATUS_OPERATION, CHANGE_OPERATION)):
            self.assertEqual("acquire_token_silently", record["actual_method"])
            self.assertEqual(
                self._binding_from_call(operation), record["challenge_owner"])
            self.assertEqual("pop", record["credential_type"])
            self.assertTrue(record["eligible_for_this_operation"])
        # Same account + scopes, yet the two SHRs must not be interchangeable.
        self.assertNotEqual(
            records[0]["shr"]["nonce"], records[1]["shr"]["nonce"])
        self.assertNotEqual(records[0]["shr"]["m"], records[1]["shr"]["m"])
        status_tokens = [
            call for call in fake_broker.FakeRuntimeState.calls
            if call["pop"] and call["pop"]["nonce"] == STATUS_OPERATION["nonce"]]
        change_tokens = [
            call for call in fake_broker.FakeRuntimeState.calls
            if call["pop"] and call["pop"]["nonce"] == CHANGE_OPERATION["nonce"]]
        self.assertTrue(status_tokens and change_tokens)
        self.assertNotEqual(
            status_tokens[0]["pop"], change_tokens[0]["pop"])

    def test_acceptance_records_capture_method_challenge_credential_eligibility(self):
        """Emit the four acceptance fields for each pre-approved request."""
        acceptance_records = [
            self._record_outcome(
                STATUS_OPERATION, self._acquire_pop_silently(STATUS_OPERATION)),
            self._record_outcome(
                CHANGE_OPERATION, self._acquire_pop_silently(CHANGE_OPERATION)),
        ]
        for record in acceptance_records:
            self.assertEqual(
                {"operation", "actual_method", "challenge_owner",
                 "credential_type", "eligible_for_this_operation", "shr"},
                set(record))
        # Visible acceptance evidence (run with pytest -s).
        for record in acceptance_records:
            print(
                "\nacceptance-record operation={operation} "
                "actual_method={actual_method} challenge_owner={challenge_owner} "
                "credential_type={credential_type} "
                "eligible_for_this_operation={eligible}".format(
                    operation=record["operation"],
                    actual_method=record["actual_method"],
                    challenge_owner=record["challenge_owner"],
                    credential_type=record["credential_type"],
                    eligible=record["eligible_for_this_operation"]))
        self.assertEqual(
            ["status-query", "change-submission"],
            [record["operation"] for record in acceptance_records])
        self.assertTrue(all(
            record["actual_method"] == "acquire_token_silently"
            and record["credential_type"] == "pop"
            and record["eligible_for_this_operation"]
            for record in acceptance_records))

    def test_reverse_arrival_still_matches_each_result_to_its_operation(self):
        results = {}
        barrier = threading.Event()

        def worker(operation):
            barrier.wait()  # Launch both operations concurrently.
            results[operation["name"]] = self._acquire_pop_silently(operation)

        threads = [
            threading.Thread(target=worker, args=(STATUS_OPERATION,)),
            threading.Thread(target=worker, args=(CHANGE_OPERATION,)),
        ]
        for thread in threads:
            thread.start()
        barrier.set()
        for thread in threads:
            thread.join()
        self.assertEqual(2, len(results))

        # The caller receives them in reverse order (change first, status after)
        # and re-derives eligibility from each credential's own binding.
        arrival_order = [CHANGE_OPERATION, STATUS_OPERATION]
        eligibility_report = []
        for operation in arrival_order:
            result = results[operation["name"]]
            shr = _decode_shr(result["access_token"])
            scheme = _auth_scheme(operation)
            eligible = (
                shr["m"] == scheme._http_method
                and shr["u"] == scheme._url.netloc
                and shr["p"] == scheme._url.path
                and shr["nonce"] == scheme._nonce)
            eligibility_report.append((operation["name"], eligible, shr["nonce"]))
            self.assertTrue(
                eligible,
                msg="Result delivered for {!r} is bound to {!r}".format(
                    operation["name"], shr))
        self.assertEqual(
            ["change-submission", "status-query"],
            [row[0] for row in eligibility_report])
        self.assertTrue(all(row[1] for row in eligibility_report))
        self.assertEqual(
            ["nonce-change-0002", "nonce-status-0001"],
            [row[2] for row in eligibility_report])

    def test_interactive_broker_path_also_preserves_binding(self):
        # With no explicit prompt the interactive API first attempts a silent
        # broker sign-in, which is itself a broker entry point and must carry
        # the same per-request PoP binding.
        result = self.app.acquire_token_interactive(
            SCOPES,
            parent_window_handle=self.app.CONSOLE_WINDOW_HANDLE,
            auth_scheme=_auth_scheme(CHANGE_OPERATION),
            )
        self.assertNotIn("error", result, result)
        self.assertEqual("pop", result["token_type"])
        self.assertEqual("broker", result["token_source"])
        shr = _decode_shr(result["access_token"])
        scheme = _auth_scheme(CHANGE_OPERATION)
        self.assertEqual(scheme._http_method, shr["m"])
        self.assertEqual(scheme._url.netloc, shr["u"])
        self.assertEqual(scheme._url.path, shr["p"])
        self.assertEqual(scheme._nonce, shr["nonce"])
        silent_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "signin_silently" and call["pop"])
        self.assertEqual(
            (scheme._http_method, scheme._url.netloc,
             scheme._url.path, scheme._nonce),
            (silent_call["pop"]["http_method"], silent_call["pop"]["host"],
             silent_call["pop"]["path"], silent_call["pop"]["nonce"]))

    def test_interactive_ui_broker_path_preserves_binding(self):
        # Forcing the account picker drives the genuinely interactive broker
        # entry point (_signin_interactively).
        result = self.app.acquire_token_interactive(
            SCOPES,
            prompt="select_account",
            parent_window_handle=self.app.CONSOLE_WINDOW_HANDLE,
            auth_scheme=_auth_scheme(STATUS_OPERATION),
            )
        self.assertNotIn("error", result, result)
        self.assertEqual("pop", result["token_type"])
        scheme = _auth_scheme(STATUS_OPERATION)
        interactive_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "signin_interactively")
        self.assertEqual(
            (scheme._http_method, scheme._url.netloc,
             scheme._url.path, scheme._nonce),
            (interactive_call["pop"]["http_method"],
             interactive_call["pop"]["host"],
             interactive_call["pop"]["path"],
             interactive_call["pop"]["nonce"]))

    def test_unapproved_challenge_fails_controlled_without_bearer_downgrade(self):
        import msal
        rogue = {
            "name": "unapproved",
            "http_method": "DELETE",
            "url": "https://terminal.contoso.com/v1/devices/42",
            "nonce": "nonce-rogue-9999",
        }
        result = self.app.acquire_token_silent(
            SCOPES, account=self.account, auth_scheme=_auth_scheme(rogue))
        # The fake broker rejects the unapproved challenge; MSAL must surface
        # a controlled error rather than handing back an unbound bearer token.
        self.assertIsNone(result, "acquire_token_silent collapses errors to None")
        detailed = self.app.acquire_token_silent_with_error(
            SCOPES, account=self.account, auth_scheme=_auth_scheme(rogue))
        self.assertEqual("broker_error", detailed.get("error"))
        self.assertNotEqual("bearer", detailed.get("token_type"))
        self.assertNotIn("access_token", detailed)

    def test_silent_broker_failure_is_controlled_and_never_a_bearer_token(self):
        # For a broker-established account the broker owns the decisive
        # outcome: a silent failure comes back as a broker_error dict rather
        # than being masked, and no unbound bearer token is ever substituted.
        fake_broker.FakeRuntimeState.fail_next_silent = 1
        detailed = self.app.acquire_token_silent_with_error(
            SCOPES, account=self.account,
            auth_scheme=_auth_scheme(STATUS_OPERATION))
        self.assertEqual("broker_error", detailed.get("error"))
        self.assertNotIn("access_token", detailed)
        self.assertNotEqual("bearer", detailed.get("token_type"))
        # The friendlier API collapses the same controlled failure to None.
        fake_broker.FakeRuntimeState.fail_next_silent = 1
        self.assertIsNone(self.app.acquire_token_silent(
            SCOPES, account=self.account,
            auth_scheme=_auth_scheme(STATUS_OPERATION)))
        # The failed broker attempt still carried this operation's binding.
        failed_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "acquire_token_silently" and call["pop"])
        scheme = _auth_scheme(STATUS_OPERATION)
        self.assertEqual(scheme._nonce, failed_call["pop"]["nonce"])
        self.assertEqual(scheme._http_method, failed_call["pop"]["http_method"])

    def test_unbound_non_broker_fallback_preserves_binding_in_error(self):
        # Simulate the controlled fallback when the broker is deactivated yet
        # the account did not originate from it: the non-broker path cannot
        # mint a PoP token, so it raises a ValueError that names the exact
        # request binding the caller asked for.
        self.app._enable_broker = False
        legacy_account = dict(self.account, account_source=None)
        with self.assertRaises(ValueError) as context:
            self.app.acquire_token_silent_with_error(
                SCOPES, account=legacy_account,
                auth_scheme=_auth_scheme(STATUS_OPERATION))
        message = str(context.exception)
        scheme = _auth_scheme(STATUS_OPERATION)
        self.assertIn(scheme._http_method, message)
        self.assertIn(scheme._url.netloc, message)
        self.assertIn(scheme._nonce, message)

    def test_signout_keeps_broker_surface_wired_to_fake(self):
        self.app.remove_account(self.account)
        signout_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "signout_silently")
        self.assertEqual(
            self.account["local_account_id"], signout_call["account_id"])
        self.assertEqual([], self.app.get_accounts())

    def test_plain_bearer_entry_point_still_works_alongside_pop(self):
        # The first silent look-up reuses the ordinary bearer access token that
        # the bootstrap sign-in placed in the MSAL cache.
        cached = self.app.acquire_token_silent(
            SCOPES, account=self.account)
        self.assertNotIn("error", cached, cached)
        self.assertEqual("bearer", cached["token_type"])
        self.assertEqual("cache", cached["token_source"])

        # force_refresh bypasses the cache and goes back to the broker, which
        # keeps serving plain bearer tokens to the non-PoP entry point.
        result = self.app.acquire_token_silent(
            SCOPES, account=self.account, force_refresh=True)
        self.assertNotIn("error", result, result)
        self.assertEqual("bearer", result["token_type"])
        self.assertEqual("broker", result["token_source"])
        bearer_call = next(
            call for call in reversed(fake_broker.FakeRuntimeState.calls)
            if call["method"] == "acquire_token_silently")
        self.assertIsNone(bearer_call["pop"])
        # Then a PoP operation still returns its own bound credential.
        pop_result = self._acquire_pop_silently(CHANGE_OPERATION)
        self.assertEqual("pop", pop_result["token_type"])
        self.assertNotEqual(
            result["access_token"], pop_result["access_token"])


class BrokerInitializationFallbackTestCase(unittest.TestCase):
    """The other controlled fallback: broker opted-in but unavailable at init."""

    def _make_deactivated_broker_app(self):
        import msal
        with patch("sys.platform", new="darwin"), \
                patch("msal.application.platform.machine",
                      new=Mock(return_value="arm64")), \
                patch("msal.authority.tenant_discovery",
                      new=_OIDC_DISCOVERY_MOCK), \
                patch("msal.application._init_broker",
                      new=Mock(side_effect=RuntimeError("broker unavailable"))):
            app = msal.PublicClientApplication(
                CLIENT_ID, authority=AUTHORITY,
                instance_discovery=False,  # Keep the test offline
                enable_broker_on_mac=True)
        return app

    def test_pop_request_errors_with_binding_when_broker_unavailable(self):
        app = self._make_deactivated_broker_app()
        self.assertFalse(app._enable_broker)
        account = {"home_account_id": "uid.utid", "local_account_id": "local",
                   "account_source": "broker", "authority_type": "MSSTS"}
        with patch("sys.platform", new="darwin"), \
                patch("msal.application.platform.machine",
                      new=Mock(return_value="arm64")):
            with self.assertRaises(ValueError) as context:
                app.acquire_token_silent_with_error(
                    SCOPES, account=account,
                    auth_scheme=_auth_scheme(STATUS_OPERATION))
        message = str(context.exception)
        self.assertIn(STATUS_OPERATION["nonce"], message)
        self.assertIn(STATUS_OPERATION["http_method"], message)

    def test_bearer_request_still_allowed_after_broker_deactivation(self):
        app = self._make_deactivated_broker_app()
        self.assertFalse(app._enable_broker)
        # No RT exists locally, so the non-broker path reports a clean
        # cache-miss/error rather than a PoP-related ValueError.
        self.assertIsNone(app.acquire_token_silent(SCOPES, account=None))

    def test_ropc_pop_request_errors_with_binding_when_broker_unavailable(self):
        app = self._make_deactivated_broker_app()
        with patch("sys.platform", new="darwin"), \
                patch("msal.application.platform.machine",
                      new=Mock(return_value="arm64")):
            with self.assertRaises(ValueError) as context:
                app.acquire_token_by_username_password(
                    "operator@contoso.com", "placeholder-password",
                    SCOPES, auth_scheme=_auth_scheme(CHANGE_OPERATION))
        message = str(context.exception)
        self.assertIn(CHANGE_OPERATION["nonce"], message)
        self.assertIn(CHANGE_OPERATION["http_method"], message)
        self.assertIn(CHANGE_OPERATION["url"], message)
