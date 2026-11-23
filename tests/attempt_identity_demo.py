"""
Observable demonstration of attempt identity handling.

Run with the repository test settings:

    PYTHONPATH=. .venv/bin/python tests/attempt_identity_demo.py

The script prints, for the two scenarios requested:

1. one password check reported through two login entry points;
2. two genuinely independent authentication attempts on one request.

For each scenario it shows the Axes lockout score
(``AccessAttempt.failures_since_start``) and, where applicable, the
rejection reason exposed to the user.
"""

import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
django.setup()

from django.contrib.auth.signals import user_login_failed
from django.http import HttpRequest
from django.test.runner import DiscoverRunner
from django.test.utils import setup_test_environment, teardown_test_environment
from django.utils.timezone import now

from axes.attempt_identity import (
    REQUEST_ATTRIBUTE,
    begin_attempt_identifier,
    mark_attempt_non_countable,
    reset_attempt_identifier,
)
from axes.helpers import (
    get_client_http_accept,
    get_client_ip_address,
    get_client_path_info,
    get_client_user_agent,
    get_credentials,
)
from axes.models import AccessAttempt


def build_request():
    request = HttpRequest()
    request.method = "POST"
    request.META["REMOTE_ADDR"] = "127.0.0.1"
    request.META["HTTP_USER_AGENT"] = "demo-agent"
    request.META["PATH_INFO"] = "/admin/login/"
    request.axes_attempt_time = now()
    request.axes_ip_address = get_client_ip_address(request)
    request.axes_user_agent = get_client_user_agent(request)
    request.axes_path_info = get_client_path_info(request)
    request.axes_http_accept = get_client_http_accept(request)
    request.axes_failures_since_start = None
    request.axes_locked_out = False
    return request


def report(sender, request, credentials):
    user_login_failed.send(
        sender=sender, credentials=credentials, request=request
    )


def main():
    runner = DiscoverRunner(verbosity=0)
    setup_test_environment()
    old_config = runner.setup_databases()
    try:
        credentials = get_credentials("demo-user", password="wrong-password")

        print("Scenario 1: one password check reported by TWO entry points")
        reset_attempt_identifier()
        request = build_request()
        identifier = begin_attempt_identifier()
        setattr(request, REQUEST_ATTRIBUTE, identifier)
        report("form-layer", request, credentials)
        report("authenticate-layer", request, credentials)
        attempt = AccessAttempt.objects.get()
        print(f"  lockout score: {attempt.failures_since_start} (expected 1)")
        print(
            "  rejection reason: standard credential failure, "
            f"locked_out={request.axes_locked_out}"
        )

        AccessAttempt.objects.all().delete()

        print("Scenario 2: TWO independent attempts on the same request")
        reset_attempt_identifier()
        request = build_request()
        first = begin_attempt_identifier()
        setattr(request, REQUEST_ATTRIBUTE, first)
        report("attempt-1", request, credentials)
        second = begin_attempt_identifier()
        setattr(request, REQUEST_ATTRIBUTE, second)
        report("attempt-2", request, credentials)
        attempt = AccessAttempt.objects.get()
        print(f"  distinct identities: {first != second}")
        print(f"  lockout score: {attempt.failures_since_start} (expected 2)")
        print(
            "  rejection reason: standard credential failure, "
            f"locked_out={request.axes_locked_out}"
        )

        AccessAttempt.objects.all().delete()

        print("Bonus: business rule rejection (not a wrong password)")
        reset_attempt_identifier()
        request = build_request()
        mark_attempt_non_countable(request, "Account is not verified.")
        report("business-rule", request, credentials)
        print(f"  AccessAttempt rows: {AccessAttempt.objects.count()} (expected 0)")
        print(
            "  rejection reason shown to the user: "
            f"{request.axes_non_countable_reason}"
        )
        print(f"  locked_out={request.axes_locked_out}")
    finally:
        runner.teardown_databases(old_config)
        teardown_test_environment()


if __name__ == "__main__":
    main()
