from __future__ import annotations

import random
from typing import TYPE_CHECKING

from django.conf import settings

from csp.middleware import CSPMiddleware, PolicyParts

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


class RateLimitedCSPMiddleware(CSPMiddleware):
    """A CSP middleware that rate-limits the number of violation reports sent
    to report-uri by excluding it from some requests."""

    def get_policy_parts(self, request: HttpRequest, response: HttpResponseBase, report_only: bool = False) -> PolicyParts:
        policy_parts = super().get_policy_parts(request, response, report_only)

        csp_setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
        policy = getattr(settings, csp_setting_name, None)
        if policy is None:
            return policy_parts

        # `random.random` returns a value in the range [0.0, 1.0) so all values will be < 100.0.
        remove_report = random.random() * 100 >= policy.get("REPORT_PERCENTAGE", 100)
        if remove_report:
            # Copy any existing replace config rather than mutating it: it may be
            # a shared object (e.g. a dict reused by view decorators across requests),
            # and the omission must only apply to this response.
            replace = dict(policy_parts.replace) if policy_parts.replace else {}
            replace.update(
                {
                    "report-uri": None,
                    "report-to": None,
                }
            )
            policy_parts.replace = replace

        return policy_parts
