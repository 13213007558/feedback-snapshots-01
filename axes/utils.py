"""
Axes utility functions that are publicly available.

This module is separate for historical reasons
and offers a backwards compatible import path.
"""

from logging import getLogger
from typing import Optional

from django.http import HttpRequest

from axes.conf import settings
from axes.handlers.proxy import AxesProxyHandler
from axes.helpers import get_client_ip_address, get_lockout_parameters

log = getLogger(__name__)


def reset(
    ip: Optional[str] = None,
    username: Optional[str] = None,
    ip_or_username=False,
    subject: Optional[str] = None,
) -> int:
    """
    Reset records that match IP, username or subject, and return the count of removed attempts.

    Resetting by ``subject`` unlocks the complete subject scope, including the
    legacy username/network-group windows registered to that subject.

    This utility method is meant to be used from the CLI or via Python API.
    """

    return AxesProxyHandler.reset_attempts(
        ip_address=ip,
        username=username,
        ip_or_username=ip_or_username,
        subject=subject,
    )


def reset_request(request: HttpRequest) -> int:
    """
    Reset records that match IP or username, and return the count of removed attempts.

    This utility method is meant to be used from the CLI or via Python API.
    """
    lockout_paramaters = get_lockout_parameters(request)

    ip: Optional[str] = get_client_ip_address(request)
    username = request.GET.get("username", None)
    subject = request.GET.get(settings.AXES_SUBJECT_FORM_FIELD, None)

    ip_required = False
    username_required = False
    ip_and_username = False

    for param in lockout_paramaters:
        # hack: in works with all iterables, including strings
        # so this checks works with separate parameters
        # and with parameters combinations
        if "subject" in param:
            continue
        if "username" in param and "ip_address" in param:
            ip_and_username = True
            ip_required = True
            username_required = True
            break
        if "username" in param:
            username_required = True
        elif "ip_address" in param:
            ip_required = True

    if subject:
        # An authorised unlock by subject applies to its complete scope,
        # regardless of which legacy lockout parameters are configured.
        return reset(subject=subject)

    ip_or_username = not ip_and_username and ip_required and username_required
    if not ip_required:
        ip = None
    if not username_required:
        username = None

    if not ip and not username:
        return 0
        # We don't want to reset everything, if there is some wrong request parameter

    # TODO: reset based on user_agent?
    return reset(ip, username, ip_or_username)
