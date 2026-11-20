from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type, get_proxy_permission_mode
from guardian.testapp.models import Ticket


class TestConfiguration(TestCase):
    def test_check_configuration(self):
        with mock.patch("guardian.conf.settings.RENDER_403", True):
            with mock.patch("guardian.conf.settings.RAISE_403", True):
                self.assertRaises(ImproperlyConfigured, guardian_settings.check_configuration)

    def test_check_configuration_render_404_and_raise_404(self):
        with mock.patch("guardian.conf.settings.RENDER_404", True):
            with mock.patch("guardian.conf.settings.RAISE_404", True):
                self.assertRaises(ImproperlyConfigured, guardian_settings.check_configuration)

    def test_get_content_type(self):
        with mock.patch(
            "guardian.conf.settings.GET_CONTENT_TYPE", "guardian.testapp.tests.test_conf.get_test_content_type"
        ):
            self.assertEqual(get_content_type(None), "x")

    def test_proxy_permission_mode_defaults_to_inherit(self):
        self.assertEqual(guardian_settings.PROXY_PERMISSION_MODE, "inherit")

    def test_proxy_permission_mode_only_applies_to_proxies(self):
        from django.contrib.auth.models import Group

        self.assertEqual(get_proxy_permission_mode(Group), "inherit")
        self.assertEqual(get_proxy_permission_mode(Ticket), "isolate")


def get_test_content_type(obj):
    """Used in TestConfiguration.test_get_content_type()."""
    return "x"
