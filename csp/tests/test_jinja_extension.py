from django.test.utils import override_settings

import pytest

from csp.constants import NONCE, SELF
from csp.exceptions import CSPNonceError
from csp.tests.utils import ScriptExtensionTestBase


class TestJinjaExtension(ScriptExtensionTestBase):
    def test_script_tag_injects_nonce(self) -> None:
        tpl = """
            {% script %}
                var hello='world';
            {% endscript %}
        """

        expected = """<script nonce="{}">var hello='world';</script>"""
        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_script_with_src_ignores_body(self) -> None:
        tpl = """
            {% script src="foo" %}
                var hello='world';
            {% endscript %}
        """

        expected = """<script nonce="{}" src="foo"></script>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_script_tag_sets_attrs_correctly(self) -> None:
        tpl = """
            {% script id='jeff' defer=True %}
                var hello='world';
            {% endscript %}
            """
        expected = """
            <script nonce="{}" id="jeff" defer>
                var hello='world';
            </script>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_async_attribute_with_falsey(self) -> None:
        tpl = """
            {% script id="jeff" async=False %}
                var hello='world';
            {% endscript %}"""

        expected = '<script nonce="{}" id="jeff" async=false>var hello=\'world\';</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_async_attribute_with_truthy(self) -> None:
        tpl = """
            {% script id="jeff" async=True %}
                var hello='world';
            {% endscript %}"""

        expected = '<script nonce="{}" id="jeff" async>var hello=\'world\';</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_nested_script_tags_are_removed(self) -> None:
        """Let users wrap their code in script tags for the sake of their
        development environment"""
        tpl = """
            {% script type="application/javascript" id="jeff" defer=True%}
                <script type="text/javascript">
                var hello='world';
                </script>
            {% endscript %}"""

        expected = '<script nonce="{}" id="jeff" type="application/javascript" defer>var hello=\'world\';</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_regex_captures_script_content_including_brackets(self) -> None:
        """
        Ensure that script content get captured properly.
        Especially when using angle brackets."""
        tpl = """
            {% script %}
            <script type="text/javascript">
                let capture_text = "<script></script>"
            </script>
            {% endscript %}
            """

        expected = '<script nonce="{}">let capture_text = "<script></script>"</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))


class TestJinjaStyleExtension(ScriptExtensionTestBase):
    def test_style_tag_injects_nonce(self) -> None:
        tpl = """
            {% style %}
                .hello { color: red; }
            {% endstyle %}
        """

        expected = """<style nonce="{}">.hello {{ color: red; }}</style>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_style_tag_sets_attrs_correctly(self) -> None:
        tpl = """
            {% style id="inline" media="print" %}
                .hello { color: red; }
            {% endstyle %}
            """
        expected = '<style nonce="{}" id="inline" media="print">.hello {{ color: red; }}</style>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_nested_style_tags_are_removed(self) -> None:
        """Let users wrap their code in style tags for the sake of their
        development environment"""
        tpl = """
            {% style %}
                <style media="print">
                .hello { color: red; }
                </style>
            {% endstyle %}"""

        expected = '<style nonce="{}">.hello {{ color: red; }}</style>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    @override_settings(
        CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "script-src": [SELF, NONCE]}},
    )
    def test_style_tag_raises_when_nonce_only_configured_for_scripts(self) -> None:
        """A config that only allows script nonces must produce a clear diagnostic"""
        tpl = """
            {% style %}.hello { color: red; }{% endstyle %}"""

        with pytest.raises(CSPNonceError, match="NONCE sentinel"):
            self.render(tpl, self.make_request())
