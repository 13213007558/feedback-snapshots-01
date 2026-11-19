from django.test.utils import override_settings

import pytest

from csp.constants import NONCE, SELF
from csp.exceptions import CSPNonceError
from csp.tests.utils import ScriptTagTestBase


class TestDjangoTemplateTag(ScriptTagTestBase):
    def test_script_tag_injects_nonce(self) -> None:
        tpl = """
            {% load csp %}
            {% script %}var hello='world';{% endscript %}"""

        expected = """<script nonce="{}">var hello='world';</script>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_script_with_src_ignores_body(self) -> None:
        tpl = """
            {% load csp %}
            {% script src="foo" %}
                var hello='world';
            {% endscript %}"""

        expected = """<script nonce="{}" src="foo"></script>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_script_tag_sets_attrs_correctly(self) -> None:
        tpl = """
            {% load csp %}
            {% script type="application/javascript" id="jeff" defer=True%}
                var hello='world';
            {% endscript %}"""

        expected = '<script nonce="{}" id="jeff" type="application/javascript" defer>var hello=\'world\';</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_async_attribute_with_falsey(self) -> None:
        tpl = """
            {% load csp %}
            {% script src="foo.com/bar.js" async=False %}
            {% endscript %}"""

        expected = '<script nonce="{}" src="foo.com/bar.js" async=false></script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_async_attribute_with_truthy(self) -> None:
        tpl = """
            {% load csp %}
            {% script src="foo.com/bar.js" async=True %}
                var hello='world';
            {% endscript %}"""

        expected = '<script nonce="{}" src="foo.com/bar.js" async></script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_nested_script_tags_are_removed(self) -> None:
        """Lets end users wrap their code in script tags for the sake of their
        development environment"""
        tpl = """
            {% load csp %}
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
            {% load csp %}
            {% script %}
            <script type="text/javascript">
                let capture_text = "<script></script>"
            </script>
            {% endscript %}
            """

        expected = '<script nonce="{}">let capture_text = "<script></script>"</script>'

        self.assert_template_eq(*self.process_templates(tpl, expected))


class TestDjangoStyleTag(ScriptTagTestBase):
    def test_style_tag_injects_nonce(self) -> None:
        tpl = """
            {% load csp %}
            {% style %}.hello { color: red; }{% endstyle %}"""

        expected = """<style nonce="{}">.hello {{ color: red; }}</style>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_style_tag_sets_attrs_correctly(self) -> None:
        tpl = """
            {% load csp %}
            {% style id="inline" media="print" %}
                .hello { color: red; }
            {% endstyle %}"""

        expected = '<style nonce="{}" id="inline" media="print">.hello {{ color: red; }}</style>'

        self.assert_template_eq(*self.process_templates(tpl, expected))

    def test_nested_style_tags_are_removed(self) -> None:
        """Lets end users wrap their code in style tags for the sake of their
        development environment"""
        tpl = """
            {% load csp %}
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
            {% load csp %}
            {% style %}.hello { color: red; }{% endstyle %}"""

        with pytest.raises(CSPNonceError, match="NONCE sentinel"):
            self.render(tpl, self.make_request())

    @override_settings(
        CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "style-src-elem": [SELF]}},
    )
    def test_style_tag_raises_when_effective_style_directive_lacks_nonce(self) -> None:
        """style-src-elem shadows default-src, so a NONCE on default-src is not enough"""
        tpl = """
            {% load csp %}
            {% style %}.hello { color: red; }{% endstyle %}"""

        with pytest.raises(CSPNonceError, match="NONCE sentinel"):
            self.render(tpl, self.make_request())

    @override_settings(
        CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "style-src": [SELF, NONCE]}},
    )
    def test_style_tag_allowed_by_style_src(self) -> None:
        tpl = """
            {% load csp %}
            {% style %}.hello { color: red; }{% endstyle %}"""

        expected = """<style nonce="{}">.hello {{ color: red; }}</style>"""

        self.assert_template_eq(*self.process_templates(tpl, expected))
