from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Any

from django.template import engines
from django.test import Client, override_settings

import pytest

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE, SELF

if TYPE_CHECKING:
    from django.http import HttpResponse

EXPECTED_SRC = "https://cdn.example.com/app.js"
EXPECTED_INLINE = "console.log('django inline script');\nvar answer = 42;"
EXPECTED_INLINE_JINJA = "console.log('jinja inline script');\nvar answer = 42;"

REPORT_ONLY_POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF],
        "script-src": [SELF, NONCE],
    }
}

ENFORCED_POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF, NONCE],
        "script-src": [SELF, NONCE],
    }
}

POLICIES = override_settings(
    CONTENT_SECURITY_POLICY=ENFORCED_POLICY,
    CONTENT_SECURITY_POLICY_REPORT_ONLY=REPORT_ONLY_POLICY,
)


@dataclass(frozen=True)
class ScriptTag:
    attrs: dict[str, str]
    content: str


class ScriptTagParser(HTMLParser):
    """Collect the attributes and body of every <script> tag in a response."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[ScriptTag] = []
        self._current: dict[str, str] | None = None
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        self._current = {name: value or "" for name, value in attrs}
        self._chunks = []

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "script" or self._current is None:
            return
        content = "".join(self._chunks).strip()
        self.scripts.append(ScriptTag(dict(self._current), content))
        self._current = None
        self._chunks = []


def parse_script_tags(response: HttpResponse) -> list[ScriptTag]:
    parser = ScriptTagParser()
    parser.feed(response.content.decode("utf-8"))
    return parser.scripts


def parse_policy(header_value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in header_value.split("; "):
        tokens = part.split(" ")
        directives[tokens[0]] = tokens[1:]
    return directives


def nonce_directives(policy: dict[str, list[str]]) -> dict[str, list[str]]:
    return {name: values for name, values in policy.items() if any(value.startswith("'nonce-") for value in values)}


def extract_nonces(policy: dict[str, list[str]]) -> set[str]:
    return {
        value.removeprefix("'nonce-").removesuffix("'")
        for values in policy.values()
        for value in values
        if value.startswith("'nonce-")
    }


def engine_cache(engine_name: str, template_name: str) -> Any:
    if engine_name == "django":
        loader = engines["django"].engine.template_loaders[0]
        return loader.get_template_cache[template_name]
    jinja_cache = engines["jinja2"].env.cache
    for key, compiled in jinja_cache.items():
        if key[-1] == template_name:
            return compiled
    return None


def engine_cache_contains(engine_name: str, template_name: str) -> bool:
    if engine_name == "django":
        return template_name in engines["django"].engine.template_loaders[0].get_template_cache
    return any(key[-1] == template_name for key in engines["jinja2"].env.cache.keys())


def clear_engine_caches() -> None:
    engines["django"].engine.template_loaders[0].get_template_cache.clear()
    engines["jinja2"].env.cache.clear()


def header_nonces(response: HttpResponse) -> set[str]:
    nonces = extract_nonces(parse_policy(response[HEADER]))
    assert nonces == extract_nonces(parse_policy(response[HEADER_REPORT_ONLY]))
    return nonces


def assert_scripts_protected(response: HttpResponse, engine_name: str) -> None:
    assert response.status_code == 200
    enforced = parse_policy(response[HEADER])
    report_only = parse_policy(response[HEADER_REPORT_ONLY])

    enforced_nonce_directives = nonce_directives(enforced)
    report_nonce_directives = nonce_directives(report_only)
    assert set(enforced_nonce_directives) == {"default-src", "script-src"}
    assert set(report_nonce_directives) == {"script-src"}

    enforced_nonces = extract_nonces(enforced)
    report_nonces = extract_nonces(report_only)
    assert len(enforced_nonces) == 1
    assert enforced_nonces == report_nonces
    nonce = next(iter(enforced_nonces))

    scripts = parse_script_tags(response)
    assert len(scripts) == 2
    external, inline = scripts

    assert external.attrs["nonce"] == nonce
    assert external.attrs["src"] == EXPECTED_SRC
    assert external.attrs["type"] == "application/javascript"
    assert external.attrs["async"] == ""
    assert external.attrs["defer"] == ""
    assert external.attrs["integrity"] == "sha384-base64digest"
    assert external.content == ""

    expected_inline = EXPECTED_INLINE if engine_name == "django" else EXPECTED_INLINE_JINJA
    assert inline.attrs == {"nonce": nonce}
    assert inline.content == expected_inline

    for directives in (enforced_nonce_directives.values(), report_nonce_directives.values()):
        for values in directives:
            assert f"'nonce-{nonce}'" in values
    assert all(script.attrs["nonce"] == nonce for script in scripts)


def assert_no_scripts(response: HttpResponse) -> None:
    assert response.status_code == 200
    assert parse_script_tags(response) == []
    assert "nonce-" not in response[HEADER]
    assert "nonce-" not in response[HEADER_REPORT_ONLY]


def policy_without_nonce(header_value: str) -> str:
    return "; ".join(
        directive
        for directive in header_value.split("; ")
        if not any(token.startswith("'nonce-") for token in directive.split(" ")[1:])
    )


@pytest.fixture
def client() -> Client:
    return Client()


@pytest.mark.parametrize(
    ("engine_name", "render_style", "template_name"),
    [
        ("django", "direct", "django/page.html"),
        ("django", "deferred", "django/page.html"),
        ("jinja", "direct", "jinja/page.html"),
        ("jinja", "deferred", "jinja/page.html"),
    ],
)
class TestCompiledTemplateReuse:
    @staticmethod
    def _path(engine_name: str, render_style: str, show_scripts: bool) -> str:
        return f"/{engine_name}/{render_style}/{int(show_scripts)}/"

    @POLICIES
    def test_compiled_template_reused_across_independent_requests(
        self, client: Client, engine_name: str, render_style: str, template_name: str
    ) -> None:
        clear_engine_caches()
        assert engine_cache_contains(engine_name, template_name) is False

        with_scripts = client.get(self._path(engine_name, render_style, True))
        compiled = engine_cache(engine_name, template_name)
        assert compiled is not None

        without_scripts = client.get(self._path(engine_name, render_style, False))
        assert engine_cache(engine_name, template_name) is compiled

        with_scripts_again = client.get(self._path(engine_name, render_style, True))
        assert engine_cache(engine_name, template_name) is compiled

        assert_scripts_protected(with_scripts, engine_name)
        assert_scripts_protected(with_scripts_again, engine_name)
        assert_no_scripts(without_scripts)

        first_nonces = header_nonces(with_scripts)
        second_nonces = header_nonces(with_scripts_again)
        assert first_nonces and second_nonces
        assert first_nonces.isdisjoint(second_nonces)

        stale_nonces = first_nonces | second_nonces
        bare_headers = (without_scripts[HEADER], without_scripts[HEADER_REPORT_ONLY])
        assert all("nonce-" not in header for header in bare_headers)
        assert all(not any(nonce in header for nonce in stale_nonces) for header in bare_headers)


@pytest.mark.parametrize("engine_name", ["django", "jinja"])
class TestRenderStylesInterleaved:
    @POLICIES
    def test_direct_and_deferred_requests_keep_isolated_nonces(self, client: Client, engine_name: str) -> None:
        direct = client.get(f"/{engine_name}/direct/1/")
        deferred = client.get(f"/{engine_name}/deferred/1/")
        direct_again = client.get(f"/{engine_name}/direct/1/")
        deferred_again = client.get(f"/{engine_name}/deferred/1/")

        responses = (direct, deferred, direct_again, deferred_again)
        nonce_sets = [extract_nonces(parse_policy(response[HEADER])) for response in responses]
        assert all(nonce_sets)
        assert len(set().union(*nonce_sets)) == len(nonce_sets)

        for response, nonces in zip(responses, nonce_sets):
            assert response.status_code == 200
            nonce = next(iter(nonces))
            assert extract_nonces(parse_policy(response[HEADER_REPORT_ONLY])) == nonces
            scripts = parse_script_tags(response)
            assert len(scripts) == 2
            assert all(script.attrs["nonce"] == nonce for script in scripts)
            assert scripts[0].content == ""
            assert scripts[0].attrs["src"] == EXPECTED_SRC


class TestReportPolicyAdjustment:
    @POLICIES
    def test_report_only_adjustment_is_scoped_to_one_response(self, client: Client) -> None:
        tweaked = client.get("/django/report-tweak/1/")
        normal = client.get("/django/direct/1/")

        tweaked_report = parse_policy(tweaked[HEADER_REPORT_ONLY])
        normal_report = parse_policy(normal[HEADER_REPORT_ONLY])
        assert "https://report.example.com" in tweaked_report["script-src"]
        assert "https://report.example.com" not in normal_report["script-src"]

        assert policy_without_nonce(tweaked[HEADER]) == policy_without_nonce(normal[HEADER])
        assert policy_without_nonce(tweaked[HEADER]) != policy_without_nonce(tweaked[HEADER_REPORT_ONLY])

        tweaked_nonce = next(iter(extract_nonces(tweaked_report)))
        normal_nonce = next(iter(extract_nonces(normal_report)))
        assert tweaked_nonce != normal_nonce
        assert tweaked_nonce not in normal[HEADER_REPORT_ONLY]
        assert normal_nonce not in tweaked[HEADER_REPORT_ONLY]

        for response, nonce in ((tweaked, tweaked_nonce), (normal, normal_nonce)):
            scripts = parse_script_tags(response)
            assert len(scripts) == 2
            assert all(script.attrs["nonce"] == nonce for script in scripts)
