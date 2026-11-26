from __future__ import annotations

import json
from textwrap import dedent
from typing import TYPE_CHECKING

import pytest
from tox.execute.request import StdinSource

if TYPE_CHECKING:

    from tox.pytest import MonkeyPatch, ToxProjectCreator


PRIVATE_TOKEN = "private-provenance-token-value"


def _ini(*, broken: bool = False) -> str:
    broken_line = "description = see {missing_provenance_reference}\n" if broken else ""
    return dedent(
        f"""
        [tox]
        env_list = private,clean,broken
        no_package = true

        [testenv]
        package = skip
        pass_env = SUPPORT_PRIVATE_TOKEN
        shared_field = support-team-shared

        [testenv:private]
        token = {{env:SUPPORT_PRIVATE_TOKEN}}
        token_alias = layer-{{[testenv:private]token}}-end
        commands =
            python probe.py --token {{[testenv:private]token_alias}} --public-arg hello
        {broken_line}
        [testenv:clean]
        token = publicly-readable-demo
        commands =
            python probe.py --token {{[testenv:clean]token}} --public-arg hello

        [testenv:broken]
        {broken_line}
        commands = python probe.py --ok
        """,
    )


@pytest.fixture
def private_environment(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("SUPPORT_PRIVATE_TOKEN", PRIVATE_TOKEN)


def test_public_json_tracks_two_replacements_without_value(
    tox_project: ToxProjectCreator,
    private_environment: None,
) -> None:
    project = tox_project({"tox.ini": _ini()})

    outcome = project.run(
        "c",
        "--public",
        "--format",
        "json",
        "-e",
        "private",
        "-k",
        "token",
        "token_alias",
        "commands",
    )

    outcome.assert_success()
    assert PRIVATE_TOKEN not in outcome.out
    assert PRIVATE_TOKEN not in outcome.err
    data = json.loads(outcome.out)
    env = data["env"]["private"]

    mask = "*" * len(PRIVATE_TOKEN)
    token = env["token"]
    assert token["visibility"] == "restricted"
    assert token["redacted"] is True
    assert token["value"] == mask
    assert token["sources"][-1]["id"] == "env:SUPPORT_PRIVATE_TOKEN"

    alias = env["token_alias"]
    assert alias["status"] == "redacted"
    assert alias["value"] == f"layer-{mask}-end"
    assert "config:testenv:private:token" in alias["derived_from"]

    command = env["commands"]
    assert command["status"] == "redacted"
    assert command["value"] == [
        f"python probe.py --token layer-{mask}-end --public-arg hello",
    ]
    chain = " -> ".join(command["chain"])
    assert "testenv:private.token_alias [resolved]" in chain
    assert "testenv:private.token [resolved]" in chain
    assert "env:SUPPORT_PRIVATE_TOKEN [resolved]" in chain
    assert "hello" in json.dumps(command)
    assert "SUPPORT_PRIVATE_TOKEN" in outcome.out


def test_public_text_matches_json_relationship(
    tox_project: ToxProjectCreator,
    private_environment: None,
) -> None:
    project = tox_project({"tox.ini": _ini()})

    json_outcome = project.run(
        "c",
        "--public",
        "--format",
        "json",
        "-e",
        "private",
        "-k",
        "commands",
    )
    text_outcome = project.run("c", "--public", "-e", "private", "-k", "commands")

    json_outcome.assert_success()
    text_outcome.assert_success()
    data = json.loads(json_outcome.out)
    command = data["env"]["private"]["commands"]

    assert PRIVATE_TOKEN not in text_outcome.out
    mask = "*" * len(PRIVATE_TOKEN)
    assert f"commands = python probe.py --token layer-{mask}-end" in text_outcome.out
    assert "status=redacted resolution=resolved visibility=restricted" in text_outcome.out
    assert "source: tox.ini [testenv:private] commands" in text_outcome.out
    assert "token_alias(resolved)" in text_outcome.out
    assert "token(resolved)" in text_outcome.out
    assert "env:SUPPORT_PRIVATE_TOKEN(resolved)" in text_outcome.out
    for chain_item in command["chain"][1:]:
        target, status = chain_item.rsplit(" [", 1)
        status = status.removesuffix("]")
        assert f"{target}({status})" in text_outcome.out


def test_same_named_key_in_clean_environment_is_public(
    tox_project: ToxProjectCreator,
    private_environment: None,
) -> None:
    project = tox_project({"tox.ini": _ini()})

    json_outcome = project.run(
        "c",
        "--public",
        "--format",
        "json",
        "-e",
        "clean",
        "-k",
        "token",
        "commands",
    )
    text_outcome = project.run("c", "--public", "-e", "clean", "-k", "token", "commands")

    json_outcome.assert_success()
    text_outcome.assert_success()
    assert PRIVATE_TOKEN not in json_outcome.out + text_outcome.out

    data = json.loads(json_outcome.out)
    token = data["env"]["clean"]["token"]
    command = data["env"]["clean"]["commands"]
    assert token["visibility"] == "public"
    assert token["redacted"] is False
    assert token["value"] == "publicly-readable-demo"
    assert command["status"] == "public"
    assert "publicly-readable-demo" in command["value"][0]
    assert "status=public resolution=resolved visibility=public" in text_outcome.out
    assert "token = publicly-readable-demo" in text_outcome.out


def test_public_view_reports_unresolved_reference(tox_project: ToxProjectCreator) -> None:
    project = tox_project({"tox.ini": _ini(broken=True)})

    outcome = project.run(
        "c",
        "--public",
        "--format",
        "json",
        "-e",
        "broken",
        "-k",
        "description",
        raise_on_config_fail=False,
    )

    data = json.loads(outcome.out)
    entry = data["env"]["broken"]["description"]
    assert entry["status"] == "unresolved"
    assert "missing_provenance_reference" in entry["unresolved_references"]
    assert any(ref.get("status") == "unresolved" for ref in entry["references"])

    text = project.run(
        "c",
        "--public",
        "-e",
        "broken",
        "-k",
        "description",
        raise_on_config_fail=False,
    )
    assert "status=unresolved" in text.out
    assert "missing_provenance_reference(unresolved)" in text.out
    assert "unresolved: missing_provenance_reference" in text.out


def test_real_execution_request_keeps_full_approved_value(
    tox_project: ToxProjectCreator,
    private_environment: None,
) -> None:
    project = tox_project({"tox.ini": _ini()})
    execute_calls = project.patch_execute(lambda _request: 0)

    outcome = project.run("r", "-e", "private")

    outcome.assert_success()
    requests = [call[0][3] for call in execute_calls.call_args_list]
    request = next(req for req in requests if "probe.py" in " ".join(req.cmd))
    assert f"layer-{PRIVATE_TOKEN}-end" in request.cmd
    assert request.env["SUPPORT_PRIVATE_TOKEN"] == PRIVATE_TOKEN
    assert request.stdin in {StdinSource.OFF, StdinSource.USER, StdinSource.API}
