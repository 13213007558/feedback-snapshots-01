from __future__ import annotations

import base64
import contextlib
import functools
import json
import logging
import os
import subprocess
import sys
from collections.abc import Generator, Iterable
from dataclasses import dataclass
from typing import Any

import pytest

import pip._internal.network.auth
from pip._internal.network.auth import MultiDomainBasicAuth

from tests.lib.requests_mocks import MockConnection, MockRequest, MockResponse


@pytest.fixture(autouse=True)
def reset_keyring() -> Iterable[None]:
    yield None
    # Reset the state of the module between tests
    pip._internal.network.auth.KEYRING_DISABLED = False
    pip._internal.network.auth.get_keyring_provider.cache_clear()


@pytest.mark.parametrize(
    "input_url, url, username, password",
    [
        (
            "http://user%40email.com:password@example.com/path",
            "http://example.com/path",
            "user@email.com",
            "password",
        ),
        (
            "http://username:password@example.com/path",
            "http://example.com/path",
            "username",
            "password",
        ),
        (
            "http://token@example.com/path",
            "http://example.com/path",
            "token",
            "",
        ),
        (
            "http://example.com/path",
            "http://example.com/path",
            None,
            None,
        ),
    ],
)
def test_get_credentials_parses_correctly(
    input_url: str, url: str, username: str | None, password: str | None
) -> None:
    auth = MultiDomainBasicAuth()
    get = auth._get_url_and_credentials

    # Check URL parsing
    assert get(input_url) == (url, username, password)
    assert (
        # There are no credentials in the URL
        (username is None and password is None)
        or
        # Credentials were found and "cached" appropriately
        auth.passwords["example.com"] == (username, password)
    )


def test_get_credentials_not_to_uses_cached_credentials() -> None:
    auth = MultiDomainBasicAuth()
    auth.passwords["example.com"] = ("user", "pass")

    got = auth._get_url_and_credentials("http://foo:bar@example.com/path")
    expected = ("http://example.com/path", "foo", "bar")
    assert got == expected


def test_get_credentials_not_to_uses_cached_credentials_only_username() -> None:
    auth = MultiDomainBasicAuth()
    auth.passwords["example.com"] = ("user", "pass")

    got = auth._get_url_and_credentials("http://foo@example.com/path")
    expected = ("http://example.com/path", "foo", "")
    assert got == expected


def test_get_credentials_uses_cached_credentials() -> None:
    auth = MultiDomainBasicAuth()
    auth.passwords["example.com"] = ("user", "pass")

    got = auth._get_url_and_credentials("http://example.com/path")
    expected = ("http://example.com/path", "user", "pass")
    assert got == expected


def test_get_credentials_uses_cached_credentials_only_username() -> None:
    auth = MultiDomainBasicAuth()
    auth.passwords["example.com"] = ("user", "pass")

    got = auth._get_url_and_credentials("http://user@example.com/path")
    expected = ("http://example.com/path", "user", "pass")
    assert got == expected


def test_get_index_url_credentials() -> None:
    auth = MultiDomainBasicAuth(
        index_urls=[
            "http://example.com/",
            "http://foo:bar@example.com/path",
        ]
    )
    get = functools.partial(
        auth._get_new_credentials, allow_netrc=False, allow_keyring=False
    )

    # Check resolution of indexes
    assert get("http://example.com/path/path2") == ("foo", "bar")
    assert get("http://example.com/path3/path2") == (None, None)


def test_prioritize_longest_path_prefix_match_organization() -> None:
    auth = MultiDomainBasicAuth(
        index_urls=[
            "http://foo:bar@example.com/org-name-alpha/repo-alias/simple",
            "http://bar:foo@example.com/org-name-beta/repo-alias/simple",
        ]
    )
    get = functools.partial(
        auth._get_new_credentials, allow_netrc=False, allow_keyring=False
    )

    # Inspired by Azure DevOps URL structure, GitLab should look similar
    assert get("http://example.com/org-name-alpha/repo-guid/dowbload/") == (
        "foo",
        "bar",
    )
    assert get("http://example.com/org-name-beta/repo-guid/dowbload/") == ("bar", "foo")


def test_prioritize_longest_path_prefix_match_project() -> None:
    auth = MultiDomainBasicAuth(
        index_urls=[
            "http://foo:bar@example.com/org-alpha/project-name-alpha/repo-alias/simple",
            "http://bar:foo@example.com/org-alpha/project-name-beta/repo-alias/simple",
        ]
    )
    get = functools.partial(
        auth._get_new_credentials, allow_netrc=False, allow_keyring=False
    )

    # Inspired by Azure DevOps URL structure, GitLab should look similar
    assert get(
        "http://example.com/org-alpha/project-name-alpha/repo-guid/dowbload/"
    ) == ("foo", "bar")
    assert get(
        "http://example.com/org-alpha/project-name-beta/repo-guid/dowbload/"
    ) == ("bar", "foo")


class KeyringModuleV1:
    """Represents the supported API of keyring before get_credential
    was added.
    """

    def __init__(self) -> None:
        self.saved_passwords: list[tuple[str, str, str]] = []

    def get_password(self, system: str, username: str) -> str | None:
        if system == "example.com" and username:
            return username + "!netloc"
        if system == "http://example.com/path2/" and username:
            return username + "!url"
        return None

    def set_password(self, system: str, username: str, password: str) -> None:
        self.saved_passwords.append((system, username, password))


@pytest.mark.parametrize(
    "url, expect",
    [
        ("http://example.com/path1", (None, None)),
        # path1 URLs will be resolved by netloc
        ("http://user@example.com/path3", ("user", "user!netloc")),
        ("http://user2@example.com/path3", ("user2", "user2!netloc")),
        # path2 URLs will be resolved by index URL
        ("http://example.com/path2/path3", (None, None)),
        ("http://foo@example.com/path2/path3", ("foo", "foo!url")),
    ],
)
def test_keyring_get_password(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    expect: tuple[str | None, str | None],
) -> None:
    keyring = KeyringModuleV1()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(
        index_urls=["http://example.com/path2", "http://example.com/path3"],
        keyring_provider="import",
    )

    actual = auth._get_new_credentials(url, allow_netrc=False, allow_keyring=True)
    assert actual == expect


def test_keyring_get_password_after_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring = KeyringModuleV1()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(keyring_provider="import")

    def ask_input(prompt: str) -> str:
        assert prompt == "User for example.com: "
        return "user"

    monkeypatch.setattr("pip._internal.network.auth.ask_input", ask_input)
    actual = auth._prompt_for_password("example.com")
    assert actual == ("user", "user!netloc", False)


def test_keyring_get_password_after_prompt_when_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = KeyringModuleV1()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(keyring_provider="import")

    def ask_input(prompt: str) -> str:
        assert prompt == "User for unknown.com: "
        return "user"

    def ask_password(prompt: str) -> str:
        assert prompt == "Password: "
        return "fake_password"

    monkeypatch.setattr("pip._internal.network.auth.ask_input", ask_input)
    monkeypatch.setattr("pip._internal.network.auth.ask_password", ask_password)
    actual = auth._prompt_for_password("unknown.com")
    assert actual == ("user", "fake_password", True)


def test_keyring_get_password_username_in_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keyring = KeyringModuleV1()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(
        index_urls=["http://user@example.com/path2", "http://example.com/path4"],
        keyring_provider="import",
    )
    get = functools.partial(
        auth._get_new_credentials, allow_netrc=False, allow_keyring=True
    )

    assert get("http://example.com/path2/path3") == ("user", "user!url")
    assert get("http://example.com/path4/path1") == (None, None)


@pytest.mark.parametrize(
    "response_status, creds, expect_save",
    [
        (403, ("user", "pass", True), False),
        (
            200,
            ("user", "pass", True),
            True,
        ),
        (
            200,
            ("user", "pass", False),
            False,
        ),
    ],
)
def test_keyring_set_password(
    monkeypatch: pytest.MonkeyPatch,
    response_status: int,
    creds: tuple[str, str, bool],
    expect_save: bool,
) -> None:
    keyring = KeyringModuleV1()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(prompting=True, keyring_provider="import")
    monkeypatch.setattr(auth, "_get_url_and_credentials", lambda u: (u, None, None))
    monkeypatch.setattr(auth, "_prompt_for_password", lambda *a: creds)
    if creds[2]:
        # when _prompt_for_password indicates to save, we should save
        def should_save_password_to_keyring(*a: Any) -> bool:
            return True

    else:
        # when _prompt_for_password indicates not to save, we should
        # never call this function
        def should_save_password_to_keyring(*a: Any) -> bool:
            pytest.fail("_should_save_password_to_keyring should not be called")

    monkeypatch.setattr(
        auth, "_should_save_password_to_keyring", should_save_password_to_keyring
    )

    req = MockRequest("https://example.com")
    resp = MockResponse(b"")
    resp.url = req.url
    connection = MockConnection()

    def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
        assert sent_req is req
        assert "Authorization" in sent_req.headers
        r = MockResponse(b"")
        r.status_code = response_status
        return r

    # https://github.com/python/mypy/issues/2427
    connection._send = _send  # type: ignore[assignment]

    resp.request = req
    resp.status_code = 401
    resp.connection = connection

    auth.handle_401(resp)

    if expect_save:
        assert keyring.saved_passwords == [("example.com", creds[0], creds[1])]
    else:
        assert keyring.saved_passwords == []


class KeyringModuleV2:
    """Represents the current supported API of keyring"""

    def __init__(self) -> None:
        self.saved_credential_by_username_by_system: dict[
            str, dict[str, KeyringModuleV2.Credential]
        ] = {}

    @dataclass
    class Credential:
        username: str
        password: str

    def get_password(self, system: str, username: str) -> None:
        pytest.fail("get_password should not ever be called")

    def get_credential(self, system: str, username: str | None) -> Credential | None:
        credential_by_username = self.saved_credential_by_username_by_system.get(
            system, {}
        )
        if username is None:
            # Just return the first cred we can find (if
            # there even are any for this service).
            credentials = list(credential_by_username.values())
            if len(credentials) == 0:
                return None

            # Just pick the first one we can find.
            credential = credentials[0]
            return credential

        return credential_by_username.get(username)

    def set_password(self, system: str, username: str, password: str) -> None:
        if system not in self.saved_credential_by_username_by_system:
            self.saved_credential_by_username_by_system[system] = {}

        credential_by_username = self.saved_credential_by_username_by_system[system]
        assert username not in credential_by_username
        credential_by_username[username] = self.Credential(username, password)

    def delete_password(self, system: str, username: str) -> None:
        del self.saved_credential_by_username_by_system[system][username]

    @contextlib.contextmanager
    def add_credential(
        self, system: str, username: str, password: str
    ) -> Generator[None]:
        """
        Context manager that adds the given credential to the keyring
        and yields. Once the yield is done, the credential is removed
        from the keyring.

        This is re-entrant safe: it's ok for one thread to call this while in
        the middle of an existing invocation

        This is probably not thread safe: it's not ok for multiple threads to
        simultaneously call this method on the exact same instance of KeyringModuleV2.
        """
        self.set_password(system, username, password)
        try:
            yield
        finally:
            # No matter what happened, make sure we clean up after ourselves.
            self.delete_password(system, username)


@pytest.mark.parametrize(
    "url, expect",
    [
        ("http://example.com/path1", ("username", "hunter2")),
        ("http://example.com/path2/path3", ("username", "hunter3")),
        ("http://user2@example.com/path2/path3", ("user2", None)),
    ],
)
def test_keyring_get_credential(
    monkeypatch: pytest.MonkeyPatch, url: str, expect: tuple[str, str]
) -> None:
    keyring = KeyringModuleV2()
    monkeypatch.setitem(sys.modules, "keyring", keyring)
    auth = MultiDomainBasicAuth(
        index_urls=["http://example.com/path1", "http://example.com/path2"],
        keyring_provider="import",
    )

    with (
        keyring.add_credential("example.com", "username", "hunter2"),
        keyring.add_credential("http://example.com/path2/", "username", "hunter3"),
    ):
        assert (
            auth._get_new_credentials(url, allow_netrc=False, allow_keyring=True)
            == expect
        )


class KeyringModuleBroken:
    """Represents the current supported API of keyring, but broken"""

    def __init__(self) -> None:
        self._call_count = 0

    def get_credential(self, system: str, username: str) -> None:
        self._call_count += 1
        raise Exception("This keyring is broken!")


def test_broken_keyring_disables_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    keyring_broken = KeyringModuleBroken()
    monkeypatch.setitem(sys.modules, "keyring", keyring_broken)

    auth = MultiDomainBasicAuth(
        index_urls=["http://example.com/"], keyring_provider="import"
    )

    assert keyring_broken._call_count == 0
    for i in range(5):
        url = "http://example.com/path" + str(i)
        assert auth._get_new_credentials(
            url, allow_netrc=False, allow_keyring=True
        ) == (None, None)
        assert keyring_broken._call_count == 1


class KeyringSubprocessResult(KeyringModuleV2):
    """Represents the subprocess call to keyring"""

    returncode = 0  # Default to zero retcode

    def __init__(self) -> None:
        super().__init__()
        self.old_version = False

    def __call__(
        self,
        cmd: list[str],
        *,
        env: dict[str, str],
        stdin: Any | None = None,
        stdout: Any | None = None,
        stderr: Any | None = None,
        input: bytes | None = None,
        check: bool | None = None,
    ) -> Any:
        parsed_cmd = list(cmd)
        assert parsed_cmd.pop(0) == "keyring"
        subcommand = [
            arg
            for arg in parsed_cmd
            # Skip past all the --whatever options until we get to the subcommand.
            if not arg.startswith("--")
        ][0]
        subcommand_func = {
            "get": self._get_subcommand,
            "set": self._set_subcommand,
        }[subcommand]

        subcommand_func(
            parsed_cmd,
            env=env,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            input=input,
            check=check,
        )

        return self

    def _get_subcommand(
        self,
        cmd: list[str],
        *,
        env: dict[str, str],
        stdin: Any | None = None,
        stdout: Any | None = None,
        stderr: Any | None = None,
        input: bytes | None = None,
        check: bool | None = None,
    ) -> None:
        assert cmd.pop(0) == "--mode=creds"
        assert cmd.pop(0) == "--output=json"
        assert stdin == -3  # subprocess.DEVNULL
        assert stdout == subprocess.PIPE
        assert stderr == subprocess.PIPE
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert check is None
        assert cmd.pop(0) == "get"

        # Return the same error message as an old keyring version, if requested
        if self.old_version:
            self.stderr = (
                b"usage: keyring [-h] [-p KEYRING_PATH] [-b KEYRING_BACKEND] "
                b"[--list-backends] [--disable] [--print-completion {bash,zsh,tcsh}] "
                b"[{get,set,del,diagnose}] [service] [username]\n"
                b"keyring: error: unrecognized arguments: --mode=creds --output=json"
            )
            self.returncode = 2
            return
        self.stderr = b""

        service = cmd.pop(0)
        username = cmd.pop(0) if len(cmd) > 0 else None
        creds = self.get_credential(service, username)
        if creds is None:
            # Expect non-zero returncode if no creds present
            self.returncode = 1
        else:
            # Passwords are returned encoded with a newline appended
            self.returncode = 0
            self.stdout = json.dumps(
                {
                    "username": creds.username,
                    "password": creds.password,
                }
            ).encode("utf-8")

    def _set_subcommand(
        self,
        cmd: list[str],
        *,
        env: dict[str, str],
        stdin: Any | None = None,
        stdout: Any | None = None,
        stderr: Any | None = None,
        input: bytes | None = None,
        check: bool | None = None,
    ) -> None:
        assert cmd.pop(0) == "set"
        assert stdin is None
        assert stdout is None
        assert stderr is None
        assert env["PYTHONIOENCODING"] == "utf-8"
        assert input is not None
        assert check

        # Input from stdin is encoded
        system, username = cmd
        self.set_password(system, username, input.decode("utf-8").strip(os.linesep))

    def check_returncode(self) -> None:
        if self.returncode:
            raise Exception()


@pytest.mark.parametrize(
    "url, expect",
    [
        # It's not obvious, but this url ultimately resolves to index url
        # http://example.com/path2, so we get the creds for that index.
        ("http://example.com/path1", ("saved-user1", "pw1")),
        ("http://saved-user1@example.com/path2", ("saved-user1", "pw1")),
        ("http://saved-user2@example.com/path2", ("saved-user2", "pw2")),
        ("http://new-user@example.com/path2", ("new-user", None)),
        ("http://example.com/path2/path3", ("saved-user1", "pw1")),
        ("http://foo@example.com/path2/path3", ("foo", None)),
    ],
)
def test_keyring_cli_get_password(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    expect: tuple[str | None, str | None],
) -> None:
    keyring_subprocess = KeyringSubprocessResult()
    monkeypatch.setattr(pip._internal.network.auth.shutil, "which", lambda x: "keyring")
    monkeypatch.setattr(
        pip._internal.network.auth.subprocess, "run", keyring_subprocess
    )
    auth = MultiDomainBasicAuth(
        index_urls=["http://example.com/path2", "http://example.com/path3"],
        keyring_provider="subprocess",
    )

    with (
        keyring_subprocess.add_credential("example.com", "example", "!netloc"),
        keyring_subprocess.add_credential(
            "http://example.com/path2/", "saved-user1", "pw1"
        ),
        keyring_subprocess.add_credential(
            "http://example.com/path2/", "saved-user2", "pw2"
        ),
    ):
        actual = auth._get_new_credentials(url, allow_netrc=False, allow_keyring=True)
        assert actual == expect


@pytest.mark.parametrize(
    "response_status, creds, expect_save",
    [
        (403, ("user", "pass", True), False),
        (
            200,
            ("user", "pass", True),
            True,
        ),
        (
            200,
            ("user", "pass", False),
            False,
        ),
    ],
)
def test_keyring_cli_set_password(
    monkeypatch: pytest.MonkeyPatch,
    response_status: int,
    creds: tuple[str, str, bool],
    expect_save: bool,
) -> None:
    expected_username, expected_password, save = creds
    monkeypatch.setattr(pip._internal.network.auth.shutil, "which", lambda x: "keyring")
    keyring = KeyringSubprocessResult()
    monkeypatch.setattr(pip._internal.network.auth.subprocess, "run", keyring)
    auth = MultiDomainBasicAuth(prompting=True, keyring_provider="subprocess")
    monkeypatch.setattr(auth, "_get_url_and_credentials", lambda u: (u, None, None))
    monkeypatch.setattr(auth, "_prompt_for_password", lambda *a: creds)
    if save:
        # when _prompt_for_password indicates to save, we should save
        def should_save_password_to_keyring(*a: Any) -> bool:
            return True

    else:
        # when _prompt_for_password indicates not to save, we should
        # never call this function
        def should_save_password_to_keyring(*a: Any) -> bool:
            pytest.fail("_should_save_password_to_keyring should not be called")

    monkeypatch.setattr(
        auth, "_should_save_password_to_keyring", should_save_password_to_keyring
    )

    req = MockRequest("https://example.com")
    resp = MockResponse(b"")
    resp.url = req.url
    connection = MockConnection()

    def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
        assert sent_req is req
        assert "Authorization" in sent_req.headers
        r = MockResponse(b"")
        r.status_code = response_status
        return r

    # https://github.com/python/mypy/issues/2427
    connection._send = _send  # type: ignore[assignment]

    resp.request = req
    resp.status_code = 401
    resp.connection = connection

    auth.handle_401(resp)

    if expect_save:
        assert keyring.saved_credential_by_username_by_system == {
            "example.com": {
                expected_username: KeyringModuleV2.Credential(
                    expected_username, expected_password
                ),
            },
        }
    else:
        assert keyring.saved_credential_by_username_by_system == {}


@pytest.mark.parametrize(
    "url, expect",
    [
        # It's not obvious, but this url ultimately resolves to index url
        # http://example.com/path2, so we get the creds for that index.
        ("http://example.com/path1", ("saved-user1", "pw1")),
        ("http://saved-user1@example.com/path2", ("saved-user1", "pw1")),
        ("http://saved-user2@example.com/path2", ("saved-user2", "pw2")),
        ("http://new-user@example.com/path2", ("new-user", None)),
        ("http://example.com/path2/path3", ("saved-user1", "pw1")),
        ("http://foo@example.com/path2/path3", ("foo", None)),
    ],
)
def test_keyring_cli_outdated_version(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    url: str,
    expect: tuple[str | None, str | None],
) -> None:
    caplog.set_level(logging.INFO)

    keyring_subprocess = KeyringSubprocessResult()
    keyring_subprocess.old_version = True

    monkeypatch.setattr(pip._internal.network.auth.shutil, "which", lambda x: "keyring")
    monkeypatch.setattr(
        pip._internal.network.auth.subprocess, "run", keyring_subprocess
    )
    auth = MultiDomainBasicAuth(
        index_urls=["http://example.com/path2", "http://example.com/path3"],
        keyring_provider="subprocess",
    )

    with (
        keyring_subprocess.add_credential("example.com", "example", "!netloc"),
        keyring_subprocess.add_credential(
            "http://example.com/path2/", "saved-user1", "pw1"
        ),
        keyring_subprocess.add_credential(
            "http://example.com/path2/", "saved-user2", "pw2"
        ),
    ):
        actual = auth._get_new_credentials(url, allow_netrc=False, allow_keyring=True)

        # Verify no password is returned
        assert actual[1] is None

    # Verify the correct warning is given to the user
    log_records = [(r.levelname, r.message) for r in caplog.records]

    assert len(log_records) == 1
    actual_level, actual_message = log_records[0]
    assert actual_level == "WARNING"
    assert "Keyring util is outdated" in actual_message
    assert "version 25.2.1" in actual_message


@pytest.mark.parametrize("prompting", [True, False])
def test_handle_401_extracts_credentials_embedded_in_url(
    prompting: bool,
) -> None:
    """Credentials embedded in the (redirect) URL must be recovered on 401.

    When an index issues a cross-origin redirect whose ``Location`` carries
    embedded Basic-auth credentials, the vendored requests session strips the
    ``Authorization`` header, so the upstream host answers ``401``. ``resp.url``
    still contains the ``user:password@host`` credentials, and ``handle_401``
    should extract them and retry -- this needs no user interaction, so it must
    work even under ``--no-input`` (``prompting=False``).

    Regression test: previously the extraction was gated behind ``use_keyring``,
    so ``--no-input`` with the default keyring provider returned the 401 without
    retrying.
    """
    auth = MultiDomainBasicAuth(prompting=prompting, keyring_provider="disabled")

    url_with_creds = "http://user:pass@example.com/simple/pkg/"
    req = MockRequest(url_with_creds)
    resp = MockResponse(b"")
    resp.request = req
    resp.url = url_with_creds
    resp.status_code = 401

    sent_headers: dict[str, str] = {}
    connection = MockConnection()

    def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
        sent_headers.update(sent_req.headers)
        r = MockResponse(b"")
        r.status_code = 200
        return r

    connection._send = _send  # type: ignore[assignment]
    resp.connection = connection

    new_resp = auth.handle_401(resp)

    assert new_resp.status_code == 200
    # The retry must carry the exact credentials embedded in the URL, not just
    # any Authorization header.
    scheme, _, encoded = sent_headers["Authorization"].partition(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "user:pass"


class _RecordingKeyring:
    """Keyring stand-in that records every lookup and save it receives.

    Two indexes hosted on the same server are the focus, so credentials are
    stored keyed by service name, mirroring a real keyring backend.
    """

    def __init__(self) -> None:
        self.credential_by_service: dict[str, dict[str, str]] = {}
        self.get_credential_calls: list[tuple[str, str | None]] = []
        self.set_password_calls: list[tuple[str, str, str]] = []

    @dataclass
    class _Credential:
        username: str
        password: str

    def get_credential(
        self, service: str, username: str | None
    ) -> "_RecordingKeyring._Credential | None":
        self.get_credential_calls.append((service, username))
        users = self.credential_by_service.get(service, {})
        if not users:
            return None
        if username is not None and username in users:
            return self._Credential(username, users[username])
        # Mirror keyring: with no username match, hand back the first entry.
        found_user, found_password = next(iter(users.items()))
        return self._Credential(found_user, found_password)

    def get_password(self, service: str, username: str) -> str | None:
        self.get_credential_calls.append((service, username))
        return self.credential_by_service.get(service, {}).get(username)

    def set_password(self, service: str, username: str, password: str) -> None:
        self.set_password_calls.append((service, username, password))
        self.credential_by_service.setdefault(service, {})[username] = password


def _make_401_response(url: str) -> tuple[MockResponse, MockConnection, MockRequest]:
    req = MockRequest(url)
    resp = MockResponse(b"")
    resp.url = url
    resp.request = req
    resp.status_code = 401
    connection = MockConnection()
    resp.connection = connection
    return resp, connection, req


def test_two_indexes_same_host_use_distinct_keyring_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two indexes on one host must authenticate with their own keyring entry.

    Represents a build account and a deploy account owning separate indexes
    served from the same server. The credentials each index puts on its
    actual retried request are asserted independently.
    """
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    build_index = "http://example.com/build/simple"
    deploy_index = "http://example.com/deploy/simple"
    auth = MultiDomainBasicAuth(
        prompting=False,
        index_urls=[build_index, deploy_index],
        keyring_provider="import",
    )

    keyring.set_password(build_index + "/", "build-user", "build-secret")
    keyring.set_password(deploy_index + "/", "deploy-user", "deploy-secret")
    keyring.get_credential_calls.clear()
    keyring.set_password_calls.clear()

    observed_auth: dict[str, str] = {}

    def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
        scheme, _, encoded = sent_req.headers["Authorization"].partition(" ")
        assert scheme == "Basic"
        observed_auth[sent_req.url] = base64.b64decode(encoded).decode()
        response = MockResponse(b"")
        response.status_code = 200
        return response

    for index_url in (build_index, deploy_index):
        resp, connection, _ = _make_401_response(index_url + "/some-package/")
        connection._send = _send  # type: ignore[assignment]
        new_resp = auth.handle_401(resp)
        assert new_resp.status_code == 200

    # The actual outgoing requests carry the per-index credentials, never the
    # other index's account.
    assert observed_auth == {
        build_index + "/some-package/": "build-user:build-secret",
        deploy_index + "/some-package/": "deploy-user:deploy-secret",
    }

    # Keyring discovery was attempted against each index URL (its own service)
    # rather than a single host-wide service.
    looked_up_services = {service for service, _ in keyring.get_credential_calls}
    assert build_index + "/" in looked_up_services
    assert deploy_index + "/" in looked_up_services
    assert "example.com" not in looked_up_services
    # Nothing is saved here: the credentials already existed in the keyring and
    # no interactive prompt happened under --no-input.
    assert keyring.set_password_calls == []


def test_saved_credentials_are_keyed_per_index_not_netloc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful interactive save must use the index URL as its service.

    Previously the save used the netloc, so the second index on a shared host
    would overwrite the first index's keyring entry.
    """
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    build_index = "http://example.com/build/simple"
    deploy_index = "http://example.com/deploy/simple"
    auth = MultiDomainBasicAuth(
        prompting=True,
        index_urls=[build_index, deploy_index],
        keyring_provider="import",
    )
    monkeypatch.setattr(auth, "_get_url_and_credentials", lambda u: (u, None, None))
    monkeypatch.setattr(
        auth, "_should_save_password_to_keyring", lambda *a: True
    )

    scenarios = [
        (build_index + "/pkg/", ("build-user", "build-secret", True)),
        (deploy_index + "/pkg/", ("deploy-user", "deploy-secret", True)),
    ]

    for url, creds in scenarios:
        monkeypatch.setattr(auth, "_prompt_for_password", lambda *a, c=creds: c)
        resp, connection, _ = _make_401_response(url)

        def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
            assert "Authorization" in sent_req.headers
            response = MockResponse(b"")
            response.status_code = 200
            return response

        connection._send = _send  # type: ignore[assignment]
        auth.handle_401(resp)

    # Each index owns a distinct keyring service; neither is saved under the
    # bare netloc and neither overwrites the other.
    assert keyring.set_password_calls == [
        (build_index + "/", "build-user", "build-secret"),
        (deploy_index + "/", "deploy-user", "deploy-secret"),
    ]
    assert set(keyring.credential_by_service) == {
        build_index + "/",
        deploy_index + "/",
    }


def test_same_host_indexes_keep_independent_in_memory_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credentials cached for one index must not be reused by a sibling index."""
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    build_index = "http://example.com/build/simple"
    deploy_index = "http://example.com/deploy/simple"
    auth = MultiDomainBasicAuth(
        prompting=False,
        index_urls=[build_index, deploy_index],
        keyring_provider="import",
    )
    keyring.set_password(build_index + "/", "build-user", "build-secret")
    keyring.set_password(deploy_index + "/", "deploy-user", "deploy-secret")

    get = functools.partial(
        auth._get_new_credentials, allow_netrc=False, allow_keyring=True
    )

    # Prime the cache through the build index.
    assert get(build_index + "/pkg/") == ("build-user", "build-secret")
    auth.passwords[
        auth._get_cache_key(build_index + "/pkg/", "example.com")
    ] = ("build-user", "build-secret")

    # The deploy index must resolve its own credentials even though the build
    # index already populated a same-netloc cache entry historically.
    assert get(deploy_index + "/pkg/") == ("deploy-user", "deploy-secret")

    # And the per-index cache keys never collapse onto the bare netloc.
    assert auth._get_cache_key(build_index + "/pkg/", "example.com") == (
        build_index + "/"
    )
    assert auth._get_cache_key(deploy_index + "/pkg/", "example.com") == (
        deploy_index + "/"
    )
    assert "example.com" not in auth.passwords


def test_prompt_prefers_index_scoped_keyring_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The interactive prompt consults the index service before the netloc."""
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    build_index = "http://example.com/build/simple"
    auth = MultiDomainBasicAuth(
        prompting=True,
        index_urls=[build_index],
        keyring_provider="import",
    )
    # A host-wide entry exists, but the index-scoped entry wins.
    keyring.set_password("example.com", "build-user", "host-secret")
    keyring.set_password(build_index + "/", "build-user", "index-secret")

    monkeypatch.setattr(
        "pip._internal.network.auth.ask_input", lambda prompt: "build-user"
    )

    def _fail_password_prompt(_prompt: str) -> str:
        pytest.fail("should use keyring password instead of prompting")

    monkeypatch.setattr(
        "pip._internal.network.auth.ask_password", _fail_password_prompt
    )

    username, password, save = auth._prompt_for_password(
        "example.com", build_index + "/pkg/"
    )
    assert (username, password, save) == ("build-user", "index-secret", False)
    looked_up = [service for service, _ in keyring.get_credential_calls]
    assert looked_up[0] == build_index + "/"


def test_public_index_without_credentials_remains_anonymous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An index with no keyring/netrc credentials must not send an auth header.

    This covers public downloads that have no credential configuration of
    their own, sitting alongside the authenticated indexes on the same host.
    """
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    public_index = "http://example.com/public/simple"
    auth = MultiDomainBasicAuth(
        prompting=False,
        index_urls=[public_index],
        keyring_provider="import",
    )

    resp, connection, req = _make_401_response(public_index + "/pkg/")

    def _send(sent_req: MockRequest, **kwargs: Any) -> MockResponse:
        # No prompt under --no-input and no stored credentials, so the retry
        # must not attach an Authorization header.
        assert "Authorization" not in sent_req.headers
        response = MockResponse(b"")
        response.status_code = 401
        return response

    connection._send = _send  # type: ignore[assignment]
    new_resp = auth.handle_401(resp)

    assert new_resp.status_code == 401
    assert auth.passwords == {}
    assert keyring.set_password_calls == []


def test_call_attaches_per_index_credentials_to_outgoing_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full request path stamps each index with its own Authorization.

    Seeds the per-index cache (as a successful 401 challenge would) and then
    drives ``MultiDomainBasicAuth.__call__`` to confirm the headers placed on
    the real outgoing requests differ between the two same-host indexes.
    """
    keyring = _RecordingKeyring()
    monkeypatch.setitem(sys.modules, "keyring", keyring)

    build_index = "http://example.com/build/simple"
    deploy_index = "http://example.com/deploy/simple"
    auth = MultiDomainBasicAuth(
        prompting=False,
        index_urls=[build_index, deploy_index],
        keyring_provider="import",
    )
    # Simulate credentials learned and cached from earlier challenges.
    auth.passwords[build_index + "/"] = ("build-user", "build-secret")
    auth.passwords[deploy_index + "/"] = ("deploy-user", "deploy-secret")

    stamped: dict[str, str] = {}
    for index_url in (build_index, deploy_index):
        prepared = MockRequest(index_url + "/pkg/")
        result = auth(prepared)
        scheme, _, encoded = result.headers["Authorization"].partition(" ")
        assert scheme == "Basic"
        stamped[result.url] = base64.b64decode(encoded).decode()

    assert stamped == {
        build_index + "/pkg/": "build-user:build-secret",
        deploy_index + "/pkg/": "deploy-user:deploy-secret",
    }
