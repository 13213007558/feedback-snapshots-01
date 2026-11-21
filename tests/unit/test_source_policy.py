from __future__ import annotations

from pathlib import Path

from pip._internal.commands.install import InstallCommand
from pip._internal.models.source_policy import SourcePolicy
from pip._internal.network.session import PipSession
from pip._internal.utils.urls import path_to_url


def test_empty_policy_allows_everything() -> None:
    policy = SourcePolicy()
    assert not policy.enforced
    assert policy.allows("pkg", "https://example.com/pkg-1.0.whl")
    assert policy.allows("pkg", "file:///somewhere/pkg-1.0.whl")


def test_directory_source_matches_only_links_below_it(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = SourcePolicy([str(repo)])
    assert policy.enforced

    base = path_to_url(str(repo))
    assert policy.allows("pkg", f"{base}/pkg-1.0-py3-none-any.whl")
    assert policy.allows("pkg", f"{base}/subdir/pkg-1.0-py3-none-any.whl")
    # A sibling directory that merely shares a prefix is not approved.
    assert not policy.allows("pkg", f"{base}2/pkg-1.0-py3-none-any.whl")
    assert not policy.allows("pkg", "https://example.com/pkg-1.0.whl")


def test_url_source_prefix_matching() -> None:
    policy = SourcePolicy(["https://files.example.com/packages/"])
    assert policy.allows("pkg", "https://files.example.com/packages/pkg-1.0.whl")
    assert not policy.allows("pkg", "https://other.example.com/packages/pkg-1.0.whl")
    assert not policy.allows("pkg", "https://files.example.com/elsewhere/pkg-1.0.whl")


def test_exact_file_source() -> None:
    wheel = "https://files.example.com/packages/pkg-1.0.whl"
    policy = SourcePolicy([wheel])
    assert policy.allows("pkg", wheel)
    assert not policy.allows("pkg", "https://files.example.com/packages/pkg-2.0.whl")


def test_approved_source_option_is_repeatable(tmp_path: Path) -> None:
    command = InstallCommand("install", "Install packages.")
    options, _ = command.parser.parse_args(
        [
            "--approved-source",
            str(tmp_path / "one"),
            "--approved-source",
            str(tmp_path / "two"),
            "pkg",
        ]
    )
    assert options.approved_sources == [
        str(tmp_path / "one"),
        str(tmp_path / "two"),
    ]


def test_option_builds_an_active_policy(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    command = InstallCommand("install", "Install packages.")
    options, _ = command.parser.parse_args(["--approved-source", str(approved), "pkg"])
    with PipSession() as session:
        finder = command._build_package_finder(options=options, session=session)

    assert finder.source_policy.enforced
    assert finder.source_policy.allows(
        "pkg", (approved / "pkg-1.0-py3-none-any.whl").as_uri()
    )
    assert not finder.source_policy.allows(
        "pkg", (tmp_path / "other" / "pkg-1.0-py3-none-any.whl").as_uri()
    )


def test_without_option_policy_is_inactive() -> None:
    command = InstallCommand("install", "Install packages.")
    options, _ = command.parser.parse_args(["pkg"])
    with PipSession() as session:
        finder = command._build_package_finder(options=options, session=session)
    assert not finder.source_policy.enforced
