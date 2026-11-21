from pathlib import Path

from pip._internal.models.source_policy import SourcePolicy
from pip._internal.utils.urls import path_to_url


def test_empty_policy_allows_everything() -> None:
    policy = SourcePolicy()
    assert not policy.enforced
    assert policy.allows("anything", "https://example.com/pkg-1.0.whl")
    assert policy.allows("anything", "file:///somewhere/pkg-1.0.whl")


def test_directory_source_matches_links_below_it(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    policy = SourcePolicy([str(repo)])
    assert policy.enforced

    base = path_to_url(str(repo))
    assert policy.allows("pkg", f"{base}/pkg-1.0-py3-none-any.whl")
    assert policy.allows("pkg", f"{base}/subdir/pkg-1.0-py3-none-any.whl")
    # Sibling directories with a common prefix must not match.
    assert not policy.allows("pkg", f"{base}2/pkg-1.0-py3-none-any.whl")
    assert not policy.allows("pkg", "https://example.com/pkg-1.0-py3-none-any.whl")


def test_url_source_prefix_matching() -> None:
    policy = SourcePolicy(["https://files.example.com/packages/"])
    assert policy.allows("pkg", "https://files.example.com/packages/pkg-1.0.whl")
    assert not policy.allows("pkg", "https://other.example.com/packages/pkg-1.0.whl")
    assert not policy.allows("pkg", "https://files.example.com/elsewhere/pkg-1.0.whl")


def test_exact_file_source() -> None:
    wheel = tmp_wheel = "https://files.example.com/packages/pkg-1.0.whl"
    policy = SourcePolicy([wheel])
    assert policy.allows("pkg", tmp_wheel)
    assert not policy.allows("pkg", "https://files.example.com/packages/other-1.0.whl")


def test_build_tool_exception_is_name_canonicalized() -> None:
    policy = SourcePolicy(
        ["https://approved.example.com/"],
        approved_build_tools=["Approved_Backend"],
    )
    assert "approved-backend" in policy.approved_build_tools
    # The exempt build tool may come from anywhere.
    assert policy.allows("approved-backend", "https://elsewhere.example.com/x.whl")
    assert policy.allows("Approved-Backend", "file:///unapproved/x.whl")
    # Other packages are still restricted.
    assert not policy.allows("normaldep", "https://elsewhere.example.com/x.whl")
    assert policy.allows("normaldep", "https://approved.example.com/x.whl")


def test_local_file_url_source(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    url = path_to_url(str(repo)) + "/"
    policy = SourcePolicy([url])
    assert policy.allows("pkg", f"{url}pkg-1.0-py3-none-any.whl")
