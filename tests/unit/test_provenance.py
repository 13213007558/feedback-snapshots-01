from __future__ import annotations

import json
from pathlib import Path

import pytest

from pip._internal.models.direct_url import ArchiveInfo, DirectUrl, VcsInfo
from pip._internal.models.link import Link
from pip._internal.models.provenance import (
    SOURCE_TYPE_DIRECT_URL,
    SOURCE_TYPE_INDEX,
    SOURCE_TYPE_LOCAL_FILE,
    SOURCE_TYPE_VCS,
    ProvenanceSummary,
    ProvenanceSummaryError,
    build_provenance_entry,
    describe_link_for_diagnostics,
)
from pip._internal.req.constructors import install_req_from_line
from pip._internal.req.req_install import InstallRequirement
from pip._vendor.packaging.requirements import Requirement

from tests.lib.wheel import make_wheel

# Values that must never reach approval material.
SECRET_USER = "deploy-token"
SECRET_PASSWORD = "super-secret-password"
INTERNAL_HOST = "index.internal.example"
DIRECT_HOST = "files.example.com"
VCS_HOST = "git.example.com"
SHA256 = "a" * 64


@pytest.fixture
def secret_dir(tmp_path: Path) -> Path:
    # A deliberately machine-specific, nested path that must not be serialized.
    path = tmp_path / "private" / "app-release"
    path.mkdir(parents=True)
    return path


def _attach_distribution(ireq: InstallRequirement, name: str, version: str) -> None:
    ireq.set_dist(make_wheel(name, version).as_distribution(name))


def _index_requirement() -> InstallRequirement:
    """A requirement resolved through the internal index.

    The artifact link carries credentials, but the requirement itself was a bare
    name, so ``original_link`` stays ``None`` (as the resolver leaves it for
    index-resolved requirements).
    """
    ireq = install_req_from_line("internalpkg==1.2.3")
    _attach_distribution(ireq, "internalpkg", "1.2.3")
    ireq.link = Link(
        f"https://{SECRET_USER}:{SECRET_PASSWORD}@{INTERNAL_HOST}/simple/"
        "internalpkg/internalpkg-1.2.3-py3-none-any.whl"
    )
    ireq.original_link = None
    ireq.download_info = DirectUrl(
        url=(
            f"https://{SECRET_USER}:{SECRET_PASSWORD}@{INTERNAL_HOST}/simple/"
            "internalpkg/internalpkg-1.2.3-py3-none-any.whl"
        ),
        archive_info=ArchiveInfo(hashes={"sha256": SHA256}),
    )
    return ireq


def _local_file_requirement(secret_dir: Path) -> InstallRequirement:
    wheel_path = Path(
        make_wheel("localpkg", "2.0.0").save_to_dir(secret_dir)
    )
    ireq = install_req_from_line(wheel_path.as_posix())
    _attach_distribution(ireq, "localpkg", "2.0.0")
    ireq.download_info = DirectUrl(
        url=wheel_path.as_uri(),
        archive_info=ArchiveInfo(hashes={"sha256": "b" * 64}),
    )
    return ireq


def _direct_url_requirement() -> InstallRequirement:
    ireq = install_req_from_line(
        "directpkg @ "
        f"https://{SECRET_USER}:{SECRET_PASSWORD}@{DIRECT_HOST}/"
        f"directpkg-3.0.0-py3-none-any.whl#sha256={'c' * 64}"
    )
    _attach_distribution(ireq, "directpkg", "3.0.0")
    return ireq


def _vcs_requirement() -> InstallRequirement:
    ireq = InstallRequirement(
        Requirement("vcsdep"),
        None,
        link=Link(
            f"git+https://{SECRET_USER}:{SECRET_PASSWORD}@{VCS_HOST}/team/repo.git"
            "@deadbeef"
        ),
    )
    ireq.download_info = DirectUrl(
        url=f"https://{SECRET_USER}:{SECRET_PASSWORD}@{VCS_HOST}/team/repo.git",
        vcs_info=VcsInfo(vcs="git", commit_id="deadbeef"),
    )
    return ireq


@pytest.fixture
def plan(secret_dir: Path) -> list[InstallRequirement]:
    return [
        _index_requirement(),
        _local_file_requirement(secret_dir),
        _direct_url_requirement(),
    ]


def test_summary_preserves_source_type_name_and_evidence(
    plan: list[InstallRequirement],
) -> None:
    summary = ProvenanceSummary(plan).to_dict()

    assert summary["version"] == "1"
    by_name = {entry["name"]: entry for entry in summary["packages"]}

    assert by_name["internalpkg"]["source_type"] == SOURCE_TYPE_INDEX
    assert by_name["internalpkg"]["version"] == "1.2.3"
    assert by_name["internalpkg"]["content_evidence"] == {
        "hashes": {"sha256": SHA256}
    }

    assert by_name["localpkg"]["source_type"] == SOURCE_TYPE_LOCAL_FILE
    assert by_name["localpkg"]["version"] == "2.0.0"

    assert by_name["directpkg"]["source_type"] == SOURCE_TYPE_DIRECT_URL
    assert by_name["directpkg"]["version"] == "3.0.0"
    # Hash is recovered from the link fragment even without download_info.
    assert by_name["directpkg"]["content_evidence"] == {
        "hashes": {"sha256": "c" * 64}
    }


def test_summary_structured_output_has_no_policy_values(
    plan: list[InstallRequirement], secret_dir: Path
) -> None:
    serialized = json.dumps(ProvenanceSummary(plan).to_dict())

    forbidden = [
        SECRET_USER,
        SECRET_PASSWORD,
        INTERNAL_HOST,
        DIRECT_HOST,
        str(secret_dir),
        "file://",
        "https://",
        "http://",
        "@",
    ]
    for value in forbidden:
        assert value not in serialized, f"{value!r} leaked into the summary"


def test_summary_text_output_has_no_policy_values(
    plan: list[InstallRequirement], secret_dir: Path
) -> None:
    text = ProvenanceSummary(plan).to_text()

    for value in [
        SECRET_USER,
        SECRET_PASSWORD,
        INTERNAL_HOST,
        DIRECT_HOST,
        str(secret_dir),
        "file://",
        "https://",
        "@",
    ]:
        assert value not in text, f"{value!r} leaked into the text summary"

    # The source type stays recognizable for internal troubleshooting.
    assert "internalpkg (index)" in text
    assert "localpkg (local_file)" in text
    assert "directpkg (direct_url)" in text
    assert "hashes=sha256=" in text


def test_vcs_requirement_records_commit_without_location() -> None:
    entry = build_provenance_entry(_vcs_requirement())

    assert entry["source_type"] == SOURCE_TYPE_VCS
    assert entry["content_evidence"]["vcs_info"] == {
        "vcs": "git",
        "commit_id": "deadbeef",
    }
    serialized = json.dumps(entry)
    for value in [SECRET_USER, SECRET_PASSWORD, VCS_HOST, "https://", "@"]:
        assert value not in serialized


def test_requirement_without_link_is_classified_as_index() -> None:
    ireq = install_req_from_line("plain==1.0")
    _attach_distribution(ireq, "plain", "1.0")

    entry = build_provenance_entry(ireq)
    assert entry["source_type"] == SOURCE_TYPE_INDEX
    assert "content_evidence" not in entry


def test_missing_name_raises_safe_error() -> None:
    ireq = InstallRequirement(
        None,
        None,
        link=Link(f"https://{SECRET_USER}:{SECRET_PASSWORD}@{DIRECT_HOST}/x.whl"),
    )
    with pytest.raises(ProvenanceSummaryError) as exc_info:
        build_provenance_entry(ireq)

    message = str(exc_info.value)
    assert SECRET_PASSWORD not in message
    assert DIRECT_HOST not in message
    assert "package name" in message


def test_describe_link_for_diagnostics_hides_location() -> None:
    direct = Link(
        f"https://{SECRET_USER}:{SECRET_PASSWORD}@{DIRECT_HOST}/path/x-1.0.whl"
    )
    described = describe_link_for_diagnostics(direct)

    assert described == "direct_url:x-1.0.whl"
    for value in [SECRET_USER, SECRET_PASSWORD, DIRECT_HOST, "path", "https://", "@"]:
        assert value not in described


def test_describe_link_for_local_and_vcs() -> None:
    local = Link(Path("/opt/secret/app-1.0-py3-none-any.whl").as_uri())
    assert describe_link_for_diagnostics(local) == (
        "local_file:app-1.0-py3-none-any.whl"
    )

    vcs = Link(
        f"git+https://{SECRET_USER}:{SECRET_PASSWORD}@{VCS_HOST}/team/repo.git"
        "@deadbeef"
    )
    described = describe_link_for_diagnostics(vcs)
    assert described.startswith("vcs:")
    assert VCS_HOST not in described
    assert SECRET_PASSWORD not in described
    assert "@" not in described


def test_describe_link_distinguishes_index_from_direct_url() -> None:
    link = Link(f"https://{SECRET_USER}:{SECRET_PASSWORD}@{INTERNAL_HOST}/i-3.0.whl")

    # Without requirement context a remote link is treated as a direct URL.
    assert describe_link_for_diagnostics(link) == "direct_url:i-3.0.whl"

    # An index-resolved requirement (original_link is None) is labeled index.
    index_ireq = install_req_from_line("ipkg==3.0")
    index_ireq.link = link
    index_ireq.original_link = None
    described = describe_link_for_diagnostics(link, index_ireq)
    assert described == "index:i-3.0.whl"
    assert SECRET_PASSWORD not in described and INTERNAL_HOST not in described


def test_to_dict_returns_defensive_copy(plan: list[InstallRequirement]) -> None:
    summary = ProvenanceSummary(plan)
    first = summary.to_dict()
    first["packages"].clear()
    # Mutating the returned dict must not change the summary itself.
    assert summary.to_dict()["packages"]
