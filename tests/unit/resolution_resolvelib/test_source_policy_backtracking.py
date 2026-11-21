"""Contract tests for backtracking around deployment source rules.

The local index below is intentionally tiny:

* ``approved/`` holds ``app 1.0``, ``app 2.0`` and ``lib 1.0``.
* ``unapproved/`` holds ``lib 2.0``. It is a normal, well-formed wheel: the
  name and version are legal, only the source rule rejects it.

``app 2.0`` requires ``lib>=2`` while ``app 1.0`` requires ``lib>=1``. The
resolver first tries ``app 2.0``, finds that ``lib 2.0`` is the only version
satisfying ``lib>=2`` but forbidden by the deployment policy, and backtracks
to ``app 1.0``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from pip._internal.exceptions import DistributionNotFound
from pip._internal.index.package_finder import PackageFinder
from pip._internal.metadata import BaseDistribution
from pip._internal.models.link import Link
from pip._internal.models.source_policy import SourcePolicy
from pip._internal.operations.prepare import RequirementPreparer
from pip._internal.req.constructors import install_req_from_line
from pip._internal.req.req_install import InstallRequirement
from pip._internal.resolution.resolvelib.resolver import Resolver

from tests.lib import make_test_finder
from tests.lib.wheel import WheelBuilder, make_wheel

WheelFactory = Callable[[], WheelBuilder]


def _add_wheel(
    wheels: dict[str, tuple[WheelFactory, str]],
    directory: Path,
    name: str,
    version: str,
    requires: str | None = None,
) -> None:
    def factory() -> WheelBuilder:
        metadata_updates: dict[str, str | list[str]] = {}
        if requires:
            metadata_updates["Requires-Dist"] = [requires]
        return make_wheel(name, version, metadata_updates=metadata_updates)

    path = Path(factory().save_to_dir(directory))
    wheels[path.name] = (factory, name)


@pytest.fixture
def small_index(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, tuple[WheelFactory, str]]]:
    """Two local indexes, plus a wheel-filename -> (factory, name) map."""
    approved = tmp_path / "approved"
    unapproved = tmp_path / "unapproved"
    approved.mkdir()
    unapproved.mkdir()

    wheels: dict[str, tuple[WheelFactory, str]] = {}
    _add_wheel(wheels, approved, "app", "2.0", requires="lib>=2")
    _add_wheel(wheels, approved, "app", "1.0", requires="lib>=1")
    _add_wheel(wheels, approved, "lib", "1.0")
    _add_wheel(wheels, unapproved, "lib", "2.0")

    return approved, unapproved, wheels


@pytest.fixture
def finder(
    small_index: tuple[Path, Path, dict[str, tuple[WheelFactory, str]]],
) -> PackageFinder:
    approved, unapproved, _ = small_index
    return make_test_finder(
        find_links=[str(approved), str(unapproved)],
        source_policy=SourcePolicy(approved_sources=[str(approved)]),
    )


@pytest.fixture
def prepared_links(
    preparer: RequirementPreparer,
    small_index: tuple[Path, Path, dict[str, tuple[WheelFactory, str]]],
    monkeypatch: pytest.MonkeyPatch,
) -> list[str]:
    """Record every link that reaches preparation and serve wheel metadata."""
    _, _, wheels = small_index
    seen: list[str] = []

    def prepare_linked_requirement(
        req: InstallRequirement, parallel_builds: bool = False
    ) -> BaseDistribution:
        assert req.link is not None
        seen.append(req.link.url)
        factory, name = wheels[req.link.filename]
        return factory().as_distribution(name)

    monkeypatch.setattr(
        preparer, "prepare_linked_requirement", prepare_linked_requirement
    )
    return seen


@pytest.fixture
def resolver(preparer: RequirementPreparer, finder: PackageFinder) -> Resolver:
    return Resolver(
        preparer=preparer,
        finder=finder,
        wheel_cache=None,
        make_install_req=install_req_from_line,
        use_user_site=False,
        ignore_dependencies=False,
        only_dependencies=False,
        ignore_installed=True,
        ignore_requires_python=False,
        force_reinstall=False,
        upgrade_strategy="to-satisfy-only",
    )


def _selected_versions(resolver: Resolver) -> dict[str, str]:
    assert resolver._result is not None
    return {
        name: str(candidate.version)
        for name, candidate in resolver._result.mapping.items()
        if candidate.get_install_requirement() is not None
    }


def _prepared_filenames(links: list[str]) -> set[str]:
    return {Link(url).filename for url in links}


def test_backtracks_to_approved_version_and_skips_rejected_candidate(
    resolver: Resolver,
    prepared_links: list[str],
    small_index: tuple[Path, Path, dict[str, tuple[WheelFactory, str]]],
) -> None:
    approved, _, _ = small_index
    result = resolver.resolve([install_req_from_line("app")], True)

    # ``app 2.0`` is tried first but cannot be satisfied because ``lib 2.0``
    # is not an approved source, so the plan falls back to ``app 1.0``.
    assert _selected_versions(resolver) == {"app": "1.0", "lib": "1.0"}
    assert set(result.requirements) == {"app", "lib"}

    # Only candidates from the approved index reached preparation. In
    # particular the well-formed ``lib 2.0`` wheel never did, even though the
    # resolver did consider ``app 2.0`` and had to backtrack.
    assert _prepared_filenames(prepared_links) == {
        "app-2.0-py2.py3-none-any.whl",
        "app-1.0-py2.py3-none-any.whl",
        "lib-1.0-py2.py3-none-any.whl",
    }
    approved_root = approved.resolve()
    assert all(
        Path(Link(url).file_path).parent == approved_root for url in prepared_links
    )


def test_version_constraint_failure_is_reported_as_such(
    resolver: Resolver,
    prepared_links: list[str],
) -> None:
    with pytest.raises(DistributionNotFound) as excinfo:
        resolver.resolve(
            [install_req_from_line("lib==3.0")], check_supported_wheels=True
        )

    message = str(excinfo.value)
    assert "No matching distribution found for lib==3.0" in message
    # No version exists at all, so this is a plain version constraint failure.
    assert "approved source" not in message
    assert prepared_links == []


def test_existing_version_rejected_by_policy_is_reported_separately(
    resolver: Resolver,
    prepared_links: list[str],
) -> None:
    with pytest.raises(DistributionNotFound) as excinfo:
        resolver.resolve(
            [install_req_from_line("lib==2.0")], check_supported_wheels=True
        )

    message = str(excinfo.value)
    assert "No matching distribution found for lib==2.0" in message
    # The version exists, but the deployment rule forbids its source. The
    # error must say so instead of pretending no such version exists.
    assert "version(s) 2.0 exist but are not from an approved source" in message
    assert "Could not find a version" not in message
    assert prepared_links == []


def test_without_policy_the_unapproved_version_is_used(
    preparer: RequirementPreparer,
    prepared_links: list[str],
    small_index: tuple[Path, Path, dict[str, tuple[WheelFactory, str]]],
) -> None:
    """The same index without a policy picks the newest versions."""
    approved, unapproved, _ = small_index
    unrestricted = Resolver(
        preparer=preparer,
        finder=make_test_finder(find_links=[str(approved), str(unapproved)]),
        wheel_cache=None,
        make_install_req=install_req_from_line,
        use_user_site=False,
        ignore_dependencies=False,
        only_dependencies=False,
        ignore_installed=True,
        ignore_requires_python=False,
        force_reinstall=False,
        upgrade_strategy="to-satisfy-only",
    )
    unrestricted.resolve([install_req_from_line("app")], True)

    assert _selected_versions(unrestricted) == {"app": "2.0", "lib": "2.0"}
    assert "lib-2.0-py2.py3-none-any.whl" in _prepared_filenames(prepared_links)
