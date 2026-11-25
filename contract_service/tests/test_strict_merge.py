"""Strict-mode authorization evidence for the contract merge service."""

import pytest
from pypdf import PdfReader
from pypdf.constants import UserAccessPermissions

from contract_service.make_fixtures import build_fixtures
from contract_service.service import (
    AuthorizationError,
    OutputPolicy,
    authorize,
    merge_contracts,
)

OUTPUT_POLICY = OutputPolicy(
    user_password="merged-view-pass",
    owner_password="merged-owner-pass",
    permissions=UserAccessPermissions.PRINT | UserAccessPermissions.EXTRACT,
    algorithm="AES-256",
)


@pytest.fixture()
def fixtures(tmp_path):
    return build_fixtures(tmp_path / "fixtures")


def test_openable_does_not_mean_mergeable(fixtures, tmp_path):
    """contract_b opens with its user password but may not be merged."""
    reader, grant = authorize(fixtures["contract_b"], "view-b-pass", purpose="view")
    assert grant.granted and len(reader.pages) == 3

    with pytest.raises(AuthorizationError, match="merging is not granted"):
        authorize(fixtures["contract_b"], "view-b-pass", purpose="merge")


def test_merge_requires_authorization_for_every_input(fixtures, tmp_path):
    out = tmp_path / "merged.pdf"
    receipt = merge_contracts(
        [
            (fixtures["contract_a"], "view-a-pass"),
            (fixtures["contract_b"], "owner-b-pass"),
        ],
        out,
        OUTPUT_POLICY,
    )
    assert receipt.total_pages == 5
    assert receipt.page_counts == {
        str(fixtures["contract_a"]): 2,
        str(fixtures["contract_b"]): 3,
    }
    # The output obeys its own policy, not any input's.
    reader = PdfReader(str(out))
    assert reader.is_encrypted
    assert reader.decrypt("merged-view-pass") != 0
    assert len(reader.pages) == 5
    perms = reader.user_access_permissions
    assert perms & UserAccessPermissions.PRINT
    assert perms & UserAccessPermissions.EXTRACT
    assert not perms & UserAccessPermissions.MODIFY
    # Input passwords must NOT open the output.
    assert PdfReader(str(out)).decrypt("view-a-pass") == 0


def test_denied_merge_writes_nothing(fixtures, tmp_path):
    out = tmp_path / "should_not_exist.pdf"
    with pytest.raises(AuthorizationError):
        merge_contracts(
            [
                (fixtures["contract_a"], "view-a-pass"),
                (fixtures["contract_b"], "view-b-pass"),  # view-only
            ],
            out,
            OUTPUT_POLICY,
        )
    assert not out.exists()  # stopped before any write


def test_blank_template_view_vs_export(fixtures):
    """Same encrypted template: view granted, export decided per password."""
    template = fixtures["blank_template"]

    _, grant = authorize(template, "template-view-pass", purpose="view")
    assert grant.granted

    with pytest.raises(AuthorizationError):
        authorize(template, "template-view-pass", purpose="merge")

    _, grant = authorize(template, "template-owner-pass", purpose="merge")
    assert grant.granted and grant.password_type == "owner"


def test_wrong_password_cannot_even_view(fixtures):
    with pytest.raises(AuthorizationError, match="view denied"):
        authorize(fixtures["contract_a"], "not-the-password", purpose="view")
