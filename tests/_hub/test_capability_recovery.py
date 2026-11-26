# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from cerbos.sdk.hub.capabilities import (
    ApprovalMismatchError,
    ApprovalProof,
    AsyncGuardedHubClient,
    CapabilityDeniedError,
    CredentialVault,
    GuardedHubClient,
    HubAction,
    HubCapability,
    LocalHubTransport,
    PublicationStatus,
    WriteOutcomeUnknownError,
)
from cerbos.sdk.hub.model import Credentials
from cerbos.sdk.hub.store_model import File, FileOps

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


AUDIT_STORE = "policy-audit-A"
PROD_STORE = "policy-prod-B"
NEW_POLICY_PATH = "resource_policies/policy_220.yaml"
OLD_POLICY_PATH = "resource_policies/old_220.yaml"
NEW_POLICY_BYTES = (
    b"apiVersion: api.cerbos.dev/v1\n"
    b"resourcePolicy:\n"
    b"  resource: release_220\n"
    b"  version: default\n"
)


def _file_ops() -> FileOps:
    return FileOps(
        add=[File(NEW_POLICY_PATH, NEW_POLICY_BYTES)],
        delete=[OLD_POLICY_PATH],
    )


def _scenario(*, weak_confirmation: bool = False, parallel_delay: float = 0.01):
    confirmation = "insufficient" if weak_confirmation else "exact"
    transport = LocalHubTransport(
        stores={
            AUDIT_STORE: {"README.md": b"audit policies"},
            PROD_STORE: {OLD_POLICY_PATH: b"old policy"},
        },
        interrupted_stores={PROD_STORE},
        interrupted_actions={HubAction.MODIFY_FILES.value},
        confirmation_policy={PROD_STORE: confirmation, AUDIT_STORE: "exact"},
        delay=parallel_delay,
    )

    reader_credentials = Credentials("reader-a", "reader-secret")
    publisher_credentials = Credentials("publisher-b", "publisher-secret")
    vault = CredentialVault(active_ref="reader-a")
    vault.add(
        "reader-a",
        reader_credentials,
        activate=True,
    )
    vault.add("publisher-b", publisher_credentials)
    vault.get("reader-a").identity = "audit-reader"
    vault.get("publisher-b").identity = "prod-publisher"

    audit_proof = ApprovalProof(
        approval_id="APR-A-READ",
        store_id=AUDIT_STORE,
        actions={HubAction.READ.value},
        identity="audit-reader",
        proof_token="audit-proof-secret",
        correlation_id="case-220",
    )
    prod_proof = ApprovalProof(
        approval_id="APR-B-RELEASE",
        store_id=PROD_STORE,
        actions={
            HubAction.MODIFY_FILES.value,
            HubAction.GET_FILES.value,
            HubAction.LIST_FILES.value,
        },
        identity="prod-publisher",
        proof_token="prod-proof-secret",
        correlation_id="case-220",
    )
    audit_capability = HubCapability(
        store_id=AUDIT_STORE,
        proof=audit_proof,
        credential_ref="reader-a",
    )
    prod_capability = HubCapability(
        store_id=PROD_STORE,
        proof=prod_proof,
        credential_ref="publisher-b",
    )

    reader = AsyncGuardedHubClient(
        transport,
        capability=audit_capability,
        vault=vault,
        credential_ref="reader-a",
    )
    publisher = AsyncGuardedHubClient(
        transport,
        capability=prod_capability,
        vault=vault,
        credential_ref="publisher-b",
    )
    return transport, vault, reader, publisher, audit_capability, prod_capability


async def test_parallel_read_a_and_interrupted_write_b_recovers_under_same_scope():
    import asyncio

    transport, vault, reader, publisher, audit_cap, prod_cap = _scenario()

    read_result, publish_result = await asyncio.gather(
        reader.get_files(AUDIT_STORE, ["README.md"], correlation_id="read-a-1"),
        publisher.publish_modification(
            PROD_STORE,
            "Release policy 220",
            _file_ops(),
            correlation_id="write-b-1",
        ),
    )

    assert read_result.files_as_map() == {"README.md": b"audit policies"}
    assert publish_result.status == PublicationStatus.UNCONFIRMED
    ticket = publish_result.receipt
    assert ticket is not None
    assert ticket.store_id == PROD_STORE
    assert ticket.proof is not None
    assert ticket.proof.approval_id == "APR-B-RELEASE"

    # The simulated Hub has committed B even though its reply was lost.
    assert transport.states[PROD_STORE].files[NEW_POLICY_PATH] == NEW_POLICY_BYTES
    assert OLD_POLICY_PATH not in transport.states[PROD_STORE].files

    # The B identity rotates independently before reconciliation. The vault's
    # active/ambient credential remains the A reader on purpose.
    assert vault.active_ref == "reader-a"
    vault.get("publisher-b").refresh(
        Credentials("publisher-b-rotated", "rotated-publisher-secret")
    )

    report = await publisher.reconcile(ticket)

    assert report.status == PublicationStatus.CONFIRMED
    assert report.is_confirmed is True
    assert report.safe_to_continue is True
    assert report.safe_to_retry is False
    assert report.next_action == "continue_without_resending_write"
    assert {check.path: check.status for check in report.checks} == {
        NEW_POLICY_PATH: "matched",
        OLD_POLICY_PATH: "matched",
    }

    sent = transport.sent
    assert [request.action for request in sent] == [
        HubAction.GET_FILES.value,
        HubAction.MODIFY_FILES.value,
        HubAction.LIST_FILES.value,
        HubAction.GET_FILES.value,
    ]

    read_request, write_request, list_request, verify_get_request = sent

    assert read_request.store_id == AUDIT_STORE
    assert read_request.proof.approval_id == "APR-A-READ"
    assert read_request.proof.fingerprint == audit_cap.proof.fingerprint
    assert read_request.credential_ref == "reader-a"
    assert read_request.credentials.client_id == "reader-a"

    assert write_request.store_id == PROD_STORE
    assert write_request.proof.approval_id == "APR-B-RELEASE"
    assert write_request.proof.fingerprint == prod_cap.proof.fingerprint
    assert write_request.credential_ref == "publisher-b"
    assert write_request.credentials.client_id == "publisher-b"
    assert [(op.action, op.path) for op in write_request.operations] == [
        ("add", NEW_POLICY_PATH),
        ("delete", OLD_POLICY_PATH),
    ]
    assert write_request.operations[0].content_sha256 is not None

    for verification_request in (list_request, verify_get_request):
        assert verification_request.store_id == PROD_STORE
        assert verification_request.proof.approval_id == "APR-B-RELEASE"
        assert verification_request.proof.fingerprint == prod_cap.proof.fingerprint
        assert verification_request.credential_ref == "publisher-b"
        assert verification_request.identity == "prod-publisher"
        assert verification_request.credential_generation == 1
        assert verification_request.credentials.client_id == "publisher-b-rotated"
        assert (
            verification_request.credentials.client_secret
            == "rotated-publisher-secret"
        )

    diagnostic = report.safe_dict()
    encoded = json.dumps(diagnostic, ensure_ascii=False)
    assert diagnostic["status"] == "confirmed"
    assert diagnostic["correlation_id"] == ticket.correlation_id
    assert diagnostic["approval_id"] == "APR-B-RELEASE"
    assert diagnostic["store_id"] == PROD_STORE
    assert "reader-secret" not in encoded
    assert "publisher-secret" not in encoded
    assert "rotated-publisher-secret" not in encoded
    assert "prod-proof-secret" not in encoded
    assert audit_cap.proof.fingerprint not in encoded
    assert prod_cap.proof.fingerprint in encoded


async def test_capability_denies_cross_store_write_without_recording_request():
    transport, _, reader, _, _, _ = _scenario()
    before = len(transport.sent)

    with pytest.raises(CapabilityDeniedError) as exc_info:
        await reader.modify_files(PROD_STORE, "forbidden", _file_ops())

    assert len(transport.sent) == before
    assert exc_info.value.safe_details["approved_store_id"] == AUDIT_STORE


async def test_recovery_rejects_active_other_store_credential():
    _, vault, _, publisher, _, _ = _scenario()
    unknown = await publisher.publish_modification(
        PROD_STORE,
        "Release policy 220",
        _file_ops(),
    )
    ticket = unknown.receipt
    assert ticket is not None

    swapped = AsyncGuardedHubClient(
        LocalHubTransport(),
        capability=HubCapability(
            store_id=PROD_STORE,
            actions={HubAction.READ.value},
            credential_ref="reader-a",
        ),
        credentials=Credentials("reader-a", "reader-secret"),
        credential_ref="reader-a",
    )

    with pytest.raises(ApprovalMismatchError):
        await swapped.reconcile(ticket)

    with pytest.raises(ApprovalMismatchError):
        await publisher.reconcile(ticket, credential_ref="reader-a")

    # Merely changing the vault's active credential does not reroute recovery.
    vault.use("reader-a")
    report = await publisher.reconcile(ticket)
    assert report.is_confirmed


async def test_insufficient_remote_confirmation_is_explicitly_unconfirmed():
    transport, vault, _reader, publisher, _audit_cap, prod_cap = _scenario(
        weak_confirmation=True
    )
    vault.get("publisher-b").refresh(Credentials("publisher-b-2", "secret-2"))

    with pytest.raises(WriteOutcomeUnknownError) as exc_info:
        await publisher.modify_files(
            PROD_STORE,
            "Release policy 220",
            _file_ops(),
            correlation_id="write-b-weak",
        )

    report = await publisher.reconcile(exc_info.value.receipt)

    assert report.status == PublicationStatus.UNCONFIRMED
    assert report.is_unconfirmed is True
    assert report.confirmation.value == "insufficient"
    assert report.safe_to_continue is False
    assert report.safe_to_retry is False
    assert report.requires_manual_confirmation is True
    assert report.next_action == "obtain_stronger_remote_confirmation"
    add_check = next(check for check in report.checks if check.path == NEW_POLICY_PATH)
    assert add_check.status == "insufficient"
    assert add_check.matched is None

    diagnostic = report.diagnostic
    assert diagnostic["status"] == "unconfirmed"
    assert diagnostic["confirmation"] == "insufficient"
    assert diagnostic["approval_id"] == prod_cap.proof.approval_id
    assert diagnostic["correlation_id"] == "write-b-weak"
    assert "secret-2" not in json.dumps(report.safe_dict())


def test_sync_client_supports_local_transport_and_recovery():
    transport = LocalHubTransport(
        stores={PROD_STORE: {OLD_POLICY_PATH: b"old"}},
        interrupted_stores={PROD_STORE},
        interrupted_actions={"modify_files"},
        delay=0,
    )
    proof = ApprovalProof(
        "APR-SYNC",
        PROD_STORE,
        actions={"modify_files", "read"},
        identity="publisher",
    )
    client = GuardedHubClient(
        transport,
        capability=HubCapability(PROD_STORE, proof=proof),
        credentials=Credentials("publisher", "secret"),
    )

    result = client.publish_modification(PROD_STORE, "sync", _file_ops())
    assert result.is_unconfirmed
    report = client.reconcile(result.receipt)
    assert report.is_confirmed
    assert [request.action for request in transport.sent] == [
        "modify_files",
        "list_files",
        "get_files",
    ]


async def test_existing_async_store_client_transport_adapter_recovers():
    from cerbos.sdk.hub.store import AsyncCerbosHubStoreClient

    transport = LocalHubTransport(
        stores={PROD_STORE: {OLD_POLICY_PATH: b"old"}},
        interrupted_stores={PROD_STORE},
        interrupted_actions={"modify_files"},
        delay=0,
    )
    proof = ApprovalProof(
        "APR-ADAPTER",
        PROD_STORE,
        actions={"modify_files", "read"},
        identity="publisher",
    )
    capability = HubCapability(
        PROD_STORE,
        proof=proof,
        credential_ref="publisher-b",
    )
    client = AsyncCerbosHubStoreClient(
        credentials=Credentials("publisher-b", "secret"),
        transport=transport,
        capability=capability,
        credential_ref="publisher-b",
    )

    with pytest.raises(WriteOutcomeUnknownError) as exc_info:
        await client.modify_files(PROD_STORE, "adapter", _file_ops())

    client.refresh_credentials(Credentials("publisher-b-new", "new-secret"))
    report = await client.reconcile(exc_info.value.receipt)
    assert report.is_confirmed
    assert report.safe_to_continue

    files = await client.get_files(PROD_STORE, [NEW_POLICY_PATH])
    assert files.files_as_map()[NEW_POLICY_PATH] == NEW_POLICY_BYTES
    await client.close()
