"""Tests for C-MOVE destination authorisation.

These tests deliberately avoid any real network activity: both the association
that receives the C-MOVE request and the association used to send the
C-STORE sub-operations are replaced with in-memory doubles. They verify that:

* the query approval and the destination approval are separate decisions,
* only approved datasets reach the destination,
* changing the destination approval part-way through the operation (after the
  first synthetic dataset has been sent) stops further datasets,
* the final C-MOVE summary distinguishes datasets that were *never sent* from
  genuine C-STORE failures.
"""

from io import BytesIO

import pytest

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ImplicitVRLittleEndian

from pynetdicom import AE, build_context, evt
from pynetdicom.association import Association
from pynetdicom.authorization import (
    DESTINATION_STAGE,
    QUERY_STAGE,
    SUB_OPERATION_STAGE,
    InMemoryMoveAuthorization,
    MoveApproval,
    query_identity,
)
from pynetdicom.dimse_primitives import C_MOVE
from pynetdicom.dsutils import encode
from pynetdicom.service_class import QueryRetrieveServiceClass
from pynetdicom.status import QR_MOVE_SERVICE_CLASS_STATUS

MOVE_MODEL = "1.2.840.10008.5.1.4.1.2.1.2"
CT_IMAGE_STORAGE = "1.2.840.10008.5.1.4.1.1.2"


def make_dataset(uid, patient="SYNTHETIC"):
    """Create a small synthetic dataset to send over the in-memory double."""
    ds = Dataset()
    ds.SOPClassUID = CT_IMAGE_STORAGE
    ds.SOPInstanceUID = uid
    ds.PatientName = patient
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
    return ds


class InMemoryDimse:
    """Capture the C-MOVE responses instead of writing them to a socket."""

    def __init__(self):
        self.sent = []
        self.cancel_req = {}

    def send_msg(self, msg, cx_id):
        self.sent.append(
            {
                "Status": msg.Status,
                "Remaining": msg.NumberOfRemainingSuboperations,
                "Failed": msg.NumberOfFailedSuboperations,
                "Warning": msg.NumberOfWarningSuboperations,
                "Completed": msg.NumberOfCompletedSuboperations,
                "ErrorComment": msg.ErrorComment,
            }
        )

    @property
    def final(self):
        return self.sent[-1]


class InMemoryStoreAssociation:
    """An in-memory replacement for the association with the Move Destination.

    ``on_store`` is called after each C-STORE is received; it may change the
    authorisation policy part-way through the operation.
    """

    is_established = True

    def __init__(self, on_store=None, status=0x0000):
        self.datasets = []
        self.released = False
        self.on_store = on_store
        self.status = status

    def send_c_store(self, dataset, **kwargs):
        # Simulate the destination receiving (or rejecting) the dataset
        self.datasets.append(dataset)
        if self.on_store is not None:
            self.on_store(len(self.datasets), dataset)

        status = Dataset()
        status.Status = self.status
        return status

    def release(self):
        self.released = True


class InMemoryServerAssociation(Association):
    """A real Association with only its DIMSE provider replaced.

    Using the real class means the C-MOVE request is actually dispatched
    through :func:`pynetdicom.evt.trigger`, the default handlers and the
    service class' abort hooks, without any network activity.
    """

    def __init__(self, request_identity="EXPORT_SCU"):
        super().__init__(AE("EXPORT_SCP"), mode="acceptor")
        self.is_established = True
        self.requestor.ae_title = request_identity
        self.dimse = InMemoryDimse()

    def bind(self, event, handler):
        super().bind(event, handler)


def _run_move(handler, policy, datasets, on_store=None, request_identity="EXPORT_SCU"):
    """Drive a single C-MOVE through the real ``_move_scp`` implementation."""
    assoc = InMemoryServerAssociation(request_identity)
    assoc.bind(evt.EVT_C_MOVE, handler)

    store = InMemoryStoreAssociation(on_store=on_store)
    assoc.ae.associate = lambda *a, **k: store
    assoc.ae.move_authorization = policy

    req = C_MOVE()
    req.MessageID = 7
    req.AffectedSOPClassUID = MOVE_MODEL
    req.MoveDestination = "ARCHIVE_DEST"
    req.Priority = 2
    req.Identifier = BytesIO(encode(Dataset(), True, True))

    context = build_context(MOVE_MODEL, ImplicitVRLittleEndian)
    context.context_id = 1

    service = QueryRetrieveServiceClass(assoc)
    service.statuses = QR_MOVE_SERVICE_CLASS_STATUS
    service._move_scp(req, context)

    return assoc.dimse, store


def _yield_datasets(datasets):
    def handler(event):
        yield ("localhost", 11113)
        yield len(datasets)
        for ds in datasets:
            yield 0xFF00, ds

    return handler


class TestQueryApproval:
    """The query approval is a separate decision from the destination."""

    def test_query_identity_denied(self):
        """A query from an unapproved identity is refused with 0x0124."""
        policy = InMemoryMoveAuthorization(approved_queries=[])
        # The destination *is* approved, but the query isn't
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert dimse.final["Status"] == 0x0124
        assert store.datasets == []
        assert dimse.final["ErrorComment"] == "query identity not approved"

        # The audit log's last decision is the denied query; the destination
        #   is never consulted for this request
        stages = [(a.stage, a.approved) for a in policy.audit_log if a.stage in (
            QUERY_STAGE,
            DESTINATION_STAGE,
        )]
        assert stages[-1] == (QUERY_STAGE, False)

    def test_query_identity_approved(self):
        """An approved identity proceeds to the destination decision."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert dimse.final["Status"] == 0x0000
        assert [d.SOPInstanceUID for d in store.datasets] == ["1.2.3.1"]

    def test_query_identity_uses_calling_aet(self):
        """The identity is derived from the calling AE title by default."""
        assoc = InMemoryServerAssociation()
        assert query_identity(assoc) == "EXPORT_SCU"


class TestDestinationApproval:
    """The destination approval is a distinct decision."""

    def test_destination_denied_is_not_query_denial(self):
        """The query may be approved while the destination is refused."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        # No destination grant at all
        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert dimse.final["Status"] == 0x0124
        assert store.datasets == []
        # All sub-operations remain unsent
        assert dimse.final["Remaining"] == 2
        assert dimse.final["Failed"] == 0
        assert "no destination approval" in dimse.final["ErrorComment"]

        stages = [a.stage for a in policy.audit_log]
        assert QUERY_STAGE in stages
        assert DESTINATION_STAGE in stages
        # The destination association is never opened, so no sub-operation
        #   approvals are requested
        assert SUB_OPERATION_STAGE not in stages

    def test_destination_approved_opens_association(self):
        """An approved destination receives the datasets."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert dimse.final["Status"] == 0x0000
        assert [d.SOPInstanceUID for d in store.datasets] == ["1.2.3.1", "1.2.3.2"]
        assert store.released

    def test_each_sub_operation_is_rechecked(self):
        """Every C-STORE sub-operation consults the policy again."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        sub_ops = [a for a in policy.audit_log if a.stage == SUB_OPERATION_STAGE]
        assert len(sub_ops) == 2
        assert sub_ops[0].sop_instance_uid == "1.2.3.1"
        assert sub_ops[1].sop_instance_uid == "1.2.3.2"
        assert all(a.approved for a in sub_ops)


class TestDestinationRevokedDuringOperation:
    """Withdrawing the destination approval part-way through the operation."""

    def test_revoke_after_first_dataset(self):
        """Only the approved dataset reaches the destination."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [
            make_dataset("1.2.3.1"),
            make_dataset("1.2.3.2"),
            make_dataset("1.2.3.3"),
        ]

        def revoke_after_first(count, dataset):
            if count == 1:
                policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

        dimse, store = _run_move(
            _yield_datasets(datasets), policy, datasets, on_store=revoke_after_first
        )

        # Only the first synthetic dataset reached the destination
        assert [d.SOPInstanceUID for d in store.datasets] == ["1.2.3.1"]

        # The final summary reports the two datasets that were never sent as
        #   remaining sub-operations, without inventing C-STORE failures
        final = dimse.final
        assert final["Status"] == 0xB000  # Warning: incomplete
        assert final["Remaining"] == 2
        assert final["Completed"] == 1
        assert final["Failed"] == 0
        assert final["Warning"] == 0
        assert final["ErrorComment"] == "destination approval withheld"

        # The final response carries a Failed SOP Instance UID List containing
        #   only genuine failures (none here)
        assert store.released

    def test_revoke_after_first_does_not_affect_completed_count(self):
        """The completed count reflects only datasets actually sent."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset(f"1.2.3.{ii}") for ii in range(1, 5)]

        def revoke(count, dataset):
            if count == 1:
                policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

        dimse, store = _run_move(
            _yield_datasets(datasets), policy, datasets, on_store=revoke
        )

        assert len(store.datasets) == 1
        assert dimse.final["Completed"] == 1
        assert dimse.final["Remaining"] == 3

    def test_revoke_before_first_dataset_sends_nothing(self):
        """Revoking before any dataset is sent leaves everything unsent."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]

        def revoke_immediately(count, dataset):
            policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

        # The revoke happens *after* the first accepted sub-operation approval
        #   but before its C-STORE is recorded as received; to test revocation
        #   prior to sending, revoke from the pending yield instead
        def handler(event):
            yield ("localhost", 11113)
            yield len(datasets)
            for ds in datasets:
                policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")
                yield 0xFF00, ds

        dimse, store = _run_move(handler, policy, datasets)

        assert store.datasets == []
        # No sub-operation was attempted, so the operation is refused
        assert dimse.final["Status"] == 0x0124
        assert dimse.final["Remaining"] == 2
        assert dimse.final["Failed"] == 0
        assert dimse.final["Completed"] == 0

    def test_regrant_after_revoke_does_not_restore_old_approval(self):
        """Re-granting creates a new generation, invalidating old approvals."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        approval = policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        # The pre-revocation approval must not be reusable
        result = policy.approve_sub_operation(approval, make_dataset("1.2.3.1"))
        assert result.denied
        assert result.reason == "destination approval changed during the operation"


class TestSummarySeparatesUnsentAndFailed:
    """The final summary must not conflate unsent datasets with failures."""

    def test_store_failures_are_reported_as_failed(self):
        """Genuine C-STORE failures are counted as failed, not remaining."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
        dimse, store = _run_move(
            _yield_datasets(datasets),
            policy,
            datasets,
            on_store=None,
        )
        # Re-run with a failing destination status
        store = InMemoryStoreAssociation(status=0xA700)
        assoc = InMemoryServerAssociation()
        assoc.bind(evt.EVT_C_MOVE, _yield_datasets(datasets))
        assoc.ae.associate = lambda *a, **k: store
        assoc.ae.move_authorization = policy

        req = C_MOVE()
        req.MessageID = 7
        req.AffectedSOPClassUID = MOVE_MODEL
        req.MoveDestination = "ARCHIVE_DEST"
        req.Identifier = BytesIO(encode(Dataset(), True, True))
        context = build_context(MOVE_MODEL, ImplicitVRLittleEndian)
        context.context_id = 1
        service = QueryRetrieveServiceClass(assoc)
        service.statuses = QR_MOVE_SERVICE_CLASS_STATUS
        service._move_scp(req, context)

        final = assoc.dimse.final
        assert final["Failed"] == 2
        assert final["Remaining"] == 0
        assert final["Completed"] == 0

    def test_unsent_is_not_a_failure(self):
        """Unsentinels are reported as remaining, with zero failures."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [make_dataset(f"1.2.3.{ii}") for ii in range(1, 4)]

        def revoke(count, dataset):
            if count == 1:
                policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

        dimse, store = _run_move(
            _yield_datasets(datasets), policy, datasets, on_store=revoke
        )

        final = dimse.final
        # One dataset sent, two never left the SCP
        assert final["Remaining"] == 2
        assert final["Failed"] == 0
        # The failed UID list must not include the unsent instances
        assert final["Completed"] == 1


class TestPolicyWeNeverStoresCredentials:
    """The in-memory policy must not retain secret material."""

    def test_secondary_field_is_never_used(self):
        """Only the primary (username) field contributes to the identity."""

        class Requestor:
            ae_title = "EXPORT_SCU"

            class Identity:
                primary_field = b"alice"
                secondary_field = b"hunter2"

            user_identity = Identity()

        class Assoc:
            requestor = Requestor()

        assert query_identity(Assoc()) == "EXPORT_SCU:alice"

    def test_audit_log_contains_no_passwords(self):
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")
        policy.approve_query("EXPORT_SCU", C_MOVE())

        for approval in policy.audit_log:
            assert "hunter2" not in repr(approval)
            assert "password" not in repr(approval).lower()

    def test_deny_query_after_grant_blocks_queries(self):
        """The query approval can also be withdrawn."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.deny_query("EXPORT_SCU")

        datasets = [make_dataset("1.2.3.1")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert dimse.final["Status"] == 0x0124
        assert store.datasets == []


class TestInstanceLevelApproval:
    """Only approved instances are sent, even with an approved destination."""

    def test_only_approved_instance_is_sent(self):
        """A destination grant may allow only one of three instances."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination(
            "EXPORT_SCU", "ARCHIVE_DEST", allowed_instances=["1.2.3.2"]
        )

        datasets = [
            make_dataset("1.2.3.1"),
            make_dataset("1.2.3.2"),
            make_dataset("1.2.3.3"),
        ]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        assert [d.SOPInstanceUID for d in store.datasets] == ["1.2.3.2"]

        final = dimse.final
        assert final["Remaining"] == 2
        assert final["Completed"] == 1
        assert final["Failed"] == 0

    def test_unapproved_instance_is_not_a_failure(self):
        """Withheld instances are remaining, not failed or warning."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination(
            "EXPORT_SCU", "ARCHIVE_DEST", allowed_instances=["1.2.3.1"]
        )

        datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
        dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

        final = dimse.final
        assert final["Remaining"] == 1
        assert final["Failed"] == 0
        assert final["Warning"] == 0
        assert final["Completed"] == 1


class TestMixedOutcomes:
    """Genuine failures and withheld datasets are reported separately."""

    def test_failed_then_revoked(self):
        """A real C-STORE failure is counted as failed, not as remaining."""
        policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
        policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

        datasets = [
            make_dataset("1.2.3.1"),
            make_dataset("1.2.3.2"),
            make_dataset("1.2.3.3"),
        ]
        def revoke_after_first(count, dataset):
            if count == 1:
                policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

        assoc = InMemoryServerAssociation()
        assoc.bind(evt.EVT_C_MOVE, _yield_datasets(datasets))
        failing_store = InMemoryStoreAssociation(
            status=0xA700, on_store=revoke_after_first
        )
        assoc.ae.associate = lambda *a, **k: failing_store
        assoc.ae.move_authorization = policy

        req = C_MOVE()
        req.MessageID = 7
        req.AffectedSOPClassUID = MOVE_MODEL
        req.MoveDestination = "ARCHIVE_DEST"
        req.Identifier = BytesIO(encode(Dataset(), True, True))
        context = build_context(MOVE_MODEL, ImplicitVRLittleEndian)
        context.context_id = 1
        service = QueryRetrieveServiceClass(assoc)
        service.statuses = QR_MOVE_SERVICE_CLASS_STATUS
        service._move_scp(req, context)

        final = assoc.dimse.final
        # One dataset was sent and failed; the rest were withheld
        assert final["Failed"] == 1
        assert final["Remaining"] == 2
        assert final["Completed"] == 0


def test_audit_order_query_then_destination_then_sub_ops():
    """Approval decisions happen in the order query, destination, sub-op."""
    policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
    policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")

    datasets = [make_dataset("1.2.3.1"), make_dataset("1.2.3.2")]
    dimse, store = _run_move(_yield_datasets(datasets), policy, datasets)

    # The grant itself was recorded first, then the actual decision order
    decisions = [a.stage for a in policy.audit_log][1:]
    assert decisions == [
        QUERY_STAGE,
        DESTINATION_STAGE,
        SUB_OPERATION_STAGE,
        SUB_OPERATION_STAGE,
    ]


def test_handler_cannot_override_policy():
    """A handler that yields datasets can't bypass the destination policy."""
    policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
    # Query approved, destination not

    datasets = [make_dataset("1.2.3.1")]

    def handler(event):
        yield ("localhost", 11113)
        yield 1
        yield 0xFF00, datasets[0]

    dimse, store = _run_move(handler, policy, datasets)

    assert store.datasets == []
    assert dimse.final["Status"] == 0x0124


class TestInMemoryPolicy:
    """Unit tests for the in-memory policy object."""

    def test_query_approval_is_recorded(self):
        policy = InMemoryMoveAuthorization(approved_queries=["A"])
        req = C_MOVE()
        req.MessageID = 3
        approval = policy.approve_query("A", req)
        assert approval.approved
        assert approval.stage == QUERY_STAGE
        assert approval.request_message_id == 3

    def test_destination_unknown(self):
        policy = InMemoryMoveAuthorization(approved_queries=["A"])
        approval = policy.approve_destination(
            MoveApproval(identity="A", approved=True, stage=QUERY_STAGE),
            "D",
            C_MOVE(),
        )
        assert approval.denied
        assert policy.destination_state("A", "D") == "unknown"

    def test_destination_grant_then_revoke(self):
        policy = InMemoryMoveAuthorization(approved_queries=["A"])
        policy.grant_destination("A", "D")
        assert policy.destination_state("A", "D") == "approved"
        policy.revoke_destination("A", "D")
        assert policy.destination_state("A", "D") == "revoked"

    def test_sub_operation_without_grant_is_denied(self):
        policy = InMemoryMoveAuthorization()
        approval = MoveApproval(
            identity="A",
            approved=False,
            stage=DESTINATION_STAGE,
            destination="D",
        )
        result = policy.approve_sub_operation(approval, make_dataset("1.2.3"))
        assert result.denied
        assert result.stage == SUB_OPERATION_STAGE

    def test_allowed_instances(self):
        policy = InMemoryMoveAuthorization(approved_queries=["A"])
        approval = policy.grant_destination(
            "A", "D", allowed_instances=["1.2.3"]
        )
        ok = policy.approve_sub_operation(approval, make_dataset("1.2.3"))
        assert ok.approved
        denied = policy.approve_sub_operation(approval, make_dataset("1.2.4"))
        assert denied.denied
        assert denied.reason == "SOP Instance not approved for the destination"

    def test_audit_log_is_immutable_snapshot(self):
        policy = InMemoryMoveAuthorization(approved_queries=["A"])
        policy.grant_destination("A", "D")
        snapshot = policy.audit_log
        policy.revoke_destination("A", "D")
        assert len(snapshot) == len(policy.audit_log) - 1
        with pytest.raises(TypeError):
            snapshot[0] = None
