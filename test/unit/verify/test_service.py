# Copyright 2026 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from pathlib import Path

import pretend
import pytest

from sigstore import dsse
from sigstore.errors import VerificationError
from sigstore.models import Bundle, TrustedRoot
from sigstore.verify.policy import UnsafeNoOp
from sigstore.verify.service import (
    BatchResult,
    ReadBudget,
    VerificationRequest,
    VerificationService,
    VerificationStatus,
)
from sigstore.verify.verifier import Verifier

# These bundles verify offline against the trusted root bundled in
# `test/assets/staging-tuf`.
_OFFLINE_BUNDLES = (
    ("bundle.txt", 109),
    ("bundle_v3.txt", 109),
    ("bundle_v3_alt.txt", 156),
)


@pytest.fixture
def offline_verifier(asset) -> Verifier:
    trusted_root = asset(
        "staging-tuf/targets/"
        "ed6a9cf4e7c2e3297a4b5974fce0d17132f03c63512029d7aa3a402b43acab49"
        ".trusted_root.json"
    )
    return Verifier(trusted_root=TrustedRoot.from_file(str(trusted_root)))


@pytest.fixture
def service(offline_verifier) -> VerificationService:
    return VerificationService(verifier=offline_verifier, policy=UnsafeNoOp())


def _request(asset, name: str) -> VerificationRequest:
    return VerificationRequest(
        name=name,
        artifact=asset(name),
        bundle=Bundle.from_json(asset(f"{name}.sigstore").read_bytes()),
    )


def _requests(asset) -> list[VerificationRequest]:
    return [_request(asset, name) for name, _ in _OFFLINE_BUNDLES]


class InterruptibleReader:
    """
    A binary stream double that can be stopped part-way through a read.

    `block_until` makes `read` block until the event is set, after returning
    at most `chunk_size` bytes. This models a slow artifact source that the
    service must be able to cancel without disturbing other requests.
    """

    def __init__(
        self,
        data: bytes,
        *,
        chunk_size: int,
        block_until: threading.Event | None = None,
        on_eof: Callable[[], None] | None = None,
    ) -> None:
        self._data = data
        self._chunk_size = chunk_size
        self._block_until = block_until
        self._on_eof = on_eof
        self._pos = 0
        self.closed = False
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self._block_until is not None and not self._block_until.is_set():
            self._block_until.wait(timeout=5)

        if size < 0:
            size = len(self._data) - self._pos
        size = min(size, self._chunk_size)
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        if not chunk and self._on_eof is not None:
            self._on_eof()
        return chunk

    def close(self) -> None:
        self.closed = True


def test_verifies_all_items(service, asset):
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=1024, batch=4096)
    )

    assert batch.complete
    assert len(batch.results) == len(_OFFLINE_BUNDLES)
    for item, (name, size) in zip(batch.results, _OFFLINE_BUNDLES, strict=True):
        assert item.name == name
        assert item.status is VerificationStatus.VERIFIED
        assert item.bytes_read == size
        assert item.digest is not None
        assert item.digest.digest == hashlib.sha256(
            asset(name).read_bytes()
        ).digest()
    assert batch.summary()["verified"] == tuple(name for name, _ in _OFFLINE_BUNDLES)


def test_results_are_in_request_order_despite_completion_order(service, asset):
    # The first request blocks until the other two have been fully read, so
    # the service observes completion in reverse order.
    release = threading.Event()
    fast_done = threading.Event()
    completed: list[str] = []
    lock = threading.Lock()

    def record(name: str) -> None:
        with lock:
            completed.append(name)

    delayed = InterruptibleReader(
        asset("bundle.txt").read_bytes(),
        chunk_size=7,
        block_until=release,
        on_eof=lambda: record("delayed"),
    )

    def fast_reader(name: str) -> InterruptibleReader:
        def done() -> None:
            record(name)
            if "bundle_v3.txt" in completed and "bundle_v3_alt.txt" in completed:
                fast_done.set()

        return InterruptibleReader(
            asset(name).read_bytes(),
            chunk_size=len(asset(name).read_bytes()),
            on_eof=done,
        )

    requests = [
        VerificationRequest(
            name="delayed",
            artifact=delayed,
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
        ),
        VerificationRequest(
            name="bundle_v3.txt",
            artifact=fast_reader("bundle_v3.txt"),
            bundle=Bundle.from_json(asset("bundle_v3.txt.sigstore").read_bytes()),
        ),
        VerificationRequest(
            name="bundle_v3_alt.txt",
            artifact=fast_reader("bundle_v3_alt.txt"),
            bundle=Bundle.from_json(asset("bundle_v3_alt.txt.sigstore").read_bytes()),
        ),
    ]

    result_box: list[BatchResult] = []

    def run() -> None:
        result_box.append(
            service.verify_batch(requests, budget=ReadBudget(per_item=1024, batch=4096))
        )

    thread = threading.Thread(target=run)
    thread.start()
    assert fast_done.wait(timeout=5), "fast readers did not complete"
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()

    # The two fast items really did finish first.
    assert completed[:2] == ["bundle_v3.txt", "bundle_v3_alt.txt"]
    assert completed[-1] == "delayed"

    batch = result_box[0]
    assert [item.name for item in batch.results] == [
        "delayed",
        "bundle_v3.txt",
        "bundle_v3_alt.txt",
    ]
    assert all(item.verified for item in batch.results)

    # Each digest belongs to its own item, not to whichever read finished first.
    for item, name in zip(
        batch.results, ("bundle.txt", "bundle_v3.txt", "bundle_v3_alt.txt"), strict=True
    ):
        assert item.digest is not None
        assert item.digest.digest == hashlib.sha256(asset(name).read_bytes()).digest()


def test_per_item_budget_is_reported(service, asset):
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=100, batch=4096)
    )

    assert [item.status for item in batch.results] == [
        VerificationStatus.BUDGET_EXCEEDED,
        VerificationStatus.BUDGET_EXCEEDED,
        VerificationStatus.BUDGET_EXCEEDED,
    ]
    for item in batch.results:
        assert item.bytes_read == 100
        assert item.digest is None
    assert batch.summary()["budget_exceeded"] == (
        "bundle.txt",
        "bundle_v3.txt",
        "bundle_v3_alt.txt",
    )


def test_per_item_budget_allows_inputs_read_through_eof(service, asset):
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=109, batch=4096)
    )

    assert batch.results[0].status is VerificationStatus.VERIFIED
    assert batch.results[1].status is VerificationStatus.VERIFIED
    # `bundle_v3_alt.txt` is 156 bytes, so exactly 109 is not enough.
    assert batch.results[2].status is VerificationStatus.BUDGET_EXCEEDED


def test_batch_budget_that_covers_every_item(service, asset):
    total = sum(size for _, size in _OFFLINE_BUNDLES)
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=None, batch=total)
    )

    assert batch.complete
    assert batch.bytes_read == total


def test_batch_budget_exhaustion_leaves_completed_items_verified(
    offline_verifier, asset
):
    # A single worker makes the allocation deterministic: room for the two
    # 109-byte artifacts, but not the 156-byte one.
    service = VerificationService(
        verifier=offline_verifier, policy=UnsafeNoOp(), max_workers=1
    )
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=None, batch=300)
    )

    by_name = {item.name: item for item in batch.results}
    assert by_name["bundle.txt"].status is VerificationStatus.VERIFIED
    assert by_name["bundle_v3.txt"].status is VerificationStatus.VERIFIED
    assert by_name["bundle_v3_alt.txt"].status is VerificationStatus.BUDGET_EXCEEDED
    assert by_name["bundle_v3_alt.txt"].bytes_read == 82
    assert by_name["bundle_v3_alt.txt"].digest is None
    assert len(batch.verified) == 2
    assert [item.name for item in batch.verified] == ["bundle.txt", "bundle_v3.txt"]


def test_batch_budget_is_never_overspent_under_contention(service, asset):
    # With concurrent readers the allocation order is unspecified, but no
    # input may push the batch past its budget and truncated inputs must not
    # produce a digest.
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=None, batch=300)
    )

    assert batch.bytes_read <= 300
    # The pool hands out remaining budget fairly, so all three inputs make
    # progress and the one that cannot finish is reported as truncated rather
    # than left at zero bytes.
    assert all(item.bytes_read > 0 for item in batch.results)
    assert len(batch.verified) >= 1
    truncated = [item for item in batch.unfinished if item.digest is None]
    assert truncated
    assert all(
        item.status is VerificationStatus.BUDGET_EXCEEDED for item in truncated
    )
    for item in batch.verified:
        assert item.digest is not None


def test_cancelling_one_item_does_not_discard_completed_verifications(
    service, asset
):
    cancel = threading.Event()
    blocked = InterruptibleReader(asset("bundle.txt").read_bytes(), chunk_size=1)
    requests = [
        VerificationRequest(
            name="cancelled",
            artifact=blocked,
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
            cancel=cancel,
        ),
        _request(asset, "bundle_v3.txt"),
    ]

    # Cancel before the batch starts, so the cancelled item never reads.
    cancel.set()
    batch = service.verify_batch(
        requests, budget=ReadBudget(per_item=1024, batch=4096)
    )

    assert [item.status for item in batch.results] == [
        VerificationStatus.CANCELLED,
        VerificationStatus.VERIFIED,
    ]
    assert batch.results[0].bytes_read == 0
    assert batch.results[0].digest is None
    assert batch.results[1].digest is not None
    assert batch.summary()["cancelled"] == ("cancelled",)
    assert batch.summary()["verified"] == ("bundle_v3.txt",)


def test_cancelled_after_full_read_keeps_digest_but_not_verified(service, asset):
    # The reader is fully consumed, then the token is set before verification.
    data = asset("bundle.txt").read_bytes()
    cancel = threading.Event()

    class CancelAfterRead(InterruptibleReader):
        def read(self, size: int = -1) -> bytes:
            chunk = super().read(size)
            if not chunk:
                cancel.set()
            return chunk

    batch = service.verify_batch(
        [
            VerificationRequest(
                name="late-cancel",
                artifact=CancelAfterRead(data, chunk_size=len(data)),
                bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
                cancel=cancel,
            )
        ]
    )

    item = batch.results[0]
    assert item.status is VerificationStatus.CANCELLED
    assert item.bytes_read == len(data)
    assert item.digest is not None
    assert item.digest.digest == hashlib.sha256(data).digest()


def test_cancelling_inflight_item_keeps_sibling_verifications(service, asset):
    # Two fast items complete, then the slow item is cancelled mid-read. Its
    # cancellation and the eventual truncated read must not remove the already
    # verified results.
    cancel = threading.Event()
    release = threading.Event()
    fast_done = threading.Event()
    completed: list[str] = []

    def record(name: str) -> None:
        completed.append(name)
        if "bundle_v3.txt" in completed and "bundle_v3_alt.txt" in completed:
            fast_done.set()

    def fast(name: str) -> InterruptibleReader:
        data = asset(name).read_bytes()
        return InterruptibleReader(
            data, chunk_size=len(data), on_eof=lambda: record(name)
        )

    slow = InterruptibleReader(
        asset("bundle.txt").read_bytes(), chunk_size=1, block_until=release
    )
    requests = [
        VerificationRequest(
            name="slow",
            artifact=slow,
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
            cancel=cancel,
        ),
        VerificationRequest(
            name="bundle_v3.txt",
            artifact=fast("bundle_v3.txt"),
            bundle=Bundle.from_json(asset("bundle_v3.txt.sigstore").read_bytes()),
        ),
        VerificationRequest(
            name="bundle_v3_alt.txt",
            artifact=fast("bundle_v3_alt.txt"),
            bundle=Bundle.from_json(asset("bundle_v3_alt.txt.sigstore").read_bytes()),
        ),
    ]

    result_box: list[BatchResult] = []

    def run() -> None:
        result_box.append(service.verify_batch(requests))

    thread = threading.Thread(target=run)
    thread.start()
    assert fast_done.wait(timeout=5), "fast readers did not complete"

    # Stop only the slow request while it is blocked in `read`.
    cancel.set()
    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()

    batch = result_box[0]
    by_name = {item.name: item for item in batch.results}
    assert by_name["slow"].status is VerificationStatus.CANCELLED
    assert by_name["slow"].digest is None
    assert by_name["bundle_v3.txt"].status is VerificationStatus.VERIFIED
    assert by_name["bundle_v3_alt.txt"].status is VerificationStatus.VERIFIED
    assert len(batch.verified) == 2


def test_batch_cancel_does_not_discard_sibling_results(service, asset):
    cancel = threading.Event()
    requests = _requests(asset)
    # Cancel only the third request, then run the whole batch.
    requests[2] = VerificationRequest(
        name=requests[2].name,
        artifact=requests[2].artifact,
        bundle=requests[2].bundle,
        cancel=cancel,
    )
    cancel.set()

    batch = service.verify_batch(requests)
    assert [item.status for item in batch.results] == [
        VerificationStatus.VERIFIED,
        VerificationStatus.VERIFIED,
        VerificationStatus.CANCELLED,
    ]


def test_bad_stream_is_an_error_without_a_digest(service, asset):
    broken = pretend.stub(read=pretend.raiser(OSError("boom")))
    batch = service.verify_batch(
        [
            VerificationRequest(
                name="broken",
                artifact=broken,
                bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
            ),
            _request(asset, "bundle_v3.txt"),
        ]
    )

    assert batch.results[0].status is VerificationStatus.ERROR
    assert batch.results[0].digest is None
    assert "boom" in (batch.results[0].message or "")
    assert batch.results[1].status is VerificationStatus.VERIFIED


def test_rejected_bundle_keeps_digest_of_complete_input(service, asset):
    bad_bundle = Bundle.from_json(asset("bundle.txt.sigstore").read_bytes())
    signature = bad_bundle._inner.message_signature
    assert signature is not None and signature.message_digest is not None
    signature.message_digest.digest = b""

    item = service.verify_item(
        VerificationRequest(
            name="mismatch",
            artifact=asset("bundle.txt"),
            bundle=bad_bundle,
        )
    )

    assert item.status is VerificationStatus.REJECTED
    assert item.digest is not None
    assert "digest mismatch" in (item.message or "")


def test_policy_failure_is_rejected(asset, offline_verifier):
    service = VerificationService(
        verifier=offline_verifier,
        policy=pretend.stub(
            verify=pretend.raiser(VerificationError("policy failed"))
        ),
    )

    item = service.verify_item(_request(asset, "bundle.txt"))

    assert item.status is VerificationStatus.REJECTED
    assert item.message == "policy failed"
    assert item.digest is not None


def test_results_serialize_for_backend_responses(service, asset):
    batch = service.verify_batch(
        _requests(asset), budget=ReadBudget(per_item=100, batch=4096)
    )
    payload = batch.to_dict()

    # The projection survives a JSON round-trip, which is what a backend
    # response will actually go through.
    assert json.loads(json.dumps(payload)) == payload
    assert payload["complete"] is False
    assert payload["bytes_read"] == 300
    assert payload["summary"]["budget_exceeded"] == [
        "bundle.txt",
        "bundle_v3.txt",
        "bundle_v3_alt.txt",
    ]
    first = payload["results"][0]
    assert first["name"] == "bundle.txt"
    assert first["status"] == "budget_exceeded"
    assert first["verified"] is False
    assert first["bytes_read"] == 100
    assert first["digest"] is None


def test_empty_batch(service):
    batch = service.verify_batch([])
    assert batch.results == ()
    assert batch.complete
    assert batch.bytes_read == 0
    assert batch.summary() == {status.value: () for status in VerificationStatus}


def test_verify_item_call_level_cancel(service, asset):
    cancel = threading.Event()
    cancel.set()

    item = service.verify_item(_request(asset, "bundle.txt"), cancel=cancel)

    assert item.status is VerificationStatus.CANCELLED
    assert item.bytes_read == 0
    assert item.digest is None


def test_verify_item_success(service, asset):
    item = service.verify_item(
        _request(asset, "bundle.txt"), budget=ReadBudget(per_item=1024)
    )

    assert item.status is VerificationStatus.VERIFIED
    assert item.index == 0
    assert item.name == "bundle.txt"
    assert item.bytes_read == 109


def test_unopenable_artifact_is_an_error(service, asset, tmp_path):
    item = service.verify_item(
        VerificationRequest(
            name="missing",
            artifact=tmp_path / "does-not-exist",
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
        )
    )

    assert item.status is VerificationStatus.ERROR
    assert "failed to open artifact" in (item.message or "")
    assert item.digest is None


def test_stream_ownership_is_left_to_the_caller(service, asset):
    stream = InterruptibleReader(asset("bundle.txt").read_bytes(), chunk_size=16)
    item = service.verify_item(
        VerificationRequest(
            name="stream",
            artifact=stream,
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
        )
    )

    assert item.status is VerificationStatus.VERIFIED
    assert not stream.closed


def test_path_input_is_closed(service, asset, monkeypatch):
    path = asset("bundle.txt")
    real_open = Path.open
    opened: list[object] = []

    def tracking_open(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        opened.append(handle)
        return handle

    monkeypatch.setattr(Path, "open", tracking_open)
    item = service.verify_item(
        VerificationRequest(
            name="path",
            artifact=path,
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
        )
    )

    assert item.status is VerificationStatus.VERIFIED
    assert opened and opened[0].closed  # type: ignore[attr-defined]


@pytest.mark.parametrize("budget", [-1, -100])
def test_negative_budgets_rejected(budget):
    with pytest.raises(ValueError, match="non-negative"):
        ReadBudget(per_item=budget)
    with pytest.raises(ValueError, match="non-negative"):
        ReadBudget(batch=budget)


def test_invalid_worker_count(offline_verifier):
    with pytest.raises(ValueError, match="max_workers"):
        VerificationService(
            verifier=offline_verifier, policy=UnsafeNoOp(), max_workers=0
        )


def test_dsse_statement_must_match_input_digest(asset, monkeypatch):
    statement = (
        dsse.StatementBuilder()
        .subjects([dsse.Subject(name="other", digest={"sha256": "00" * 32})])
        .predicate_type("https://cosign.sigstore.dev/attestation/v1")
        .predicate({})
        .build()
    )
    fake_verifier = pretend.stub(
        verify_dsse=lambda **kwargs: (dsse.Envelope._TYPE, statement._contents)
    )
    service = VerificationService(verifier=fake_verifier, policy=UnsafeNoOp())
    monkeypatch.setattr(
        Bundle, "_dsse_envelope", property(lambda self: pretend.stub())
    )

    item = service.verify_item(
        VerificationRequest(
            name="dsse",
            artifact=b"artifact",
            bundle=Bundle.from_json(asset("bundle.txt.sigstore").read_bytes()),
        )
    )

    assert item.status is VerificationStatus.REJECTED
    assert "no subject for digest" in (item.message or "")
    assert item.digest is not None
