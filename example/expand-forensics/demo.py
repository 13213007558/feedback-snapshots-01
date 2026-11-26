"""
Run the Expand forensics workflow against the local in-memory stub twice,
once per response ordering, then verify that:

* the two shareable reports are directly comparable (identical after the
  generation timestamp is ignored);
* overlapping relationships keep the same evidence ids and public ids;
* the evidence-free branch is marked unconfirmed in both;
* no internal account id appears in either public report;
* the raw Expand response and subject mapping are retained internally.
"""

import asyncio
import json

from pathlib import Path

from local_fga_stub import (
    DOCUMENT,
    MODEL_ID,
    UNCONFIRMED_USER,
    LocalFgaStub,
    display_name_resolver,
)

from openfga_sdk.forensics import ExpandEvidenceCollector
from openfga_sdk.forensics.identifiers import public_identifier
from openfga_sdk.models.expand_request import ExpandRequest
from openfga_sdk.models.expand_request_tuple_key import ExpandRequestTupleKey


OUTPUT_DIR = Path(__file__).parent / "out"
SALT = "deal-memo-incident-2026-11"


def build_request() -> ExpandRequest:
    return ExpandRequest(
        tuple_key=ExpandRequestTupleKey(relation="viewer", object=DOCUMENT),
        authorization_model_id=MODEL_ID,
    )


async def export(order: str, generated_at) -> dict:
    stub = LocalFgaStub(order=order)
    collector = ExpandEvidenceCollector(
        stub,
        internal_types=("user", "employee"),
        salt=SALT,
        display_name_resolver=display_name_resolver,
    )
    investigation = await collector.collect(build_request(), generated_at=generated_at)

    OUTPUT_DIR.mkdir(exist_ok=True)
    stem = Path(OUTPUT_DIR / f"report_{order}")
    stem.with_suffix(".json").write_text(
        json.dumps(investigation.public_report(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    stem.with_name(f"internal_{order}.json").write_text(
        json.dumps(
            {
                "raw_expand": investigation.raw_expand,
                "raw_evidence": investigation.raw_evidence,
                "subject_mapping": investigation.subject_mapping,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "order": order,
        "investigation": investigation,
        "report": investigation.public_report(),
    }


def comparable(report: dict) -> dict:
    clone = dict(report)
    clone.pop("generated_at", None)
    return clone


def assert_no_internal_ids(report: dict) -> None:
    text = json.dumps(report, ensure_ascii=False)
    for internal in (
        "alice@internal.example.com",
        "bob@internal.example.com",
        "jordan.li@internal.example.com",
        "carol.temp@internal.example.com",
    ):
        assert internal not in text, f"internal id leaked: {internal}"


async def main() -> None:
    from datetime import datetime, timezone

    fixed_time = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)
    forward = await export("forward", fixed_time)
    reversed_export = await export("reversed", fixed_time)

    report_a = forward["report"]
    report_b = reversed_export["report"]

    assert comparable(report_a) == comparable(
        report_b
    ), "reports differ despite identical underlying data"

    assert_no_internal_ids(report_a)
    assert_no_internal_ids(report_b)

    # The shared internal account (alice) appears in viewer, the group
    # membership and the editor chain, yet always maps to one public id.
    alice_public = public_identifier("user:alice@internal.example.com", salt=SALT)
    subject_ids = {subject["public_subject_id"] for subject in report_a["subjects"]}
    assert alice_public in subject_ids

    # Two distinct subjects share one display name; they must not be merged.
    jordan_collisions = [
        collision
        for collision in report_a["display_name_collisions"]
        if collision["display_name"] == "Jordan Lee"
    ]
    assert jordan_collisions and len(jordan_collisions[0]["public_subject_ids"]) == 2

    unconfirmed = report_a["unconfirmed_branches"]
    assert any(
        branch["reason"] == "missing_relationship_evidence"
        and branch["expected_relation"]["relation"] == "temp_contractor"
        and branch["expected_relation"]["users"]
        == [
            public_identifier(UNCONFIRMED_USER, salt=SALT),
        ]
        for branch in unconfirmed
    ), "evidence-free branch was not flagged"
    assert report_b["unconfirmed_branches"] == unconfirmed

    evidence_ids_a = [item["evidence_id"] for item in report_a["evidence"]]
    evidence_ids_b = [item["evidence_id"] for item in report_b["evidence"]]
    assert evidence_ids_a == evidence_ids_b

    # Internal review artifacts still expose the raw Expand tree.
    internal_a = forward["investigation"]
    assert internal_a.raw_expand["tree"]["root"]["name"] == f"{DOCUMENT}#viewer"
    assert "user:alice@internal.example.com" in internal_a.subject_mapping

    print("orders compared:", forward["order"], reversed_export["order"])
    print("report id:", report_a["report_id"])
    print("evidence records:", report_a["summary"]["evidence_records"])
    print("subjects:", report_a["summary"]["subject_count"])
    print("unconfirmed branches:", report_a["summary"]["unconfirmed_branch_count"])
    print(
        "display name collisions:", report_a["summary"]["display_name_collision_count"]
    )
    print("reports identical ignoring generated_at: True")
    print("outputs written under:", OUTPUT_DIR)


if __name__ == "__main__":
    asyncio.run(main())
