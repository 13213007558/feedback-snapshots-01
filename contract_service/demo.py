"""
End-to-end demonstration of the strict contract merge service.

Run:  .venv/bin/python contract_service/demo.py
"""

import shutil
import tempfile
from pathlib import Path

from pypdf import PdfReader
from pypdf.constants import UserAccessPermissions

from contract_service.make_fixtures import build_fixtures
from contract_service.service import (
    AuthorizationError,
    OutputPolicy,
    authorize,
    merge_contracts,
)

# The merged output opens under its OWN policy, unrelated to the inputs.
OUTPUT_POLICY = OutputPolicy(
    user_password="merged-view-pass",
    owner_password="merged-owner-pass",
    permissions=UserAccessPermissions.PRINT | UserAccessPermissions.EXTRACT,
    algorithm="AES-256",
)


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="contract-service-"))
    try:
        fixtures = build_fixtures(workdir / "fixtures")
        out = workdir / "out"
        out.mkdir()

        print("== Scenario 1: two merge-authorized contracts -> new encrypted file")
        # contract_b's USER password cannot merge, so here it is presented
        # with its OWNER password, which grants full control.
        receipt = merge_contracts(
            [
                (fixtures["contract_a"], "view-a-pass"),    # user password is enough
                (fixtures["contract_b"], "owner-b-pass"),   # needs owner password
            ],
            out / "merged_contract.pdf",
            OUTPUT_POLICY,
        )
        for grant in receipt.grants:
            print(f"  authorized: {Path(grant.path).name} "
                  f"({grant.password_type} password) - {grant.reason}")
        print(f"  merged sources : {[Path(s).name for s in receipt.merged_sources]}")
        print(f"  pages per input: { {Path(k).name: v for k, v in receipt.page_counts.items()} }")
        print(f"  total pages    : {receipt.total_pages}")
        print(f"  output         : {receipt.output_path}")
        print(f"  output opens with user password: {receipt.output_user_password!r}")
        granted = sorted(k for k, v in receipt.output_permissions.items()
                         if v and not k.startswith("R"))
        print(f"  output permissions granted     : {granted}")

        check = PdfReader(receipt.output_path)
        check.decrypt("merged-view-pass")
        assert len(check.pages) == receipt.total_pages
        print(f"  verified: output decrypts with its own user password, "
              f"{len(check.pages)} pages")

        print()
        print("== Scenario 2: contract_b with only its USER password "
              "(opens, but merge not granted)")
        target = out / "should_not_exist.pdf"
        try:
            merge_contracts(
                [
                    (fixtures["contract_a"], "view-a-pass"),
                    (fixtures["contract_b"], "view-b-pass"),  # view-only permissions
                ],
                target,
                OUTPUT_POLICY,
            )
        except AuthorizationError as exc:
            print(f"  stopped BEFORE writing: {exc}")
        print(f"  output file exists afterwards: {target.exists()}  <- must be False")
        assert not target.exists()

        print()
        print("== Scenario 3: same encrypted blank template, two roles")
        template = fixtures["blank_template"]
        _, grant = authorize(template, "template-view-pass", purpose="view")
        print(f"  view   with user  password: GRANTED ({grant.reason})")
        try:
            authorize(template, "template-view-pass", purpose="merge")
        except AuthorizationError as exc:
            print(f"  export with user  password: DENIED  ({exc})")
        _, grant = authorize(template, "template-owner-pass", purpose="merge")
        print(f"  export with owner password: GRANTED ({grant.reason})")

        print()
        print("All scenarios behaved as required.")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
