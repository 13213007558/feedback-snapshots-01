"""Create the protected sample documents used by the demo and tests."""

from pathlib import Path

from pypdf import PdfWriter
from pypdf.constants import UserAccessPermissions

VIEW_ONLY = UserAccessPermissions.PRINT  # open + print, nothing else
MERGEABLE = (
    UserAccessPermissions.PRINT
    | UserAccessPermissions.EXTRACT
    | UserAccessPermissions.ASSEMBLE_DOC
)


def _write_encrypted(path: Path, pages: int, user: str, owner: str,
                     permissions: UserAccessPermissions) -> None:
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=595, height=842)  # A4
    writer.encrypt(
        user_password=user,
        owner_password=owner,
        permissions_flag=permissions,
        algorithm="AES-256",
    )
    with open(path, "wb") as fh:
        writer.write(fh)


def build_fixtures(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        # Opens with its user password AND grants merge permissions.
        "contract_a": directory / "contract_a.pdf",
        # Opens with its user password but does NOT grant merge permissions.
        "contract_b": directory / "contract_b.pdf",
        # The local encrypted blank template, used in two roles below.
        "blank_template": directory / "blank_template.pdf",
    }
    _write_encrypted(paths["contract_a"], 2, "view-a-pass", "owner-a-pass", MERGEABLE)
    _write_encrypted(paths["contract_b"], 3, "view-b-pass", "owner-b-pass", VIEW_ONLY)
    _write_encrypted(paths["blank_template"], 1, "template-view-pass",
                     "template-owner-pass", VIEW_ONLY)
    return paths


if __name__ == "__main__":
    build_fixtures(Path(__file__).parent / "fixtures")
    print("fixtures written to", Path(__file__).parent / "fixtures")
