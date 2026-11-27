from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING
from zipfile import ZIP_DEFLATED, ZipFile

if TYPE_CHECKING:
    from tox.pytest import ToxProjectCreator


WHEEL_NAME = "approved_demo-1.0-py3-none-any.whl"


def _write_distinguishable_wheel(path: Path, variant: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    dist_info = "approved_demo-1.0.dist-info"
    files = {
        "approved_demo/__init__.py": (
            f"VARIANT = {variant!r}\n"
            "def main() -> None:\n"
            '    print(f"APPROVED_VARIANT={VARIANT}")\n'
        ),
        f"{dist_info}/METADATA": "Metadata-Version: 2.1\nName: approved-demo\nVersion: 1.0\n",
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    record_name = f"{dist_info}/RECORD"
    record_lines = []
    for name, content in files.items():
        body = content.encode()
        digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
        record_lines.append(f"{name},sha256={digest},{len(body)}")
    record_lines.append(f"{record_name},,")
    files[record_name] = "\n".join(record_lines) + "\n"
    with ZipFile(path, "w", ZIP_DEFLATED) as wheel:
        for name, content in files.items():
            wheel.writestr(name, content)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_project(project_path: Path) -> dict[str, str]:
    hashes = {
        "a": _write_distinguishable_wheel(project_path / "wheels" / "a" / WHEEL_NAME, "A"),
        "b": _write_distinguishable_wheel(project_path / "wheels" / "b" / WHEEL_NAME, "B"),
    }

    requirements = project_path / "requirements"
    nested = requirements / "nested"
    nested.mkdir(parents=True)
    for variant in ("a", "b"):
        (requirements / f"root-{variant}.txt").write_text(f"-r nested/inner-{variant}.txt\n")
        (nested / f"inner-{variant}.txt").write_text(
            f"{project_path / 'wheels' / variant / WHEEL_NAME}\n",
        )
    (project_path / "constraints.txt").write_text("approved-demo==1.0\n")

    for variant, digest in hashes.items():
        (project_path / f"pylock-{variant}.toml").write_text(
            f"""
lock-version = "1.0"
created-by = "approval-test"

[[packages]]
name = "approved-demo"
version = "1.0"

[[packages.wheels]]
path = "wheels/{variant}/{WHEEL_NAME}"

[packages.wheels.hashes]
sha256 = "{digest}"
""".strip()
            + "\n",
        )

    policy = {
        "schema_version": 1,
        "approvals": [
            {
                "id": f"allow-{variant}",
                "name": "approved-demo",
                "version": "1.0",
                "path": f"wheels/{variant}/{WHEEL_NAME}",
                "sha256": digest,
                "status": "approved",
            }
            for variant, digest in hashes.items()
        ],
    }
    (project_path / "approvals.json").write_text(json.dumps(policy, indent=2))

    (project_path / "pip_double.py").write_text(
        """
import json
import os
import runpy
import sys
from pathlib import Path

record = Path(os.environ["PIP_APPROVAL_RECORD"])
with record.open("a", encoding="utf-8") as handler:
    handler.write(json.dumps({"pip_argv": ["install", *sys.argv[1:]]}) + "\\n")
sys.argv = ["pip", "install", *sys.argv[1:]]
runpy.run_module("pip", run_name="__main__")
""".strip()
        + "\n",
    )

    (project_path / "tox.ini").write_text(
        """
[tox]
env_list = reqa,reqb,locka,lockb

[testenv]
skip_install = true
constraints = constraints.txt
artifact_approvals = approvals.json
install_command = python {toxinidir}/pip_double.py {packages}
set_env =
    PIP_APPROVAL_RECORD = {toxinidir}/pip-calls.jsonl
commands = python -c "import approved_demo; approved_demo.main()"

[testenv:reqa]
deps = -r requirements/root-a.txt

[testenv:reqb]
deps = -r requirements/root-b.txt

[testenv:locka]
pylock = pylock-a.toml
set_env =
    PIP_APPROVAL_RECORD = {toxinidir}/pip-calls.jsonl
    PIP_FIND_LINKS = {toxinidir}/wheels/a
    PIP_NO_INDEX = 1

[testenv:lockb]
pylock = pylock-b.toml
set_env =
    PIP_APPROVAL_RECORD = {toxinidir}/pip-calls.jsonl
    PIP_FIND_LINKS = {toxinidir}/wheels/b
    PIP_NO_INDEX = 1
""".strip()
        + "\n",
    )
    return hashes


def _pip_calls(project_path: Path) -> list[dict[str, list[str]]]:
    record = project_path / "pip-calls.jsonl"
    if not record.exists():
        return []
    return [json.loads(line) for line in record.read_text().splitlines() if line]


def test_artifact_approval_survives_requirements_pylock_cache_and_revocation(
    tox_project: ToxProjectCreator,
) -> None:
    project = tox_project({})
    hashes = _write_project(project.path)

    first = project.run("r")
    first.assert_success()
    assert first.out.count("APPROVED_VARIANT=A") >= 2
    assert first.out.count("APPROVED_VARIANT=B") >= 2

    calls = _pip_calls(project.path)
    assert len(calls) == 4
    assert any(
        "install" in call["pip_argv"]
        and any(arg.endswith("root-a.txt") for arg in call["pip_argv"])
        for call in calls
    )
    assert any(
        "install" in call["pip_argv"]
        and "--no-deps" in call["pip_argv"]
        and any(arg.endswith("pylock.txt") for arg in call["pip_argv"])
        for call in calls
    )

    cached = project.run("r")
    cached.assert_success()
    assert _pip_calls(project.path) == calls

    policy_path = project.path / "approvals.json"
    policy = json.loads(policy_path.read_text())
    for approval in policy["approvals"]:
        if approval["id"] == "allow-a":
            approval["status"] = "revoked"
            approval["reason"] = "test revocation"
    policy_path.write_text(json.dumps(policy))

    revoked = project.run("r")
    revoked.assert_failed()
    assert "dependency artifact approval failed for PythonRun.deps" in revoked.out
    assert "dependency artifact approval failed for PythonRun.pylock" in revoked.out
    assert "[revoked]" in revoked.out
    assert hashes["a"] in revoked.out
    assert "test revocation" in revoked.out
    assert "APPROVED_VARIANT=B" in revoked.out
    assert "APPROVED_VARIANT=A" not in revoked.out

    # Revocation is checked from the current policy even though both environments already have install caches.
    assert _pip_calls(project.path) == calls

    allowed_check = project.run("approvals", "-e", "reqb,lockb")
    allowed_check.assert_success()
    assert "reqb: approved" in allowed_check.out
    assert "lockb: approved" in allowed_check.out

    revoked_check = project.run("approvals", "-e", "reqa,locka")
    revoked_check.assert_failed()
    assert revoked_check.out.count("[revoked]") >= 2

    req_receipt = json.loads((project.path / ".tox" / "reqa" / "approvals" / "PythonRun.deps.json").read_text())
    lock_receipt = json.loads((project.path / ".tox" / "locka" / "approvals" / "PythonRun.pylock.json").read_text())
    assert req_receipt["approved"] is False
    assert lock_receipt["approved"] is False
    assert req_receipt["decisions"][0]["status"] == "revoked"
    assert lock_receipt["decisions"][0]["status"] == "revoked"
    assert req_receipt["digest"] != lock_receipt["digest"]
