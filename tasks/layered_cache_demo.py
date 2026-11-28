#!/usr/bin/env python3
"""Demonstrate a read-only shared virtualenv cache with a private per-project staging folder.

Scenario (mirrors a build machine handing the same pre-filled cache to several projects):

1. Warm a shared app-data cache with the pip image, then freeze it read-only.
2. Run two local sessions concurrently, each in its own project: pip is served straight from the shared
   read-only cache, while the missing setuptools seed is generated inside that project's private staging
   folder. The shared tree is never written to.
3. Inject a mid-build failure in a third session and prove its staging directory is reclaimed.
4. Simulate a process killed mid-build and show the audit that detects the orphaned staging directory,
   then reap it.

Everything is created under one working directory (default: a fresh temp dir) and nothing is written outside
the private staging paths. Run with the project interpreter, e.g. ``python tasks/layered_cache_demo.py``.
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from virtualenv import cli_run
from virtualenv.app_data.layered_run import cli_run_layered
from virtualenv.seed.wheels.embed import get_embed_wheel

PY = f"{sys.version_info.major}.{sys.version_info.minor}"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def heading(text: str) -> None:
    print(f"\n{BOLD}=== {text} ==={RESET}")


def freeze_read_only(folder: Path) -> None:
    for root, dirs, files in os.walk(folder):
        for name in files + dirs:
            target = os.path.join(root, name)
            os.chmod(target, 0o555 if os.path.isdir(target) else 0o444)
    os.chmod(folder, 0o555)


def snapshot(folder: Path) -> set[str]:
    return {str(p.relative_to(folder)) for p in folder.rglob("*")}


def find_orphaned_staging(private_stage: Path) -> list[Path]:
    """Staging directories a killed/failed image build could leave (prefix mirrors PipInstall.build_image)."""
    return sorted(p for p in private_stage.rglob("CopyPipInstall-*") if p.is_dir())


def _session_worker(shared: str, stage: str, dest: str, index: str, fail: str) -> None:
    args = [
        dest,
        "--setuptools",
        "bundle",
        "--extra-search-dir",
        index,
        "--no-periodic-update",
        "--no-download",
        "--activators",
        "",
    ]
    if fail:
        # failure injection hook used by the failure-recovery phase; a non-zero exit is enough for the demo,
        # so swallow the expected traceback instead of letting the spawned process dump it
        os.environ["VIRTUALENV_LAYERED_FAIL_IMAGE"] = fail
        try:
            cli_run_layered(shared, stage, args)
        except RuntimeError as error:
            print(f"expected failure injected: {error.args[0].splitlines()[0]}")
            sys.exit(1)
        return
    cli_run_layered(shared, stage, args)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="layered-cache-demo-"))
    print(f"{BOLD}workdir:{RESET} {work}")
    shared = work / "shared-cache"
    index = work / "private-index"
    projects = work / "projects"

    heading("1. Warm shared cache (pip image only) and freeze it read-only")
    cli_run(
        [str(work / "warmer"), "--app-data", str(shared),
         "--no-periodic-update", "--no-setuptools", "--activators", ""]
    )
    freeze_read_only(shared)
    before = snapshot(shared)
    print(f"shared cache frozen at {shared}")
    print(f"  seed image(s) pre-baked: "
          f"{sorted(p.name for p in (shared / 'wheel' / PY / 'image' / '1' / 'CopyPipInstall').iterdir())}")

    heading("2. Stage the missing seed in a private index (setuptools)")
    index.mkdir(parents=True)
    wheel = get_embed_wheel("setuptools", PY)
    shutil.copy2(wheel.path, index / wheel.path.name)
    print(f"private index wheel: {wheel.path.name}")

    heading("3. Two local sessions interleave (shared pip hit + private setuptools build)")
    ctx = multiprocessing.get_context("spawn")
    procs = []
    for name in ("project-a", "project-b"):
        project = projects / name
        proc = ctx.Process(
            target=_session_worker,
            args=(str(shared), str(project / "stage"), str(project / "env"), str(index), ""),
        )
        procs.append((name, proc))
        proc.start()
    for name, proc in procs:
        proc.join()
        status = GREEN + "ok" + RESET if proc.exitcode == 0 else RED + f"exit {proc.exitcode}" + RESET
        print(f"  session {name}: {status}")

    heading("4. What was READ from the shared directory (still read-only, unchanged)")
    after = snapshot(shared)
    print(f"  shared tree unchanged: {GREEN + 'yes' + RESET if after == before else RED + 'NO' + RESET}")
    print(f"  shared dir writable: {RED + 'yes (BAD)' + RESET if os.access(shared, os.W_OK) else GREEN + 'no' + RESET}")
    for name in ("project-a", "project-b"):
        env_python = projects / name / "env" / "bin" / "python"
        out = subprocess.run(
            [str(env_python), "-c", "import pip,setuptools;print(pip.__version__, setuptools.__version__)"],
            capture_output=True, text=True, check=False,
        )
        print(f"  {name} env seeds (pip setuptools): {out.stdout.strip() or RED + out.stderr.strip() + RESET}")

    heading("5. What was GENERATED in each private staging area")
    for name in ("project-a", "project-b"):
        stage = projects / name / "stage"
        images = stage / "wheel" / PY / "image" / "1" / "CopyPipInstall"
        generated = sorted(p.name for p in images.iterdir() if p.is_dir()) if images.exists() else []
        locks = sum(1 for _ in stage.rglob("*.lock"))
        print(f"  {name}: generated images {generated}; lock files in private stage: {locks}")
        assert not any(shared.rglob("setuptools-*")), "setuptools leaked into the shared cache"

    heading("6. Mid-build failure: staging directory is reclaimed")
    fail_stage = work / "failure" / "stage"
    proc = ctx.Process(
        target=_session_worker,
        args=(str(shared), str(fail_stage), str(work / "failure" / "env"), str(index), "boom"),
    )
    proc.start()
    proc.join()
    print(f"  failing session exit code: {proc.exitcode} (non-zero as expected)")
    leftovers = find_orphaned_staging(fail_stage)
    print(f"  leftover staging dirs after caught failure: {leftovers or GREEN + 'none (reclaimed)' + RESET}")
    print(f"  shared tree still unchanged: {GREEN + 'yes' + RESET if snapshot(shared) == before else RED + 'NO' + RESET}")

    heading("7. Simulate a killed process and audit for unreclaimed temp files")
    orphan = fail_stage / "wheel" / PY / "image" / "1" / "CopyPipInstall" / f"CopyPipInstall-{wheel.path.stem}"
    orphan.mkdir(parents=True, exist_ok=True)
    (orphan / "half-extracted.txt").write_text("partial", encoding="utf-8")
    found = find_orphaned_staging(fail_stage)
    print(f"  audit detects orphan: {YELLOW + str(found[0].relative_to(work)) + RESET if found else RED + 'none' + RESET}")
    for target in found:
        shutil.rmtree(target)
    print(f"  audit after reaping: {find_orphaned_staging(fail_stage) or GREEN + 'clean' + RESET}")

    heading("Summary")
    print("  shared cache: read-only, zero writes across 3 sessions")
    print("  private staging: only place new images/locks are created; failures cleaned, orphans auditable")
    print(f"\nArtifacts kept under: {work}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
