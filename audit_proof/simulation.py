"""Command line entrypoint: ``python -m audit_proof``."""

from __future__ import annotations

import sys

from .report import render_full_report
from .scenarios import run_simulation


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    result = run_simulation()
    print(render_full_report(result))

    print("[9] 真实 APScheduler 代码路径佐证（AsyncScheduler + SQLAlchemyDataStore）")
    print("=" * 104)
    exit_ok = result.all_passed

    if "--no-live" not in argv:
        from .live import run_live_corroboration

        live = run_live_corroboration()
        if not live.available:
            print(
                f"[SKIP] APScheduler 依赖不可用，已跳过 live 佐证：{live.unavailable_reason}"
            )
        else:
            for line in live.lines:
                print(f"  - {line}")
            for name, passed, detail in live.checks:
                mark = "PASS" if passed else "FAIL"
                print(f"[{mark}] {name}\n         {detail}")
                if not passed:
                    exit_ok = False
            live_passed = sum(1 for _, passed, _ in live.checks if passed)
            print("-" * 104)
            print(f"live assertions: {live_passed}/{len(live.checks)} passed")
            if any(not passed for _, passed, _ in live.checks):
                exit_ok = False
    else:
        print("[SKIP] --no-live given")

    print("=" * 104)
    if exit_ok:
        print(
            "RESULT: ALL CHECKS PASSED — 重复可去重、缺失/提前可辨别、结论可绑定已提交事实。"
        )
        return 0
    print("RESULT: FAILURES PRESENT — 见上方 FAIL 项。")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
