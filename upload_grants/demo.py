"""Runnable two-request demonstration.

Usage::

    .venv/bin/python -m upload_grants.demo

Writes a fresh JSONL signature record plus a JSON report into
``upload_grants/demo_artifacts/`` and prints a readable audit narrative.
No network access is performed; signing uses the well-known synthetic AWS
documentation credentials against a local endpoint label.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from upload_grants.issuer import (SYNTHETIC_ACCESS_KEY, SYNTHETIC_ENDPOINT,
                                      SYNTHETIC_REGION)
    from upload_grants.scenarios import run_two_requests
else:
    from .issuer import (SYNTHETIC_ACCESS_KEY, SYNTHETIC_ENDPOINT,
                         SYNTHETIC_REGION)
    from .scenarios import run_two_requests

ARTIFACT_DIR = Path(__file__).resolve().parent / "demo_artifacts"
JOURNAL_PATH = ARTIFACT_DIR / "signature_records.jsonl"
REPORT_PATH = ARTIFACT_DIR / "demo_report.json"


def _print_checks(verification: dict | None) -> None:
    if not verification:
        return
    for check in verification["checks"]:
        mark = "PASS" if check["ok"] else "FAIL"
        print(f"    [{mark}] {check['name']}: "
              f"expected={check['expected']!r} actual={check['actual']!r}")


def main() -> int:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    JOURNAL_PATH.write_text("", encoding="utf-8")

    print("=" * 78)
    print("MinIO 归档上传授权：最小权限合同 / 两种发放路径核对")
    print("=" * 78)
    print(f"合成端点: http://{SYNTHETIC_ENDPOINT} (不发起网络请求)")
    print(f"合成凭据: access_key={SYNTHETIC_ACCESS_KEY} "
          f"region={SYNTHETIC_REGION} (secret 仅参与 HMAC，不落盘)")
    print(f"本地签名记录: {JOURNAL_PATH}")

    report = run_two_requests(JOURNAL_PATH)

    one = report["request_one"]
    scope1 = one["post_form"]["scope"]
    print("\n--- 请求 1：获准前缀收紧为单个对象，两种输出对照 ---")
    print(f"  共同范围对象: {scope1['key']}")
    print(f"  来源审批前缀: {scope1['approved_prefix']}")
    print(f"  有效期: {scope1['ttl_seconds']}s，"
          f"截止 {scope1['expires_at']}")
    print("  [post_form] " + one["post_form"]["message"])
    _print_checks(one["post_form"]["verification"])
    print("  [put_url]   " + one["put_url"]["message"])
    _print_checks(one["put_url"]["verification"])
    cross = one["cross_channel"]
    if cross:
        for check in cross["checks"]:
            mark = "PASS" if check["ok"] else "FAIL"
            print(f"    [{mark}] cross/{check['name']}: "
                  f"form={check['expected']!r} put={check['actual']!r}")
    put_url1 = one["put_url"]["artifact"]["put_url"]
    print(f"  PUT URL 实际路径锁定: "
          f"{put_url1.split('?', 1)[0]}")

    two = report["request_two"]
    scope2 = two["post_form"]["scope"]
    print("\n--- 请求 2：追加只有表单能表达的大小与标签限制 ---")
    print(f"  共同范围对象: {scope2['key']}")
    print(f"  大小区间(字节): {scope2['size_range']}")
    print(f"  数据标签: {scope2['tags']}")
    print("  [post_form] " + two["post_form"]["message"])
    policy = two["post_form"]["artifact"]["form_data"]["policy"]
    print(f"    policy(base64) 已签名，解码后条件片段:")
    import base64
    doc = json.loads(base64.b64decode(policy))
    for condition in doc["conditions"]:
        if condition[0] in ("content-length-range",) or \
                (condition[0] == "eq" and "tagging" in condition[1]):
            print(f"      {condition}")
    _print_checks(two["post_form"]["verification"])

    put2 = two["put_url"]
    print("  [put_url]   " + put2["message"])
    for missing in put2["missing"]:
        print(f"    [缺项] {missing['condition']} — {missing['label']}")
        print(f"           原因: {missing['detail']}")
        print(f"           可用于: {', '.join(missing['expressible_in'])}")
    print(f"    调用结果 status={put2['status']} "
          f"available_methods={put2['available_methods']}")
    print("    该次调用未触发 presigned_put_object，记录为 refused。")

    print("\n--- 签名记录审计 ---")
    for check in report["audit"]["checks"]:
        mark = "PASS" if check["ok"] else "FAIL"
        extra = {k: v for k, v in check.items()
                 if k not in ("name", "ok")}
        print(f"  [{mark}] {check['name']} {extra}")

    request_two_puts = [
        r for r in report["records"]
        if r.get("request_id") == "REQ-059-02"
        and r.get("channel") == "put_url"
    ]
    request_two_signed_puts = [
        r for r in request_two_puts if r.get("signed")
    ]
    print(f"  REQ-059-02 的 PUT 台账条目: {len(request_two_puts)} 条，"
          f"其中真正签名发出的 PUT: {len(request_two_signed_puts)} 条")
    print("  唯一的 PUT 条目为 refused：无签名、无 URL、未调用预签方法。")
    print(f"  JSONL 总记录数: {len(report['records'])}")

    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n机器可读报告: {REPORT_PATH}")

    ok = (
        report["audit"]["ok"]
        and one["post_form"]["status"] == "issued"
        and one["put_url"]["status"] == "issued"
        and cross is not None and cross["consistent"]
        and two["post_form"]["status"] == "issued"
        and two["put_url"]["status"] == "unexpressible"
        and {m["condition"] for m in two["put_url"]["missing"]}
        == {"content_length_range", "tags"}
        and all(r["event"] == "refused" for r in request_two_puts)
        and not request_two_signed_puts
    )
    print("结果: " + ("全部核对通过 ✅" if ok else "存在失败项 ❌"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
