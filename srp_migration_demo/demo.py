"""End-to-end, actually runnable migration demo on top of pysrp.

Run with::

    python -m srp_migration_demo.demo

Scenarios:
  1. registration record formats (legacy SHA-1 user, new SHA-256 user)
  2. legacy login succeeds, then an authenticated upgrade to SHA-256
  3. wrong password: login fails and the record is untouched
  4. parallel legacy logins: the stale upgrade loses the revision CAS
  5. interrupted switch: crash mid-commit, recovery, safe retry
  6. relabelling the old verifier as SHA-256 does not authenticate
  7. handshake parameters are bound to the record, never renegotiated
"""

import json
import os
import shutil
import tempfile

import srp

from .migration import (attempt_login, open_store, register_new_user,
                        review, seed_legacy_user, upgrade_after_login)
from .params import (LEGACY_PARAM_SET, TARGET_PARAM_SET,
                     ParameterError, assert_globals_pinned,
                     assert_consistent, describe)
from .protocol import (AuthService, AuthenticationFailed, Client,
                       full_login)
from .store import (ConflictError, SimulatedCrash, from_hex,
                    validate_record)

PASS = "PASS"
FAIL = "FAIL"
checks = []


def check(name, condition, detail=""):
    checks.append((name, bool(condition), detail))
    print("    [%s] %s%s" % (PASS if condition else FAIL, name,
                             (" -- " + detail) if detail else ""))


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show_record(record):
    print(json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True))


def fresh_store():
    root = tempfile.mkdtemp(prefix="srp-migrate-")
    store, recovery = open_store(root)
    return root, store, recovery


# -------------------------------------------------------------- scenario 1
def scenario_registration():
    section("1. 注册记录格式：每条记录绑定一个明确参数集")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    register_new_user(store, "zoe", "brand new password")

    legacy = store.get_record("alice")
    print("\n旧用户 alice 的记录（SHA-1，模拟历史数据）:")
    show_record(legacy)
    print("\n新用户 zoe 的记录（直接以 SHA-256 注册）:")
    show_record(store.get_record("zoe"))

    check("旧记录 param_set 唯一且为 SHA-1",
          legacy["param_set"] == LEGACY_PARAM_SET
          and legacy["params"]["digest"] == "sha1")
    check("记录只含单个 salt/verifier，无双份材料",
          all(k in legacy for k in ("salt", "verifier"))
          and "verifier_sha256" not in legacy)
    check("盐与验证器均为 hex 编码且可还原",
          from_hex(legacy["salt"]) and from_hex(legacy["verifier"]))
    check("用户名参与规则已固定并写入 params",
          legacy["params"]["x_rule"] == "srp_default_username_in_x")
    check("新用户直接落在目标参数集",
          store.get_record("zoe")["param_set"] == TARGET_PARAM_SET)
    validate_record(legacy)
    validate_record(store.get_record("zoe"))
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 2
def scenario_upgrade_ok():
    section("2. 旧用户成功登录后升级到 SHA-256")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    before = store.get_record("alice")
    old_salt, old_v = before["salt"], before["verifier"]

    print("\n升级前元数据盘点（无需口令的工作）:")
    print(json.dumps(review(store), indent=2, ensure_ascii=False))

    print("\n用旧 SHA-1 记录完成一次完整 SRP 握手（需要口令）...")
    before2, after, new_salt, new_verifier = upgrade_after_login(
        store, "alice", "correct horse")

    print("\n升级后的记录:")
    show_record(after)

    check("升级前确实是 SHA-1 记录",
          before["param_set"] == LEGACY_PARAM_SET)
    check("升级后只有一个参数集 SHA-256",
          after["param_set"] == TARGET_PARAM_SET
          and after["params"]["digest"] == "sha256"
          and after["salt"] != old_salt)
    check("新盐是客户端新生成的，未复用旧盐", after["salt"] != old_salt)
    check("新验证器与旧验证器不同（不是重贴标签）",
          after["verifier"] != old_v)
    check("revision 自增且历史可追溯",
          after["revision"] == before["revision"] + 1
          and any(h["event"] == "upgrade_committed" for h in after["history"]))
    check("无遗留 pending 日志", store.list_journals() == [])

    print("\n用新 SHA-256 记录再次登录，确认记录可用:")
    attempt_login(store, "alice", "correct horse", TARGET_PARAM_SET)
    check("升级后可按 SHA-256 参数集正常登录", True)

    # Explicit honesty check: we never computed the new verifier from the old.
    check("新验证器由客户端凭口令+新盐生成，旧 v 无法推出新 v",
          new_verifier != from_hex(old_v) and new_salt != from_hex(old_salt))
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 3
def scenario_wrong_password():
    section("3. 错误口令：握手失败，旧记录保持可用")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    before = store.get_record("alice")

    try:
        upgrade_after_login(store, "alice", "wrong horse")
    except AuthenticationFailed as exc:
        print("\n预期内的认证失败: %s" % exc)

    after = store.get_record("alice")
    check("记录参数集仍为 SHA-1", after["param_set"] == LEGACY_PARAM_SET)
    check("salt/verifier 完全未变",
          after["salt"] == before["salt"]
          and after["verifier"] == before["verifier"])
    check("revision 未自增", after["revision"] == before["revision"])
    check("无 pending 日志残留", store.list_journals() == [])

    print("\n正确口令仍可登录，旧记录未被破坏:")
    attempt_login(store, "alice", "correct horse", LEGACY_PARAM_SET)
    check("正确口令的旧登录仍然成功", True)
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 4
def scenario_parallel_logins():
    section("4. 并行旧登录：两个会话都成功，过期升级在 CAS 处失败")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    base = store.get_record("alice")

    # Two independent full handshakes against the same SHA-1 record.
    svc1, sid1, client1 = full_login(store, "alice", "correct horse",
                                     LEGACY_PARAM_SET)
    svc2, sid2, client2 = full_login(store, "alice", "correct horse",
                                     LEGACY_PARAM_SET)
    check("两个并行 SHA-1 会话均认证成功",
          svc1._sessions[sid1]["authenticated"]
          and svc2._sessions[sid2]["authenticated"])

    env1, _, _ = client1.build_upgrade_envelope(TARGET_PARAM_SET)
    env2, _, _ = client2.build_upgrade_envelope(TARGET_PARAM_SET)
    svc1.begin_upgrade(sid1, env1)
    svc2.begin_upgrade(sid2, env2)

    # Session 1 wins the swap.
    winner = svc1.commit_upgrade(sid1)
    check("会话1 提交成功，记录切到 SHA-256",
          winner["param_set"] == TARGET_PARAM_SET)

    # Session 2 holds a journal based on the now-stale revision.
    try:
        svc2.commit_upgrade(sid2)
        raised = False
    except ConflictError as exc:
        raised = True
        print("\n预期内的 CAS 冲突: %s" % exc)
    check("会话2 的过期升级被拒绝", raised)
    check("过期日志被清理，赢家记录未被覆盖",
          store.list_journals() == []
          and store.get_record("alice")["revision"] == winner["revision"])

    record = store.get_record("alice")
    check("恢复点记录仍只属于一个参数集",
          record["param_set"] == TARGET_PARAM_SET
          and record["params"]["digest"] == "sha256")
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 5
def scenario_interrupted_switch():
    section("5. 切换中断：提交中途崩溃，恢复后安全重试")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    before = store.get_record("alice")

    try:
        upgrade_after_login(store, "alice", "correct horse",
                            crash_after_replace=True)
    except SimulatedCrash as exc:
        print("\n模拟崩溃点: %s" % exc)

    mid = store.get_record("alice")
    journals = store.list_journals()
    check("崩溃后新记录已落盘（原子 replace 已完成）",
          mid["param_set"] == TARGET_PARAM_SET)
    check("未清理的日志仍在 pending 中", len(journals) == 1)
    check("落盘记录自身完整且只属于 SHA-256", mid["param_set"]
          == TARGET_PARAM_SET and mid["params"]["digest"] == "sha256")

    print("\n重启进程，执行无需口令的恢复流程...")
    store2, recovery = open_store(root)
    print("恢复动作: %s" % json.dumps(recovery, ensure_ascii=False))
    check("已应用的日志被识别并清理",
          recovery["completed_cleanup"] and not recovery["quarantined"])
    check("恢复后无 pending 日志", store2.list_journals() == [])
    recovered = store2.get_record("alice")
    check("恢复后记录唯一参数集为 SHA-256 且可登录",
          recovered["param_set"] == TARGET_PARAM_SET)
    attempt_login(store2, "alice", "correct horse", TARGET_PARAM_SET)
    check("恢复后 SHA-256 登录成功", True)

    # Second interruption shape: journal staged but swap never happens.
    seed_legacy_user(store2, "bob", "bob password")
    svc, sid, client = full_login(store2, "bob", "bob password",
                                  LEGACY_PARAM_SET)
    env, _, _ = client.build_upgrade_envelope(TARGET_PARAM_SET)
    svc.begin_upgrade(sid, env)
    bob_before = store2.get_record("bob")
    print("\nbob 的日志已 staged 但未 commit，模拟进程被杀；重启恢复...")
    store3, recovery3 = open_store(root)
    print("恢复动作: %s" % json.dumps(recovery3, ensure_ascii=False))
    check("未应用的日志被隔离而非自动提交",
          bool(recovery3["quarantined"])
          and not os.listdir(store3.pending_dir))
    bob = store3.get_record("bob")
    check("bob 的旧 SHA-1 记录原样可用",
          bob["param_set"] == LEGACY_PARAM_SET
          and bob["verifier"] == bob_before["verifier"])
    print("\nbob 重新走一次完整登录升级（需要口令）:")
    _, bob_after, _, _ = upgrade_after_login(store3, "bob", "bob password")
    check("重试后 bob 唯一参数集为 SHA-256",
          bob_after["param_set"] == TARGET_PARAM_SET
          and store3.list_journals() == [])
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 6
def scenario_relabel_does_not_work():
    section("6. 不能把旧验证值直接标成新算法")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")
    legacy = store.get_record("alice")

    # Forgery: keep the exact SHA-1 salt+verifier, only flip the label.
    forged = dict(legacy)
    forged["param_set"] = TARGET_PARAM_SET
    forged["params"] = describe(TARGET_PARAM_SET)
    forged["revision"] = legacy["revision"] + 1
    forged["history"] = legacy["history"] + [
        {"event": "illegal relabel", "at": legacy["updated_at"]}]
    # It passes pure shape validation (single material), which is why shape
    # checks alone are not enough; the proof is the handshake itself.
    validate_record(forged)
    from .store import _atomic_write
    _atomic_write(store._user_path("alice"), forged)

    client = Client("alice", "correct horse", TARGET_PARAM_SET)
    service = AuthService(store)
    name, A = client.start()
    sid, salt, B, served = service.challenge(name, A, TARGET_PARAM_SET)
    M = client.process_challenge(salt, B, served)
    try:
        service.verify(sid, M)
        raised = False
    except AuthenticationFailed as exc:
        raised = True
        print("\n预期内失败: %s" % exc)
    check("重贴标签的记录无法通过 SHA-256 握手", raised)

    # Restore the honest record to show the old one still works.
    _atomic_write(store._user_path("alice"), legacy)
    attempt_login(store, "alice", "correct horse", LEGACY_PARAM_SET)
    check("恢复诚实标签后，旧 SHA-1 登录仍然成功", True)
    shutil.rmtree(root)


# -------------------------------------------------------------- scenario 7
def scenario_no_renegotiation():
    section("7. 握手期间不重新协商解释：参数集必须与记录一致")
    root, store, _ = fresh_store()
    seed_legacy_user(store, "alice", "correct horse")

    client = Client("alice", "correct horse", TARGET_PARAM_SET)
    service = AuthService(store)
    name, A = client.start()
    try:
        service.challenge(name, A, TARGET_PARAM_SET)
        raised = False
    except ParameterError as exc:
        raised = True
        print("\n服务端拒绝: %s" % exc)
    check("SHA-256 客户端不能对 SHA-1 记录发起另一套解释", raised)

    # The guard function itself, used on both sides.
    try:
        assert_consistent(LEGACY_PARAM_SET, TARGET_PARAM_SET)
        raised2 = False
    except ParameterError:
        raised2 = True
    check("assert_consistent 拒绝任何参数集漂移", raised2)

    # Honest SHA-1 client still works against the same record.
    attempt_login(store, "alice", "correct horse", LEGACY_PARAM_SET)
    check("诚实的 SHA-1 登录不受影响", True)
    shutil.rmtree(root)


def main():
    assert_globals_pinned()
    print("pysrp backend: %s" % srp._mod.__name__)
    print("固定全局规则: rfc5054=%s, x_rule=%s"
          % (False, "srp_default_username_in_x"))
    scenario_registration()
    scenario_upgrade_ok()
    scenario_wrong_password()
    scenario_parallel_logins()
    scenario_interrupted_switch()
    scenario_relabel_does_not_work()
    scenario_no_renegotiation()

    section("汇总")
    total = len(checks)
    passed = sum(1 for _, ok, _ in checks if ok)
    for name, ok, detail in checks:
        if not ok:
            print("  FAILED: %s %s" % (name, detail))
    print("\n%d/%d 项断言通过" % (passed, total))
    if passed != total:
        raise SystemExit(1)
    print("\n结论: 升级只能由持有口令的客户端生成全新 SHA-256 盐与验证器；")
    print("旧 SHA-1 验证器无法推导出新验证器，任何失败路径都保留可用的旧记录。")


if __name__ == "__main__":
    main()
