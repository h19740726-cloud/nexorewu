#!/usr/bin/env python3
"""T02 第 12 輪：反向突變。

原則（沿用第 4 輪教訓）：
  - 突變的單位＝**一條防線**，不是一行。
  - 突變後**必須有紅燈**才算有效；全綠就先假設是突變寫壞了。
  - 要「精準」：該紅的紅、不該紅的仍綠。

每個突變都改**受驗腳本本體**（測試用的副本由它複製而來，故一併繼承突變）。
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

BASE = pathlib.Path("/Users/wulieqiang/AI協作/work/codex")
AUDIT = BASE / "T02-discipline-audit.py"
TESTMOD = "test_T02_discipline_audit"

# (名稱, 原字串, 突變字串, 期望轉紅的測試名)
MUTATIONS = [
    (
        "M1_stop_signature_check",
        "    if not openssl_verify(payload_bytes, signature, RECEIPT_PUBKEY_PEM):",
        "    if False and not openssl_verify(payload_bytes, signature, RECEIPT_PUBKEY_PEM):",
        ["test_r12_b2_tampered_payload_is_rejected"],
    ),
    (
        "M2_stop_fingerprint_check",
        "    if fp != expected_fp:",
        "    if False and fp != expected_fp:",
        ["test_r12_i_wrong_fingerprint_is_rejected"],
    ),
    (
        "M3_stop_nonce_replay_check",
        "    elif nonce in load_used_nonces():",
        "    elif False and nonce in load_used_nonces():",
        ["test_r12_f_receipt_nonce_cannot_be_replayed"],
    ),
    (
        "M4_stop_pending_ids_check",
        "            if not isinstance(receipt_ids, list) or sorted(str(i) for i in receipt_ids) != target_ids:",
        "            if False:",
        ["test_r12_d_receipt_pending_ids_must_match"],
    ),
    (
        "M5_stop_result_sha_check",
        '            elif str(payload.get("result_sha256") or "") != digest:',
        "            elif False:",
        ["test_r12_g_receipt_result_hash_must_match"],
    ),
    (
        "M6_stop_task_id_check",
        '    elif str(payload.get("task_id") or "") != key:',
        "    elif False:",
        ["test_r12_h_receipt_task_id_must_match_target"],
    ),
    (
        "M7_stop_pubkey_installed_guard",
        "    if not RECEIPT_PUBKEY_PEM.strip():",
        "    if False:",
        ["test_r12_c_uninstalled_pubkey_rejects_all_clears"],
    ),
    (
        "M8_stop_result_taskid_check",
        '            elif f"task_id={key}" not in text:',
        "            elif False:",
        ["test_r10_a7c_clear_requires_verdict_task_binding"],
    ),
    (
        "M9_stop_pending_dedup",
        "    # 已有同卡的 open pending → 只更新它（累加次數），不新增第二筆。\n    if card_id:",
        "    # 已有同卡的 open pending → 只更新它（累加次數），不新增第二筆。\n    if False and card_id:",
        ["test_r12_d3_same_card_keeps_single_pending"],
    ),
]


def run_tests() -> tuple[int, list[str]]:
    """跑全套測試，回 (returncode, 紅燈測試名清單)。

    🔴 unittest 的 FAIL／ERROR 明細寫在 **stderr**，Ran／OK／FAILED 也在 stderr；
    一定要兩個流都讀（第 6 輪踩過的坑）。
    """
    proc = subprocess.run(
        ["/usr/bin/python3", "-m", "unittest", TESTMOD],
        cwd=str(BASE),
        capture_output=True,
        text=True,
        check=False,
    )
    blob = (proc.stdout or "") + "\n" + (proc.stderr or "")
    failures = []
    for line in blob.splitlines():
        for prefix in ("FAIL: ", "ERROR: "):
            if line.startswith(prefix):
                name = line[len(prefix):].split(" ")[0]
                if "." in name:
                    name = name.split(".")[-1]
                failures.append(name)
    return proc.returncode, sorted(set(failures))


def main() -> int:
    original = AUDIT.read_text(encoding="utf-8")

    print("=== 基準（突變前）===")
    rc, failures = run_tests()
    print(f"rc={rc} 紅燈={failures}")
    if rc != 0:
        print("!! 基準不是全綠，先修基準再突變。中止。")
        return 1

    results = []
    try:
        for name, old, new, expected in MUTATIONS:
            if old not in original:
                print(f"\n=== {name} ===")
                print(f"!! 找不到字串，突變無效：{old!r}")
                results.append((name, expected, ["<字串未命中>"], False))
                continue
            mutated = original.replace(old, new, 1)
            AUDIT.write_text(mutated, encoding="utf-8")
            rc2, failures2 = run_tests()
            got = set(failures2)
            exp = set(expected)
            precise = got == exp
            print(f"\n=== {name} ===")
            print(f"rc={rc2}")
            print(f"紅燈={sorted(got)}")
            print(f"期望={sorted(exp)}  ->  {'✅ 精準' if precise else '⚠️ 不精準'}")
            results.append((name, sorted(exp), sorted(got), precise))
    finally:
        AUDIT.write_text(original, encoding="utf-8")

    print("\n=== 彙總 ===")
    ok = 0
    for name, exp, got, precise in results:
        print(f"{'✅' if precise else '⚠️'} {name}: 期望={exp} 實得={got}")
        ok += 1 if precise else 0
    print(f"\n精準 {ok}/{len(results)}")

    # 還原驗證
    restored = AUDIT.read_text(encoding="utf-8")
    print("還原後與原稿逐位元相同：", restored == original)
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
