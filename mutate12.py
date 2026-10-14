#!/usr/bin/env python3
"""T02 第 14 輪：反向突變（**隔離副本版**）。

原則（沿用第 4 輪教訓）：
  - 突變的單位＝**一條防線**，不是一行。
  - 突變後**必須有紅燈**才算有效；全綠就先假設是突變寫壞了。
  - 要「精準」：該紅的紅、不該紅的仍綠。

🔴 第 14 輪（對應業主 2026-10-14 要求）：**只在隔離副本跑**。
  整個過程把受驗程式與測試複製到暫存目錄，所有突變只作用在副本上；
  正式受驗檔 `work/codex/T02-discipline-audit.py` **不會被寫入**，
  收尾時比對前後 SHA256 作為「未被改寫」的收據。

🔴 M8 於第 14 輪更新：`clear_pending()` 的結果檔檢查已由「全文包含 `task_id=` 字串」
  改為 `parse_verdict_declaration()` 的**欄位等值核對**，舊突變字串已不存在；
  本輪改為突變該解析函式的 task_id 取樣行。
"""
from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

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
        "        handle = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)",
        "        handle = os.open(str(marker), os.O_CREAT | os.O_WRONLY, 0o600)",
        [
            "test_r12_f_receipt_nonce_cannot_be_replayed",
            "test_r13_a3_nonce_store_path_cannot_be_redirected",
            "test_r13_nonce_consumption_is_atomic_under_concurrency",
        ],
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
        "    task_ids = TASK_ID_DECL_RE.findall(text)",
        '    task_ids = ["test-card"]',
        ["test_r10_a7c_clear_requires_verdict_task_binding"],
    ),
    (
        "M9_stop_pending_dedup",
        "    # 已有同卡的 open pending → 只更新它（累加次數），不新增第二筆。\n    if card_id:",
        "    # 已有同卡的 open pending → 只更新它（累加次數），不新增第二筆。\n    if False and card_id:",
        ["test_r12_d3_same_card_keeps_single_pending"],
    ),
]


def run_tests(workdir: pathlib.Path) -> tuple[int, list[str]]:
    """在**隔離目錄**跑全套測試，回 (returncode, 紅燈測試名清單)。

    🔴 unittest 的 FAIL／ERROR 明細寫在 **stderr**，Ran／OK／FAILED 也在 stderr；
    一定要兩個流都讀（第 6 輪踩過的坑）。
    """
    proc = subprocess.run(
        ["/usr/bin/python3", "-m", "unittest", TESTMOD],
        cwd=str(workdir),
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
    before_sha = hashlib.sha256(AUDIT.read_bytes()).hexdigest()

    work = pathlib.Path(tempfile.mkdtemp(prefix="t02-mutation-"))
    results: list[tuple[str, list[str], list[str], bool]] = []
    try:
        target = work / "T02-discipline-audit.py"
        shutil.copy2(AUDIT, target)
        shutil.copy2(BASE / f"{TESTMOD}.py", work / f"{TESTMOD}.py")

        print("=== 基準（突變前，隔離副本）===")
        rc, failures = run_tests(work)
        print(f"rc={rc} 紅燈={failures}")
        if rc != 0:
            print("!! 基準不是全綠，先修基準再突變。中止。")
            return 1

        for name, old, new, expected in MUTATIONS:
            if old not in original:
                print(f"\n=== {name} ===")
                print(f"!! 找不到字串，突變無效：{old!r}")
                results.append((name, expected, ["<字串未命中>"], False))
                continue
            target.write_text(original.replace(old, new, 1), encoding="utf-8")
            rc2, failures2 = run_tests(work)
            got = set(failures2)
            exp = set(expected)
            precise = got == exp
            print(f"\n=== {name} ===")
            print(f"rc={rc2}")
            print(f"紅燈={sorted(got)}")
            print(f"期望={sorted(exp)}  ->  {'✅ 精準' if precise else '⚠️ 不精準'}")
            results.append((name, sorted(exp), sorted(got), precise))
            target.write_text(original, encoding="utf-8")

        print("\n=== 彙總 ===")
        ok = 0
        for name, exp, got, precise in results:
            print(f"{'✅' if precise else '⚠️'} {name}: 期望={exp} 實得={got}")
            ok += 1 if precise else 0
        print(f"\n精準 {ok}/{len(results)}")

        after_sha = hashlib.sha256(AUDIT.read_bytes()).hexdigest()
        print(f"正式受驗檔未被寫入（前後 SHA256 相同）：{before_sha == after_sha}")
        print(f"正式受驗檔 SHA256：{after_sha}")
        return 0 if ok == len(results) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
