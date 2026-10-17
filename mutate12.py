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

🔴 M13 於第 18 輪重送輪同步（2026-10-14 22:5x）：expected 補入 c6／c7／c8。
  該三條與 c1／c3／c4／c5／c9 同屬 `blocked` 判斷防線家族（皆斷言 `audit_decision=="block"`），
  突變 `blocked=False` 時本應全數轉紅；先前清單漏列（第 18 輪只補了 c9）。
  同步後重跑，14 組全數精準。

🔴 M15 於第 19 輪新增（2026-10-14 23:4x）：鎖「宿主欄位永遠不得是 block」。
  第 18 輪把審計訊號放在 `decision`，而宿主 `parseHookOutput()` 是 else-if 鏈、
  `decision:"block"` 優先於 `continue:true` ⇒ 每次使用者送出訊息都被阻擋（已實測兩次）。
  本組突變 `"decision": "allow",` → `"decision": "block",`，預期 r18_c1~c9 全數轉紅。
  全量 15 組。

🔴 第 20 輪（Codex 第 19 輪驗收整改①，2026-10-15）：**支援指定單組／分批執行**。
  `--list`（列出組別編號）／`--only M7`（單組，逗號可多組）／`--range 1-5`（編號區間）；
  無參數＝全量（與舊版行為相同）。每組輸出 `started=… finished=… elapsed=…s` 與退出碼，
  供驗收方在合理時間內分批獨立重跑（本機全量序列實測約 8 至 19 分鐘，視負載）。
  每批執行都會先跑一次基準（基準必須全綠才進入該批的突變）。

🔴 第 20 輪·全量首跑後同步：M14／M15 的 expected 補入 `r18_c10`（2026-10-15 07:1x）。
  兩者的突變直接改 `continue`／`decision` 兩個宿主欄位，而 c10 於第 20 輪改為
  「兩段式安全契約」後會直接鎖這兩個值 ⇒ 兩組本應多紅 c10 一條（全量首跑實得
  各多一條 c10，屬預期）；expected 同步後，15 組於各自批次內全數精準。

🔴 最終輪新增 M16／M17（2026-10-15，對應最終整改④「信任根不可替換」）：
  - M16：信任根改讀**環境變數**（`T02_RECEIPT_PUBKEY` 優先於內嵌常數）
    ⇒ 預期轉紅 r22_a（env 向量）與 r22_e（未安裝免疫）。
  - M17：信任根 fallback 到**可寫檔**（cwd 與腳本目錄的 `pub.pem`）
    ⇒ 預期轉紅 r22_b（cwd 向量）、r22_c（腳本目錄向量）與 r22_e。
  - 兩組的紅燈互補且不散射（r22_a 不受 M17 影響、r22_b／c 不受 M16 影響、
    r22_d 兩組皆綠＝CLI 向量不在這兩條突變的路徑上），已在實作前以徒手探針驗證。
  全量 17 組。

🔴 C0d 同步（2026-10-17）：受驗稽核器的信任根驗證已重構為通用
  `verify_signed_document()`（Codex C0d 施工引入，收據／核准共用）⇒ 下列五組的
  find 字串同步至**現行碼形**（M1／M2／M7 改咬通用函式內的三道守門；
  M16／M17 改在 `verify_receipt()` 的呼叫前注入覆寫）；**缺陷語義與預期紅燈不變**。
  未同步時五組均為「<字串未命中>」（2026-10-17 實測五組全數命中斷點）。
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

# 🔴 第 18 輪整改（Codex 第 17 輪驗收反例 ③，2026-10-14）：
#   BASE 一律綁「本檔自身所在目錄」——在隔離 clone 中執行時，只會讀寫該 clone 的受驗檔，
#   不再讀取共享的可變目錄（正式工作目錄）。
BASE = pathlib.Path(__file__).resolve().parent
AUDIT = BASE / "T02-discipline-audit.py"
TESTMOD = "test_T02_discipline_audit"

# (名稱, 原字串, 突變字串, 期望轉紅的測試名)
MUTATIONS = [
    (
        "M1_stop_signature_check",
        "    if not openssl_verify(payload_bytes, signature, pubkey_pem):",
        "    if False and not openssl_verify(payload_bytes, signature, pubkey_pem):",
        ["test_r12_b2_tampered_payload_is_rejected", "test_r17_b1_signature_failure_leaves_pending_intact"],
    ),
    (
        "M2_stop_fingerprint_check",
        '    if str(raw.get("key_fingerprint") or "") != pubkey_fingerprint(pubkey_pem):',
        '    if False and str(raw.get("key_fingerprint") or "") != pubkey_fingerprint(pubkey_pem):',
        [
            "test_r12_i_wrong_fingerprint_is_rejected",
            # 🔴 C0d 同步（2026-10-17）：本突變關的是**收據／核准共用**的指紋守門；
            #    C0d 反例的偽造核准一路正斷言拒絕語「公鑰指紋」⇒ 守門被關時同轉紅，屬預期。
            "test_c0d_workbuddy_cannot_self_clear_or_forge_independent_approval",
        ],
    ),
    (
        "M3_stop_nonce_replay_check",
        "        handle = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)",
        "        handle = os.open(str(marker), os.O_CREAT | os.O_WRONLY, 0o600)",
        [
            "test_r12_f_receipt_nonce_cannot_be_replayed",
            "test_r13_a3_nonce_store_path_cannot_be_redirected",
            "test_r13_nonce_consumption_is_atomic_under_concurrency",
            "test_r17_b6_nonce_replay_leaves_pending_intact",
        ],
    ),
    (
        "M4_stop_pending_ids_check",
        "            if not isinstance(receipt_ids, list) or sorted(str(i) for i in receipt_ids) != target_ids:",
        "            if False:",
        ["test_r12_d_receipt_pending_ids_must_match", "test_r17_b3_pending_ids_mismatch_leaves_pending_intact"],
    ),
    (
        "M5_stop_result_sha_check",
        '            elif str(payload.get("result_sha256") or "") != digest:',
        "            elif False:",
        ["test_r12_g_receipt_result_hash_must_match", "test_r17_b4_result_sha_mismatch_leaves_pending_intact"],
    ),
    (
        "M6_stop_task_id_check",
        '    elif str(payload.get("task_id") or "") != key:',
        "    elif False:",
        ["test_r12_h_receipt_task_id_must_match_target", "test_r17_b2_wrong_task_leaves_pending_intact"],
    ),
    (
        "M7_stop_pubkey_installed_guard",
        "    if not pubkey_pem.strip():",
        "    if False and not pubkey_pem.strip():",
        [
            "test_r12_c_uninstalled_pubkey_rejects_all_clears",
            # 最終輪同步：r22_e 同樣斷言「尚未安裝守門」（M7 關掉它時應一併轉紅）。
            "test_r22_e_uninstalled_trust_root_immune_to_env_and_files",
        ],
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
    (
        "M10_behavior_defense_disabled",
        "    mutation_problems, mutation_summary = review_mutations(turn_rows, base_dir)",
        "    mutation_problems, mutation_summary = [], []",
        [
            "test_r15_a_failed_edit_with_fabricated_completion_is_blocked",
            "test_r15_b_failed_a_success_b_still_blocked",
            "test_r15_d_completed_without_artifact_is_blocked",
            "test_r15_e_existing_file_alone_is_not_evidence",
            "test_r15_f_edit_without_result_is_blocked",
            "test_r15_i_completed_but_file_unchanged_is_blocked",
            "test_r15_j_same_file_different_edit_cannot_mask_failure",
            "test_r15_l_write_content_mismatch_is_blocked",
            "test_r15_m_edit_without_content_fields_is_unverified",
            "test_r18_c5_end_to_end_real_project_and_transcript",
        ],
    ),
    (
        "M11_stop_locked_version_binding",
        "    elif receipt_version != artifact_sha:",
        "    elif False:",
        ["test_clear_rejects_version_mismatch", "test_r17_b5_locked_version_mismatch_leaves_pending_intact"],
    ),
    (
        "M12_stop_pending_write_failure_must_refuse",
        '        print("clear refused: pending 存放區寫入失敗，未清除", file=sys.stderr)\n        return 3',
        '        print("clear refused: pending 存放區寫入失敗，未清除", file=sys.stderr)\n        return 0',
        [
            "test_r17_b7_unwritable_pending_store_keeps_original_file",
            # 最終輪同步：b11 同樣斷言「寫入失敗時 rc!=0」（M12 改成假成功時應一併轉紅）。
            "test_r17_b11_pending_write_failure_leaves_correction_mark_in_log",
        ],
    ),
    (
        "M13_user_prompt_readback_never_blocks",
        "    blocked = bool(problem) or bool(open_items)",
        "    blocked = False",
        [
            "test_r18_c1_blocks_when_open_pending_exists",
            "test_r18_c3_output_must_not_claim_completion",
            "test_r18_c4_broken_store_blocks",
            "test_r18_c5_end_to_end_real_project_and_transcript",
            "test_r18_c6_cli_key_must_not_override_event_card",
            "test_r18_c7_cli_key_alone_is_not_authoritative",
            "test_r18_c8_matching_cli_key_keeps_behaviour",
            "test_r18_c9_host_safety_never_blocks_prompt",
        ],
    ),
    (
        "M14_readback_continue_safety_lock",
        '        "continue": True,',
        '        "continue": False,',
        [
            "test_r18_c9_host_safety_never_blocks_prompt",
            "test_r18_c10_formal_hook_installed_in_settings",
        ],
    ),
    (
        # 🔴 第 19 輪新增：把回讀的**宿主欄位**改回 `block`（＝第 18 輪的真實缺陷形狀）。
        # 宿主 `parseHookOutput()` 的 else-if 鏈中 `decision` 優先於 `continue`，
        # 一旦是 block，使用者每一次送出訊息都會被擋（實測已發生兩次）。
        # ⇒ 本組鎖住「宿主欄位永遠不得是 block」這條不變式。
        "M15_host_field_must_never_be_block",
        '        "decision": "allow",',
        '        "decision": "block",',
        [
            "test_r18_c1_blocks_when_open_pending_exists",
            "test_r18_c2_allows_after_pending_cleared",
            "test_r18_c3_output_must_not_claim_completion",
            "test_r18_c4_broken_store_blocks",
            "test_r18_c5_end_to_end_real_project_and_transcript",
            "test_r18_c6_cli_key_must_not_override_event_card",
            "test_r18_c7_cli_key_alone_is_not_authoritative",
            "test_r18_c8_matching_cli_key_keeps_behaviour",
            "test_r18_c9_host_safety_never_blocks_prompt",
            "test_r18_c10_formal_hook_installed_in_settings",
        ],
    ),
    (
        # 🔴 最終輪新增：信任根（內嵌公鑰）被**環境變數**替換的突變。
        # 對應 r22_a（env 向量反例）與 r22_e（未安裝時對 env 免疫）。
        # r22_b／c／d 綠＝正確（它們測的是檔案與 CLI 向量，本突變不涉及）。
        "M16_trustroot_env_override",
        '    return verify_signed_document(\n        receipt_path,\n        RECEIPT_PUBKEY_PEM,\n        "receipt",',
        (
            '    if os.environ.get("T02_RECEIPT_PUBKEY"):\n'
            '        globals()["RECEIPT_PUBKEY_PEM"] = os.environ["T02_RECEIPT_PUBKEY"]\n'
            '    return verify_signed_document(\n'
            '        receipt_path,\n'
            '        RECEIPT_PUBKEY_PEM,\n'
            '        "receipt",'
        ),
        [
            "test_r22_a_env_vars_cannot_replace_trust_root",
            "test_r22_e_uninstalled_trust_root_immune_to_env_and_files",
        ],
    ),
    (
        # 🔴 最終輪新增：信任根被**工作目錄／腳本目錄可寫檔**替換的突變。
        # 對應 r22_b（cwd 向量）、r22_c（腳本目錄向量）與 r22_e（未安裝時對檔案免疫）。
        # r22_a／d 綠＝正確（env 與 CLI 向量，本突變不涉及）。
        "M17_trustroot_file_fallback",
        '    return verify_signed_document(\n        receipt_path,\n        RECEIPT_PUBKEY_PEM,\n        "receipt",',
        (
            '    for _fallback in (Path.cwd() / "pub.pem", SELF_ARTIFACT_PATH.parent / "pub.pem"):\n'
            '        if _fallback.is_file():\n'
            '            globals()["RECEIPT_PUBKEY_PEM"] = _fallback.read_text(encoding="utf-8")\n'
            '            break\n'
            '    return verify_signed_document(\n'
            '        receipt_path,\n'
            '        RECEIPT_PUBKEY_PEM,\n'
            '        "receipt",'
        ),
        [
            "test_r22_b_cwd_files_cannot_replace_trust_root",
            "test_r22_c_script_dir_files_cannot_replace_trust_root",
            "test_r22_e_uninstalled_trust_root_immune_to_env_and_files",
        ],
    ),
    (
        # 🔴 最終輪新增：關掉日誌回推對 `CLEAR_FAILED` 更正痕的採納
        # （＝「pending 寫入失敗後，假痕不會被更正」的缺陷形狀）。
        # 對應 r17_b11（最終輪補完的 B 組測試）。
        "M18_clear_failed_correction_ignored",
        '        elif result == "CLEAR_FAILED":',
        '        elif False and result == "CLEAR_FAILED":',
        ["test_r17_b11_pending_write_failure_leaves_correction_mark_in_log"],
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


def select_groups(args: argparse.Namespace) -> tuple[list[int] | None, bool]:
    """依命令列參數決定要執行哪些組別；回傳（組索引清單, 是否成功）。None＝參數錯誤。"""
    n = len(MUTATIONS)
    if args.only and args.range:
        print("!! --only 與 --range 不可並用。")
        return None, False
    if args.only:
        idx: list[int] = []
        for w in (s.strip() for s in args.only.split(",")):
            if not w:
                continue
            hit = [
                i
                for i, (name, *_rest) in enumerate(MUTATIONS)
                if name == w or name.split("_", 1)[0] == w
            ]
            if not hit:
                print(f"!! 找不到組別：{w}（用 --list 看可用組別）")
                return None, False
            idx.append(hit[0])
        return sorted(set(idx)), True
    if args.range:
        m = re.match(r"^(\d+)-(\d+)$", args.range)
        if not m:
            print(f"!! --range 格式應為 N-M（1 起算，如 1-5），收到：{args.range}")
            return None, False
        lo, hi = int(m.group(1)), int(m.group(2))
        if not (1 <= lo <= hi <= n):
            print(f"!! --range 超出範圍（可用 1-{n}），收到：{args.range}")
            return None, False
        return list(range(lo - 1, hi)), True
    return list(range(n)), True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="T02 反向突變（隔離副本版）：全量或分批執行。"
    )
    parser.add_argument(
        "--list", action="store_true", help="只列出所有組別（編號＋名稱），不執行"
    )
    parser.add_argument(
        "--only", metavar="M7[,M9...]", default=None,
        help="只執行指定組別（前綴或全名，逗號分隔）",
    )
    parser.add_argument(
        "--range", metavar="N-M", default=None,
        help="只執行編號區間（1 起算，如 1-5）",
    )
    args = parser.parse_args()

    if args.list:
        print(f"共 {len(MUTATIONS)} 組：")
        for i, (name, *_rest) in enumerate(MUTATIONS, 1):
            print(f"{i:2d}. {name}")
        return 0

    selected, sel_ok = select_groups(args)
    if not sel_ok or selected is None:
        return 2

    print(f"BASE={BASE}")
    preview = ", ".join(MUTATIONS[i][0].split("_", 1)[0] for i in selected) or "（無）"
    print(f"本次執行 {len(selected)}/{len(MUTATIONS)} 組：{preview}")
    original = AUDIT.read_text(encoding="utf-8")
    before_sha = hashlib.sha256(AUDIT.read_bytes()).hexdigest()

    work = pathlib.Path(tempfile.mkdtemp(prefix="t02-mutation-"))
    results: list[tuple[str, list[str], list[str], bool]] = []
    t_all0 = time.time()
    try:
        target = work / "T02-discipline-audit.py"
        shutil.copy2(AUDIT, target)
        shutil.copy2(BASE / f"{TESTMOD}.py", work / f"{TESTMOD}.py")

        print("=== 基準（突變前，隔離副本）===")
        s0, t0 = datetime.datetime.now(), time.time()
        rc, failures = run_tests(work)
        t1, s1 = time.time(), datetime.datetime.now()
        print(f"started={s0.isoformat(timespec='seconds')} finished={s1.isoformat(timespec='seconds')} elapsed={t1 - t0:.1f}s")
        print(f"rc={rc} 紅燈={failures}")
        if rc != 0:
            print("!! 基準不是全綠，先修基準再突變。中止。")
            return 1

        for i in selected:
            name, old, new, expected = MUTATIONS[i]
            if old not in original:
                print(f"\n=== {name} ===")
                print(f"!! 找不到字串，突變無效：{old!r}")
                results.append((name, expected, ["<字串未命中>"], False))
                continue
            target.write_text(original.replace(old, new, 1), encoding="utf-8")
            s0, t0 = datetime.datetime.now(), time.time()
            rc2, failures2 = run_tests(work)
            t1, s1 = time.time(), datetime.datetime.now()
            got = set(failures2)
            exp = set(expected)
            precise = got == exp
            print(f"\n=== {name} ===")
            print(f"started={s0.isoformat(timespec='seconds')} finished={s1.isoformat(timespec='seconds')} elapsed={t1 - t0:.1f}s")
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
        print(f"本次執行 {len(selected)} 組｜總耗時 {time.time() - t_all0:.1f}s")

        after_sha = hashlib.sha256(AUDIT.read_bytes()).hexdigest()
        print(f"正式受驗檔未被寫入（前後 SHA256 相同）：{before_sha == after_sha}")
        print(f"正式受驗檔 SHA256：{after_sha}")
        return 0 if ok == len(results) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

# <!-- 變更：WorkBuddy ｜ 2026-10-14 19:5x ｜ 第18輪整改③：BASE 改綁自身所在目錄（clone 隔離有效化）；開頭輸出 BASE 行；供完整 13 組 stdout 收斂 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-14 19:4x ｜ 第18輪整改②配套：新增 M14（continue 安全鎖突變）；M13 expected 加 c9 -->
