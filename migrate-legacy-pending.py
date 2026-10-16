#!/usr/bin/env python3
"""T02 一次性遷移（2026-10-16 · Codex 獨立驗收整改第 1、2 條）：
把「無卡號（malformed）」的歷史 pending 記錄，從正式 pending 存放區
**原樣遷移**到歸檔檔（不刪除、不改語義、留完整稽核痕）。

背景（一手）：正式 store 有 42 筆——
  · 21 筆 T02（合法；為 receipt 綁定對象，保持不動）
  · 21 筆「task_id 空」的 malformed 記錄（產生於 2026-10-12~10-13 施工早期，
    當時稽核器尚無法解析卡號，逐輪記成「無卡」阻擋；其後不再更新）
本腳本把後者移入 `T02-legacy-pending-archive.json`（含遷移 metadata 與原文），
主 store 只保留「可識別卡號」的記錄。

安全設計：
  · 預設 dry-run；--apply 才寫入。
  · 只遷移「task_id 為空」的記錄（絕不碰任何有卡號的記錄）。
  · 遷移前備份原檔；寫入用稽核器官方函式 save_pending（同格式、原子）。
  · 產出 before/after 筆數與 SHA256 對照；歸檔檔與主檔皆可獨立核對。

用法：
    python3 migrate-legacy-pending.py             # dry-run（只印計畫）
    python3 migrate-legacy-pending.py --apply     # 執行遷移
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys

BASE = pathlib.Path(__file__).resolve().parent
STORE = BASE / "T02-pending-violations.json"
ARCHIVE = BASE / "T02-legacy-pending-archive.json"
BACKUP_DIR = BASE / "_備份" / "c0c-legacy-migration-20261016"


def load_audit():
    os.environ["T02_PENDING_PATH"] = str(STORE)
    spec = importlib.util.spec_from_file_location("t02aud_mig", BASE / "T02-discipline-audit.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="遷移無卡號的歷史 pending 記錄")
    parser.add_argument("--apply", action="store_true", help="實際執行（預設只 dry-run）")
    args = parser.parse_args(argv[1:])

    audit = load_audit()
    data, ok = audit.load_pending()
    if not ok:
        print(json.dumps({"ok": False, "error": "pending 存放區讀取失敗"}, ensure_ascii=False))
        return 2

    legacy = {k: v for k, v in data.items() if isinstance(v, dict) and str(v.get("task_id") or "") == ""}
    keep = {k: v for k, v in data.items() if k not in legacy}
    t02 = [k for k, v in keep.items() if isinstance(v, dict) and str(v.get("task_id") or "") == "T02"]
    other = [k for k, v in keep.items() if k not in t02]

    print(f"store 總筆數: {len(data)}")
    print(f"  將遷移（task_id 空）: {len(legacy)} 筆")
    print(f"  保留（T02）: {len(t02)} 筆；保留（其他卡）: {len(other)} 筆")
    for k in sorted(legacy):
        print(f"    - {k}  updated={legacy[k].get('updated')}")

    if not args.apply:
        print("\n[dry-run] 未寫入。加 --apply 才執行。")
        return 0

    # 1) 備份
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup = BACKUP_DIR / "T02-pending-violations.before.json"
    shutil.copy2(STORE, backup)
    before_sha = sha256_of(STORE)

    # 2) 歸檔（原文原樣）
    archive_doc = {
        "schema": 1,
        "migration": {
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
            "reason": (
                "Codex 2026-10-16 獨立驗收整改第 1、2 條：malformed（task_id 空）的歷史記錄"
                "（2026-10-12~10-13 施工早期、稽核器尚無法解析卡號時逐輪寫入）"
                "原樣移入本歸檔檔；主 store 只保留可識別卡號的記錄。不改語義、不刪除。"
            ),
            "source_store_sha256_before": before_sha,
            "migrated_count": len(legacy),
            "kept_t02_count": len(t02),
            "kept_other_count": len(other),
            "migrated_keys": sorted(legacy.keys()),
        },
        "entries": legacy,
    }
    ARCHIVE.write_text(json.dumps(archive_doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 3) 主 store 只留可識別卡號的
    audit.save_pending(keep)
    after_sha = sha256_of(STORE)

    # 4) 驗證
    data2, ok2 = audit.load_pending()
    legacy2 = {k: v for k, v in data2.items() if isinstance(v, dict) and str(v.get("task_id") or "") == ""}
    t022 = [k for k, v in data2.items() if isinstance(v, dict) and str(v.get("task_id") or "") == "T02"]
    print(json.dumps({
        "ok": bool(ok2) and not legacy2 and len(data2) == len(keep),
        "store_after_total": len(data2),
        "store_after_t02": len(t022),
        "store_after_legacy": len(legacy2),
        "archive_path": str(ARCHIVE),
        "archive_count": len(legacy),
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "backup": str(backup),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
