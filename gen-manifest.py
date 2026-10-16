#!/usr/bin/env python3
"""生成 T02 受驗檔案 manifest（`T02-r22-manifest.json`）。

用法：python3 gen-manifest.py [--out T02-r22-manifest.json] [--allow-missing]

清單＝受驗鏈的全部檔案（稽核器、測試、突變器、工具鏈、workflow 副本、keygen）。
缺失檔案視為錯誤（rc=1），除非給 --allow-missing（此時缺失項標記 "MISSING" 但仍列出）。
輸出格式與既有 manifest 相同：{檔名: {"bytes": N, "sha256": "..."}}。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

FILES = [
    # 稽核器與測試
    "T02-discipline-audit.py",
    "test_T02_discipline_audit.py",
    "mutate12.py",
    "test-sign-inputs.py",
    # 簽發鏈工具
    "t02-ci-payload.py",
    "rehearse-final-chain.py",
    "install-pubkey.py",
    "make-sign-request.py",
    "sign-receipt.py",
    "gen-receipt-key.py",
    # 既有端到端工具
    "e2e12.py",
    "repro-round2.py",
    # C0c 遷移工具與歸檔（Codex 2026-10-16 整改第 1、2 條）
    "migrate-legacy-pending.py",
    "T02-legacy-pending-archive.json",
    # workflow 權威副本與 keygen
    "github-actions/t02-sign-receipt.yml",
    "tools/t02-keygen.html",
]

# 選配項：存在則收錄、不存在則跳過（不報錯）。
# 這兩項在「公鑰安裝後」才定稿（version 綁定最終稽核器 SHA），屬 C0b 內容。
OPTIONAL_FILES = [
    "T02-sign-request.json",
    "T02-sign-verdict.md",
]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="生成 T02 受驗檔案 manifest")
    parser.add_argument("--out", default="T02-r22-manifest.json", help="輸出檔名")
    parser.add_argument("--root", default="", help="repo 根目錄（預設：本檔所在目錄）")
    parser.add_argument("--allow-missing", action="store_true", help="允許缺失（標記 MISSING）")
    args = parser.parse_args(argv[1:])

    root = pathlib.Path(args.root) if args.root else pathlib.Path(__file__).resolve().parent
    manifest: dict = {}
    missing: list[str] = []
    for name in FILES + OPTIONAL_FILES:
        path = root / name
        if not path.is_file():
            if name in OPTIONAL_FILES:
                continue
            missing.append(name)
            if args.allow_missing:
                manifest[name] = {"bytes": None, "sha256": "MISSING"}
            continue
        data = path.read_bytes()
        manifest[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    out_path = root / args.out
    out_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"manifest 已寫入：{out_path}（{len(manifest)} 項）")
    if missing:
        print(f"缺失 {len(missing)} 項：{missing}")
        return 0 if args.allow_missing else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
