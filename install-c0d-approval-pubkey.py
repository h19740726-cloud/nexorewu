#!/usr/bin/env python3
"""T02 C0d ①：把「獨立核准公鑰」裝進受驗稽核器（APPROVAL_PUBKEY_PEM）。

依 Codex 交接檔 `T02-c0d-approval-handoff.md`（2026-10-17）施工：

- 預期公鑰檔 SHA256 與指紋「一律從交接檔即時解析」，腳本內不手抄任何長雜湊；
- 只接受 PEM 公鑰（含 "PRIVATE" 字樣一律拒絕）；
- 改檔前先驗「受驗稽核器＝交接檔指定的 C0d 基底版本」；
- 冪等：已安裝同一把公鑰時不改動、退出 0；
- 失敗一律 fail-closed：拒絕並以非零碼退出，不安裝任何東西；
- 寫入後以 AST 重新解析回讀驗證；驗證不過即還原備份並拒絕。

本腳本只讀公鑰檔；不觸碰、不尋找、不讀取任何私鑰。
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HANDOFF = HERE / "T02-c0d-approval-handoff.md"
PUBKEY = HERE / "T02-c0d-approval-pubkey.pem"
AUDITOR = HERE / "T02-discipline-audit.py"
BACKUP_DIR = HERE / "_備份"
CONST = "APPROVAL_PUBKEY_PEM"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(pem: str) -> str:
    """與稽核器 pubkey_fingerprint() 同演算法：PEM 正規化後 SHA256 前 16 位。"""
    normalized = "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def refuse(msg: str) -> None:
    print(f"REFUSED: {msg}", file=sys.stderr)
    sys.exit(2)


def extract_const_value(source: str, const_name: str) -> str:
    """以 AST 取出 `const_name = "..."` 的字串值（找不到或不是字串即拒絕）。"""
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == const_name for t in node.targets
        ):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, SyntaxError) as exc:
                refuse(f"{const_name} 不是字串常數：{exc}")
            if not isinstance(value, str):
                refuse(f"{const_name} 不是字串常數（型別 {type(value).__name__}）")
            return value
    refuse(f"在受驗稽核器找不到 {const_name} 常數（結構已變動，需人工確認）")


def main() -> None:
    # ── 1) 期望值：只從交接檔解析（零手抄） ─────────────────────────────
    if not HANDOFF.is_file():
        refuse(f"交接檔不存在：{HANDOFF}")
    handoff = HANDOFF.read_text(encoding="utf-8")

    def parse(pattern: str, what: str) -> str:
        match = re.search(pattern, handoff)
        if not match:
            refuse(f"交接檔解析不到{what}（格式已變動，需人工確認）")
        return match.group(1)

    expected_pubkey_sha = parse(r"檔案 SHA256[：:]\s*`([0-9a-f]{64})`", "公鑰檔 SHA256")
    expected_fp = parse(r"稽核器指紋[：:]\s*`([0-9a-f]{16})`", "稽核器指紋")
    expected_base_sha = parse(r"C0d 稽核器 SHA256[：:]\s*`([0-9a-f]{64})`", "C0d 稽核器 SHA256")

    print("【期望值｜解析自交接檔】")
    print(f"  公鑰檔 SHA256 : {expected_pubkey_sha}")
    print(f"  稽核器指紋    : {expected_fp}")
    print(f"  C0d 基底雜湊  : {expected_base_sha}")
    print()

    # ── 2) 公鑰檔驗證 ───────────────────────────────────────────────────
    if not PUBKEY.is_file():
        refuse(f"公鑰檔不存在：{PUBKEY}")
    pubkey_bytes = PUBKEY.read_bytes()
    got_pubkey_sha = sha256_bytes(pubkey_bytes)
    if got_pubkey_sha != expected_pubkey_sha:
        refuse(f"公鑰檔 SHA256 不符（got={got_pubkey_sha}）")
    pem = pubkey_bytes.decode("utf-8")
    if "PRIVATE" in pem:
        refuse("公鑰檔含 'PRIVATE' 字樣（疑似私鑰），拒絕處理")
    if not pem.lstrip().startswith("-----BEGIN PUBLIC KEY-----"):
        refuse("公鑰檔不是 PEM PUBLIC KEY")
    got_fp = fingerprint(pem)
    if got_fp != expected_fp:
        refuse(f"公鑰指紋不符（got={got_fp}）")
    print("【公鑰檔驗證】SHA256 相符、指紋相符、無私鑰字樣 ✅")
    print()

    # ── 3) 讀受驗稽核器，判斷狀態（冪等） ─────────────────────────────
    src_bytes = AUDITOR.read_bytes()
    src = src_bytes.decode("utf-8")
    current = extract_const_value(src, CONST)

    if current == pem:
        print("【狀態】已安裝同一把公鑰（冪等）→ 不改動任何位元組。")
        print(f"  稽核器目前 SHA256：{sha256_bytes(src_bytes)}")
        print(f"  已裝指紋          ：{fingerprint(current)}")
        return

    if current != "":
        refuse(
            "受驗稽核器的 APPROVAL_PUBKEY_PEM 非空且非本次公鑰（"
            f"現值指紋={fingerprint(current)}）→ 拒絕覆寫既有信任根"
        )

    got_base_sha = sha256_bytes(src_bytes)
    if got_base_sha != expected_base_sha:
        refuse(
            "受驗稽核器不是交接檔指定的 C0d 基底版本"
            f"（got={got_base_sha}）→ 拒絕安裝"
        )

    # ── 4) 備份後寫入 ──────────────────────────────────────────────────
    if not BACKUP_DIR.exists():
        BACKUP_DIR.mkdir()
    backup = BACKUP_DIR / f"T02-discipline-audit.py.c0d-preinstall-{got_base_sha[:12]}"
    shutil.copy2(AUDITOR, backup)

    new_line = f"{CONST} = {json.dumps(pem)}\n"
    lines = src.splitlines(keepends=True)
    hit = None
    for index, line in enumerate(lines):
        if line.startswith(CONST + " = "):
            hit = index
            break
    if hit is None:
        refuse("找不到 APPROVAL_PUBKEY_PEM 指派行（與 AST 結果矛盾）")
    lines[hit] = new_line
    AUDITOR.write_bytes("".join(lines).encode("utf-8"))

    # ── 5) 回讀驗證（AST 重解析；不過即還原） ─────────────────────────
    reread = AUDITOR.read_text(encoding="utf-8")
    installed = extract_const_value(reread, CONST)
    installed_fp = fingerprint(installed)
    if installed != pem or installed_fp != expected_fp:
        shutil.copy2(backup, AUDITOR)
        refuse(
            "寫入後回讀驗證失敗（已還原備份）"
            f"（installed_fp={installed_fp}）"
        )

    new_sha = sha256_bytes(AUDITOR.read_bytes())
    print("【安裝完成】")
    print(f"  公鑰指紋          : {installed_fp}")
    print(f"  安裝前 SHA256     : {got_base_sha}")
    print(f"  安裝後 SHA256     : {new_sha}")
    print(f"  備份              : {backup}")
    print()
    print("下一手（機器重算）：")
    print(f"  shasum -a 256 {AUDITOR.name}   # 應為 {new_sha}")


if __name__ == "__main__":
    main()
