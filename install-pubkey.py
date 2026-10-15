#!/usr/bin/env python3
"""把正式公鑰安裝進 T02 稽核器（最終整改④：信任根安裝）。

安裝位置：`T02-discipline-audit.py` 的**內嵌常數** `RECEIPT_PUBKEY_PEM`。
    - 公鑰以程式碼常數形式存在（無獨立檔案、無檔案權限問題）；
    - 執行期**不讀**環境變數、工作目錄、可寫檔、CLI 參數（由 r22 測試與 M16／M17 突變鎖定）；
    - 完整性由「受驗腳本 SHA256 鎖版 ＋ 獨立驗收核對公鑰指紋」把關。

用法：
    python3 install-pubkey.py --pubkey <pub.pem> [--audit <稽核器路徑>]
    python3 install-pubkey.py --check --pubkey <pub.pem> [--audit <稽核器路徑>]

行為：
    - 僅在常數目前為**空**（`RECEIPT_PUBKEY_PEM = ""`，＝尚未安裝）時安裝；
      已安裝（非空）時一律拒絕（換鍵屬重大變更，需人工處理與重新鎖版）。
    - 安裝前驗證 PEM 合法且為 EC P-256 公鑰（openssl 解析）。
    - 安裝後載入新腳本，輸出：公鑰指紋（16 hex）、正規化 PEM 的完整 SHA256、
      安裝後稽核器 SHA256（供鎖版表）。
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

OPENSSL = "/usr/bin/openssl"
SENTINEL = 'RECEIPT_PUBKEY_PEM = ""'
PREFIX = "RECEIPT_PUBKEY_PEM = "


def normalize_pem(pem: str) -> str:
    """與稽核器 `pubkey_fingerprint()` 相同的正規化（去空白行、行首尾 trim）。"""
    return "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())


def validate_pubkey(pem: str) -> tuple[bool, str]:
    """以 openssl 驗證 PEM 為 EC P-256 公鑰。回 (是否合法, 說明)。"""
    proc = subprocess.run(
        [OPENSSL, "pkey", "-pubin", "-noout", "-text"],
        input=pem.encode("utf-8"), capture_output=True,
    )
    if proc.returncode != 0:
        return False, "openssl 無法解析此公鑰 PEM"
    text = proc.stdout.decode("utf-8", errors="replace")
    if "prime256v1" not in text:
        return False, f"公鑰不是 P-256 曲線（openssl 輸出未含 prime256v1）"
    return True, ""


def load_module(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("audit_install_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def current_constant_line(audit_path: pathlib.Path) -> str | None:
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if line.startswith(PREFIX):
            return line
    return None


def install(audit_path: pathlib.Path, pub_pem: str) -> tuple[dict | None, str]:
    line = current_constant_line(audit_path)
    if line is None:
        return None, "受驗稽核器找不到公鑰常數（結構已變動）"
    if line != SENTINEL:
        return None, "公鑰常數已非空（已安裝過）；換鍵屬重大變更，請人工處理並重新鎖版"
    src = audit_path.read_text(encoding="utf-8")
    new_line = PREFIX + json.dumps(pub_pem.rstrip("\n") + "\n")
    patched = src.replace(SENTINEL, new_line, 1)
    backup = audit_path.read_bytes()
    audit_path.write_text(patched, encoding="utf-8")
    try:
        module = load_module(audit_path)
        fingerprint = module.pubkey_fingerprint(pub_pem)
        embedded = module.RECEIPT_PUBKEY_PEM
    except Exception as exc:  # noqa: BLE001 - 安裝後自檢失敗要回滾
        audit_path.write_bytes(backup)
        return None, f"安裝後自檢失敗（已回滾）：{exc}"
    if module.pubkey_fingerprint(embedded) != fingerprint:
        audit_path.write_bytes(backup)
        return None, "安裝後自檢失敗：內嵌公鑰指紋與提供公鑰不符（已回滾）"
    info = {
        "installed": True,
        "audit_path": str(audit_path),
        "fingerprint": fingerprint,
        "normalized_pem_sha256": hashlib.sha256(normalize_pem(pub_pem).encode("utf-8")).hexdigest(),
        "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
    }
    return info, ""


def check(audit_path: pathlib.Path, pub_pem: str) -> tuple[dict | None, str]:
    line = current_constant_line(audit_path)
    if line is None:
        return None, "受驗稽核器找不到公鑰常數（結構已變動）"
    if line == SENTINEL:
        return None, "尚未安裝公鑰（常數為空）"
    embedded_pem = json.loads(line[len(PREFIX):])
    module = load_module(audit_path)
    embedded_fp = module.pubkey_fingerprint(embedded_pem)
    given_fp = module.pubkey_fingerprint(pub_pem)
    info = {
        "installed": True,
        "match": embedded_fp == given_fp,
        "embedded_fingerprint": embedded_fp,
        "given_fingerprint": given_fp,
        "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
    }
    return info, ""


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="T02 稽核器公鑰安裝工具")
    parser.add_argument("--pubkey", required=True, help="公鑰 PEM 檔路徑")
    parser.add_argument("--audit", default="", help="稽核器路徑（預設：同目錄 T02-discipline-audit.py）")
    parser.add_argument("--check", action="store_true", help="只核對現狀，不寫入")
    args = parser.parse_args(argv[1:])

    audit_path = pathlib.Path(args.audit) if args.audit else (
        pathlib.Path(__file__).resolve().parent / "T02-discipline-audit.py"
    )
    pub_path = pathlib.Path(args.pubkey)
    if not pub_path.is_file():
        print(json.dumps({"ok": False, "error": f"公鑰檔不存在：{pub_path}"}, ensure_ascii=False))
        return 2
    pub_pem = pub_path.read_text(encoding="utf-8")

    ok, why = validate_pubkey(pub_pem)
    if not ok:
        print(json.dumps({"ok": False, "error": why}, ensure_ascii=False))
        return 3

    if args.check:
        info, error = check(audit_path, pub_pem)
    else:
        info, error = install(audit_path, pub_pem)
    if error:
        print(json.dumps({"ok": False, "error": error}, ensure_ascii=False))
        return 3
    print(json.dumps({"ok": True, **info}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
