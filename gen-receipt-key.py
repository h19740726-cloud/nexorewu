#!/usr/bin/env python3
"""產生 T02 核定 receipt 的簽章金鑰對（ECDSA P-256）。

用法：
    python3 gen-receipt-key.py [輸出目錄]        # 預設：./t02-receipt-keys

產出：
    <輸出目錄>/t02-receipt-priv.pem   私鑰（**只給外部主體**，例如 GitHub Actions secret）
    <輸出目錄>/t02-receipt-pub.pem    公鑰（貼進 T02-discipline-audit.py 的 RECEIPT_PUBKEY_PEM）

🔴 鐵律（第 11 輪 §5 第 3 條「本機帳號之外的可信邊界」）：
  - 私鑰**不得**留在本機共用路徑、**不得**進版控、**不得**經過產出者。
  - 正確流程：由業主或外部主體產生 → 私鑰直接進外部 secret → 只有公鑰回到本機。
  - 公鑰貼進受驗腳本後，腳本 SHA256 會變 → 由「獨立驗收」核對受驗版本雜湊把關。
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

OPENSSL = "/usr/bin/openssl"


def main(argv: list[str]) -> int:
    out_dir = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path("t02-receipt-keys")
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = out_dir / "t02-receipt-priv.pem"
    pub = out_dir / "t02-receipt-pub.pem"

    subprocess.run(
        [OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(priv)],
        check=True,
    )
    subprocess.run(
        [OPENSSL, "ec", "-in", str(priv), "-pubout", "-out", str(pub)],
        check=True,
    )
    priv.chmod(0o600)

    print("金鑰對已產生：")
    print(f"  私鑰（只給外部主體，勿留本機）：{priv}")
    print(f"  公鑰（貼進受驗腳本）：{pub}")
    print()
    print("--- 公鑰內容（貼進 RECEIPT_PUBKEY_PEM 用）---")
    print(pub.read_text(encoding="utf-8"), end="")
    print("--- 公鑰結束 ---")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
