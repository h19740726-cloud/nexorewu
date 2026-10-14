#!/usr/bin/env python3
"""用私鑰簽發一份 T02 核定 receipt。

用法：
    python3 sign-receipt.py --key <priv.pem> --task-id T02 --version <受驗腳本S256> \
        --result <驗收結果檔> --receipt-out <receipt.json> \
        [--pending-ids a,b,c] [--nonce <hex>] [--issued-at <iso>]

- `--pending-ids` 省略時 → 讀 pending 存放區（`T02_PENDING_PATH`）自動算；僅本機可行。
  外部主體（GitHub Actions）**必須**明確傳入。
- payload 的正規化形式**直接 import 自受驗腳本**（單一真相源），
  避免簽端與驗端各寫一份而位元組不一致。

🔴 私鑰只在外部主體手中；本機（產出者）拿不到 → 無法自行簽發 receipt。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

OPENSSL = "/usr/bin/openssl"
AUDIT = pathlib.Path(__file__).with_name("T02-discipline-audit.py")


def load_audit_module():
    """載入受驗腳本，取用它的 `canonical_payload` / `pubkey_fingerprint`（單一真相源）。"""
    spec = importlib.util.spec_from_file_location("t02_audit_module", AUDIT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def derive_public_pem(priv_path: pathlib.Path) -> str:
    proc = subprocess.run(
        [OPENSSL, "ec", "-in", str(priv_path), "-pubout"],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout


def collect_pending_ids(pending_path: pathlib.Path, task_id: str) -> list[str]:
    if not pending_path.is_file():
        return []
    try:
        data = json.loads(pending_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    ids = [
        str(item.get("pending_id") or "")
        for item in data.values()
        if isinstance(item, dict) and str(item.get("task_id") or "") == task_id
    ]
    return sorted(i for i in ids if i)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="簽發 T02 核定 receipt")
    parser.add_argument("--key", required=True, help="私鑰 PEM 路徑（外部主體持有）")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--version", required=True, help="受驗腳本 SHA256")
    parser.add_argument("--result", default="", help="驗收結果檔路徑（取其 SHA256）")
    parser.add_argument("--result-sha256", dest="result_sha256", default="",
                        help="直接給驗收結果的 SHA256（外部主體沒有檔案時用）")
    parser.add_argument("--receipt-out", required=True, help="receipt 輸出檔路徑")
    parser.add_argument("--pending-ids", default="", help="逗號分隔；省略＝讀 pending 存放區")
    parser.add_argument("--nonce", default="", help="省略＝自動產生 uuid")
    parser.add_argument("--issued-at", default="", help="省略＝現在時間（UTC）")
    args = parser.parse_args(argv[1:])

    audit = load_audit_module()

    if args.pending_ids.strip():
        pending_ids = [s for s in (x.strip() for x in args.pending_ids.split(",")) if s]
    else:
        pending_path = pathlib.Path(
            __import__("os").environ.get("T02_PENDING_PATH", str(AUDIT.parent / "T02-pending-violations.json"))
        )
        pending_ids = collect_pending_ids(pending_path, args.task_id)

    result_path = pathlib.Path(args.result) if args.result else None
    if args.result_sha256.strip():
        result_sha = args.result_sha256.strip().lower()
    elif result_path is not None:
        if not result_path.is_file():
            print(f"sign refused: 驗收結果檔不存在：{result_path}", file=sys.stderr)
            return 3
        result_sha = hashlib.sha256(result_path.read_bytes()).hexdigest()
    else:
        print("sign refused: 必須給 --result 或 --result-sha256", file=sys.stderr)
        return 3

    payload = {
        "task_id": args.task_id,
        "version": args.version,
        "pending_ids": pending_ids,
        "result_sha256": result_sha,
        "issued_at": args.issued_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "nonce": args.nonce or uuid.uuid4().hex,
    }
    data = audit.canonical_payload(payload)

    priv_path = pathlib.Path(args.key)
    if not priv_path.is_file():
        print(f"sign refused: 私鑰不存在：{priv_path}", file=sys.stderr)
        return 3

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        data_file = tmpdir / "payload.bin"
        sig_file = tmpdir / "sig.bin"
        data_file.write_bytes(data)
        subprocess.run(
            [OPENSSL, "dgst", "-sha256", "-sign", str(priv_path), "-out", str(sig_file), str(data_file)],
            check=True,
        )
        signature = sig_file.read_bytes()

    pub_pem = derive_public_pem(priv_path)
    receipt = {
        "schema": 1,
        "payload_b64": base64.b64encode(data).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_fingerprint": audit.pubkey_fingerprint(pub_pem),
    }
    out_path = pathlib.Path(args.receipt_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"receipt 已簽發：{out_path}")
    print(f"  task_id       = {payload['task_id']}")
    print(f"  version       = {payload['version']}")
    print(f"  pending_ids   = {payload['pending_ids']}")
    print(f"  result_sha256 = {payload['result_sha256']}")
    print(f"  nonce         = {payload['nonce']}")
    print(f"  fingerprint   = {receipt['key_fingerprint']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
