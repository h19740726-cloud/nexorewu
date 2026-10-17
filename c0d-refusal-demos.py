#!/usr/bin/env python3
"""C0d ② 反例實證：以**正式安裝版稽核器位元**證明「WorkBuddy 自清必被拒」。

環境：`T02-c0d-evidence/refusals/work/`（副本 pending＝正式 store 位元複製；
稽核器＝正式安裝版位元複製；真 receipt＝C0c 產物複製）。正式 store 全程不參與。

三幕（每幕都要：拒絕＋pending 位元組不變）：
  D1 缺核准：合法 receipt、無核准檔 → 拒（獨立核准檔不存在）
  D2 偽造核准（誠實他鑰指紋）：以拋棄式他鑰自簽核准 → 拒（指紋不符）
  D3 偽造核准（冒充正式指紋）：指紋欄冒填正式核准指紋、簽章為他鑰所簽 → 拒（簽章驗證失敗）

輸出：三幕 log ＋ summary.txt（全落 `T02-c0d-evidence/refusals/`）。
若任何一幕「清除成功」＝本腳本 rc=1（此為安全失效訊號，正常情況永不發生）。
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDITOR = HERE / "T02-discipline-audit.py"
STORE = HERE / "T02-pending-violations.json"
RECEIPT = HERE / "T02-receipt-38909842135" / "receipt.json"
RESULT = HERE / "T02-sign-verdict.md"
EVID = HERE / "T02-c0d-evidence" / "refusals"
WORK = EVID / "work"
PY = "/usr/bin/python3"
OPENSSL = "/usr/bin/openssl"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(pem: str) -> str:
    """同稽核器 pubkey_fingerprint：PEM 正規化後 SHA256 前 16 位。"""
    normalized = "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def extract_const(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, str):
                return value
    raise SystemExit(f"找不到常數 {name}")


def load_audit_module():
    spec = importlib.util.spec_from_file_location("t02_demo_module", AUDITOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def main() -> int:
    EVID.mkdir(parents=True, exist_ok=True)
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    tasks = WORK / "tasks"
    tasks.mkdir()
    (tasks / "T02-c0d-demo.md").write_text("# demo\n", encoding="utf-8")

    # 隔離副本（位元複製）
    shutil.copy2(AUDITOR, WORK / "T02-discipline-audit.py")
    shutil.copy2(STORE, WORK / "pending.json")
    shutil.copy2(RECEIPT, WORK / "receipt.json")
    shutil.copy2(RESULT, WORK / "T02-sign-verdict.md")
    (WORK / "audit.jsonl").write_text("", encoding="utf-8")

    audit_src = AUDITOR.read_text(encoding="utf-8")
    approval_pem = extract_const(audit_src, "APPROVAL_PUBKEY_PEM")
    prod_fp = fingerprint(approval_pem)
    receipt_raw = json.loads((WORK / "receipt.json").read_text(encoding="utf-8"))
    receipt_payload = json.loads(base64.b64decode(receipt_raw["payload_b64"]).decode("utf-8"))
    store = json.loads((WORK / "pending.json").read_text(encoding="utf-8"))
    store_ids = sorted(
        str(v.get("pending_id") or "")
        for v in store.values()
        if isinstance(v, dict) and str(v.get("task_id") or "") == "T02"
    )

    # 拋棄式他鑰（演示用；非任何正式金鑰）
    attacker = WORK / "attacker"
    attacker.mkdir()
    subprocess.run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                    "-out", str(attacker / "priv.pem")], check=True, capture_output=True)
    subprocess.run([OPENSSL, "ec", "-in", str(attacker / "priv.pem"), "-pubout",
                    "-out", str(attacker / "pub.pem")], check=True, capture_output=True)
    attacker_pub = (attacker / "pub.pem").read_text(encoding="utf-8")
    attacker_fp = fingerprint(attacker_pub)

    # 核准 payload（六欄契約，綁定真 receipt）＋ 以他鑰簽章
    audit_module = load_audit_module()
    payload = {
        "task_id": receipt_payload["task_id"],
        "version": receipt_payload["version"],
        "pending_ids": receipt_payload["pending_ids"],
        "result_sha256": receipt_payload["result_sha256"],
        "receipt_sha256": sha256_of(WORK / "receipt.json"),
        "receipt_nonce": receipt_payload["nonce"],
    }
    data = audit_module.canonical_payload(payload)
    data_file = WORK / "approval-payload.bin"
    sig_file = WORK / "approval-payload.sig"
    data_file.write_bytes(data)
    subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", str(attacker / "priv.pem"),
                    "-out", str(sig_file), str(data_file)], check=True, capture_output=True)
    signature_b64 = base64.b64encode(sig_file.read_bytes()).decode("ascii")
    payload_b64 = base64.b64encode(data).decode("ascii")

    def write_doc(path: Path, key_fingerprint: str) -> None:
        doc = {
            "schema": 1,
            "payload_b64": payload_b64,
            "signature_b64": signature_b64,
            "key_fingerprint": key_fingerprint,
        }
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    write_doc(WORK / "approval-D2.json", attacker_fp)
    write_doc(WORK / "approval-D3.json", prod_fp)

    env = os.environ.copy()
    env["T02_PENDING_PATH"] = str(WORK / "pending.json")
    env["T02_DISCIPLINE_LOG"] = str(WORK / "audit.jsonl")
    env["T02_TASKS_DIR"] = str(WORK / "tasks")

    summary: list[str] = []
    summary.append("=== C0d ② 反例實證 · 正式產物（機器重算值） ===")
    summary.append(f"稽核器（隔離副本）SHA256 : {sha256_of(WORK / 'T02-discipline-audit.py')}")
    summary.append(f"receipt SHA256            : {sha256_of(WORK / 'receipt.json')}")
    summary.append(f"receipt version 綁定      : {receipt_payload['version']}")
    summary.append(f"receipt nonce             : {receipt_payload['nonce']}")
    summary.append(f"正式核准公鑰指紋（稽核器內嵌）: {prod_fp}")
    summary.append(f"他鑰指紋（拋棄式演示金鑰）    : {attacker_fp}")
    summary.append(f"pending 集合（{len(store_ids)} 筆）與 receipt 綁定集合相等: "
                   f"{store_ids == sorted(str(x) for x in receipt_payload['pending_ids'])}")
    summary.append("")

    def demo(name: str, args: list[str], expect: str) -> tuple[str, bool]:
        before = sha256_of(WORK / "pending.json")
        proc = subprocess.run(
            [PY, str(WORK / "T02-discipline-audit.py"), *args],
            capture_output=True, text=True, env=env,
        )
        after = sha256_of(WORK / "pending.json")
        intact = before == after
        refused = proc.returncode != 0
        matched = expect in proc.stderr
        passed = refused and intact and matched
        log = "\n".join([
            f"$ {PY} T02-discipline-audit.py {' '.join(args)}",
            f"（隔離：T02_PENDING_PATH={env['T02_PENDING_PATH']}）",
            "",
            f"rc = {proc.returncode}",
            "",
            "--- stderr ---",
            proc.stderr.strip(),
            "",
            f"pending SHA256（跑前）: {before}",
            f"pending SHA256（跑後）: {after}",
            f"pending 位元不變: {intact}",
            f"預期拒絕語「{expect}」出現: {matched}",
            f"本幕判定: {'✅ 拒絕且未動 pending' if passed else '❌ 未達預期'}",
        ])
        (EVID / f"{name}.log").write_text(log + "\n", encoding="utf-8")
        summary.append(f"{name}: rc={proc.returncode} 未動={intact} 預期語命中={matched} "
                       f"=> {'✅' if passed else '❌'}")
        return name, passed

    r1 = demo("D1-missing-approval",
              ["--clear", "T02", "--result", str(WORK / "T02-sign-verdict.md"),
               "--receipt", str(WORK / "receipt.json"), "--by", "WorkBuddy"],
              "獨立核准檔不存在")
    r2 = demo("D2-forged-approval-fingerprint",
              ["--clear", "T02", "--result", str(WORK / "T02-sign-verdict.md"),
               "--receipt", str(WORK / "receipt.json"),
               "--approval", str(WORK / "approval-D2.json"), "--by", "WorkBuddy"],
              "公鑰指紋")
    r3 = demo("D3-forged-fingerprint-signature",
              ["--clear", "T02", "--result", str(WORK / "T02-sign-verdict.md"),
               "--receipt", str(WORK / "receipt.json"),
               "--approval", str(WORK / "approval-D3.json"), "--by", "WorkBuddy"],
              "簽章驗證失敗")

    ok = all(p for _, p in (r1, r2, r3))
    summary.append("")
    summary.append(f"總結：{sum(1 for _, p in (r1, r2, r3) if p)}/3 幕全部拒絕且 pending 未動 "
                   f"（{'✅ WorkBuddy 自清必被拒' if ok else '❌ 安全失效，需立即排查'}）")
    (EVID / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
