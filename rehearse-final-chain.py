#!/usr/bin/env python3
"""T02 簽發鏈 · 本地端到端彩排（測試金鑰版）。

在隔離的臨時目錄內，用**測試金鑰**完整走一遍最終簽發鏈——與
`.github/workflows/t02-sign-receipt.yml` 的步驟一一對應，差別只在
執行地點（本機 vs GitHub runner）與金鑰（測試 vs 正式 environment secret）。

步驟（對應 workflow）：
  S0  準備：造「測試公鑰版」稽核器（兩棵樹）、造 pending（真實 Stop 事件）、
      生成結果檔與申請檔
  S1  preflight（= workflow 的 preflight / sign 內重跑）→ payload.bin
  S2  簽名（= workflow 的有鑰步驟；純 openssl）→ sig.bin / pub.pem
  S3  assemble（= workflow 的組裝步驟）→ receipt.json
  S4  反例（清除前）：錯卡、錯版本、錯簽名、竄改受驗檔 → 全部拒＋pending 不變
  S5  正例：清除成功（rc=0、status=True）
  S6  反例（清除後）：重放 → 拒
  S7  反例：缺 key（空 T02_SIGNING_KEY 的簽名步驟）→ 拒
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

BASE = pathlib.Path(__file__).resolve().parent
PY = "/usr/bin/python3"
OPENSSL = "/usr/bin/openssl"

RESULTS: list[tuple[str, bool, str]] = []


def record(name: str, passed: bool, detail: str) -> None:
    RESULTS.append((name, passed, detail))
    print(f"{'✅' if passed else '❌'} {name}   [{detail}]")


def run(cmd, *, env=None, stdin=None, cwd=None):
    return subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, check=False, env=env, cwd=cwd
    )


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def env_for(root: pathlib.Path, extra=None) -> dict:
    env = os.environ.copy()
    for key in ("T02_TASK_ID", "T02_TRUSTED_COMMIT"):
        env.pop(key, None)
    env["T02_PENDING_PATH"] = str(root / "pending.json")
    env["T02_DISCIPLINE_LOG"] = str(root / "audit.jsonl")
    env["T02_TASKS_DIR"] = str(root / "tasks")
    env["T02_TASK_ID"] = "T02DEMO"
    env.update(extra or {})
    return env


def make_transcript(root: pathlib.Path) -> pathlib.Path:
    rows = [
        {"type": "message", "role": "user",
         "content": "<user_query>彩排：造一筆 pending</user_query>",
         "id": "u1", "sessionId": "session-r1"},
        {"type": "function_call", "name": "Edit", "arguments": "{}", "id": "e1",
         "sessionId": "session-r1"},
    ]
    path = root / "session-r1.jsonl"
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return path


def build_audit_with_test_pubkey(src: pathlib.Path, dst: pathlib.Path, pub_pem: str) -> str:
    text = src.read_text(encoding="utf-8")
    sentinel = 'RECEIPT_PUBKEY_PEM = ""'
    if sentinel in text:
        replaced = text.replace(sentinel, "RECEIPT_PUBKEY_PEM = " + json.dumps(pub_pem), 1)
    else:
        # 雙路相容（2026-10-16）：正式公鑰已安裝 → 整行替換成測試公鑰
        _lines = []
        _done = False
        for _line in text.splitlines(keepends=True):
            if not _done and _line.startswith("RECEIPT_PUBKEY_PEM = "):
                _lines.append("RECEIPT_PUBKEY_PEM = " + json.dumps(pub_pem) + "\n")
                _done = True
            else:
                _lines.append(_line)
        assert _done, "受驗稽核器找不到公鑰常數（結構已變動）"
        replaced = "".join(_lines)
    dst.write_text(replaced, encoding="utf-8")
    return sha256_of(dst)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="t02-rehearse-") as tmp:
        root = pathlib.Path(tmp)
        tag_tree = root / "tag-tree"
        trusted_tree = root / "trusted-tree"
        env_dir = root / "env"
        keys = root / "keys"
        for d in (tag_tree, trusted_tree, env_dir, keys, env_dir / "tasks"):
            d.mkdir(parents=True, exist_ok=True)
        (env_dir / "tasks" / "T02DEMO-demo.md").write_text("# 彩排示範卡\n", encoding="utf-8")

        # ---------- S0 準備 ----------
        # 測試金鑰對
        r = run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout",
                 "-out", str(keys / "priv.pem")])
        if r.returncode != 0:
            print("openssl genkey 失敗：", r.stderr)
            return 1
        run([OPENSSL, "ec", "-in", str(keys / "priv.pem"), "-pubout", "-out", str(keys / "pub.pem")])
        pub_pem = (keys / "pub.pem").read_text(encoding="utf-8")

        # 測試公鑰版稽核器（tag 樹與 trusted 樹各一份，逐位元相同）
        version = build_audit_with_test_pubkey(BASE / "T02-discipline-audit.py",
                                               tag_tree / "T02-discipline-audit.py", pub_pem)
        shutil.copy2(tag_tree / "T02-discipline-audit.py", trusted_tree / "T02-discipline-audit.py")
        # 簽發工具與 workflow 檔（兩樹對應路徑）
        shutil.copy2(BASE / "t02-ci-payload.py", tag_tree / "t02-ci-payload.py")
        shutil.copy2(BASE / "t02-ci-payload.py", trusted_tree / "t02-ci-payload.py")
        (tag_tree / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
        shutil.copy2(BASE / "github-actions" / "t02-sign-receipt.yml",
                     tag_tree / ".github" / "workflows" / "t02-sign-receipt.yml")
        (trusted_tree / "github-actions").mkdir(parents=True, exist_ok=True)
        shutil.copy2(BASE / "github-actions" / "t02-sign-receipt.yml",
                     trusted_tree / "github-actions" / "t02-sign-receipt.yml")
        # 本地簽發工具（供「錯版本」情境使用；載入 trusted 樹的稽核器）
        shutil.copy2(BASE / "sign-receipt.py", trusted_tree / "sign-receipt.py")

        # 造 pending（真實 Stop 事件：有修改操作、零 Skill → BLOCK 並記 pending）
        transcript = make_transcript(env_dir)
        event = {
            "hook_event_name": "Stop", "session_id": "session-r1", "generation_id": "g1",
            "task_id": "T02DEMO",
            "transcript_path": str(transcript), "stop_hook_active": True,
        }
        r = run([PY, str(tag_tree / "T02-discipline-audit.py")],
                env=env_for(env_dir), stdin=json.dumps(event))
        pending = json.loads((env_dir / "pending.json").read_text(encoding="utf-8"))
        pending_ids = sorted(str(v.get("pending_id") or "") for v in pending.values())
        record("S0 造 pending（Stop 事件 → FAIL_OPEN_RETRY + pending）",
               bool(pending_ids) and "FAIL_OPEN_RETRY" in r.stderr,
               f"pending_ids={pending_ids} rc={r.returncode}")

        # 結果檔（demo verdict fixture）——用工具生成（單一來源），兩個樹各一份、逐位元相同
        verdict_src = env_dir / "T02-DEMO-verdict.md"
        r = run([PY, str(BASE / "make-sign-request.py"),
                 "--audit", str(tag_tree / "T02-discipline-audit.py"),
                 "--make-verdict", str(verdict_src), "--verdict-task", "T02DEMO"])
        assert r.returncode == 0, r.stderr
        for base in (tag_tree, trusted_tree):
            shutil.copy2(verdict_src, base / "T02-DEMO-verdict.md")

        # 申請檔——用工具生成（version／pending_ids／result_sha256 皆自權威來源算出）
        req_out = tag_tree / "T02-sign-request.json"
        r = run([PY, str(BASE / "make-sign-request.py"),
                 "--audit", str(tag_tree / "T02-discipline-audit.py"),
                 "--pending-store", str(env_dir / "pending.json"),
                 "--task-id", "T02DEMO",
                 "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                 "--out", str(req_out)])
        record("S0b 生成申請檔（make-sign-request.py）", r.returncode == 0,
               f"rc={r.returncode} {(r.stderr.strip() or r.stdout.strip())[:80]}")
        if r.returncode != 0:
            return finish()
        shutil.copy2(req_out, trusted_tree / "T02-sign-request.json")

        # ---------- S1 preflight ----------
        fake_trusted_commit = "a" * 40
        ci_env = env_for(env_dir, {
            "T02_TRUSTED_COMMIT": fake_trusted_commit,
            "GITHUB_RUN_ID": "900001",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": "refs/tags/t02-sign-rehearsal",
        })
        payload_path = env_dir / "payload.bin"
        r = run([PY, str(trusted_tree / "t02-ci-payload.py"), "preflight",
                 "--tag-tree", str(tag_tree), "--trusted-tree", str(trusted_tree),
                 "--payload-out", str(payload_path)], env=ci_env)
        ok = r.returncode == 0 and payload_path.is_file()
        record("S1 preflight（雙源比對＋申請檔自洽 → payload）", ok,
               f"rc={r.returncode} payload={sha256_of(payload_path)[:16] if ok else '-'}")
        if not ok:
            print(r.stdout[-2000:], r.stderr[-2000:])
            return finish()

        # ---------- S2 簽名（模擬 workflow 有鑰步驟） ----------
        r1 = run([OPENSSL, "pkey", "-in", str(keys / "priv.pem"), "-pubout",
                  "-out", str(env_dir / "pub.out.pem")])
        r2 = run([OPENSSL, "dgst", "-sha256", "-sign", str(keys / "priv.pem"),
                  "-out", str(env_dir / "sig.bin"), str(payload_path)])
        record("S2 簽名（openssl pkey/dgst）", r1.returncode == 0 and r2.returncode == 0,
               f"rc={r1.returncode}/{r2.returncode}")

        # ---------- S3 assemble ----------
        receipt_path = env_dir / "receipt.json"
        r = run([PY, str(trusted_tree / "t02-ci-payload.py"), "assemble",
                 "--trusted-tree", str(trusted_tree),
                 "--payload-bin", str(payload_path), "--sig-bin", str(env_dir / "sig.bin"),
                 "--pub-pem", str(env_dir / "pub.out.pem"), "--receipt-out", str(receipt_path)])
        record("S3 assemble（組 receipt）", r.returncode == 0 and receipt_path.is_file(),
               f"rc={r.returncode}")

        # ---------- S4 反例（清除前；每條都要：拒絕＋pending 位元組不變） ----------
        pending_before = sha256_of(env_dir / "pending.json")

        def try_clear(label, args, expect_reject=True):
            nonlocal pending_before
            rr = run([PY, str(trusted_tree / "T02-discipline-audit.py"), *args], env=env_for(env_dir))
            after = sha256_of(env_dir / "pending.json")
            intact = after == pending_before
            if expect_reject:
                passed = rr.returncode != 0 and intact
                record(label, passed, f"rc={rr.returncode} pending_intact={intact} err={rr.stderr.strip()[:80]}")
            else:
                passed = rr.returncode == 0 and not intact
                record(label, passed, f"rc={rr.returncode} out={rr.stdout.strip()[:80]}")
            pending_before = after
            return rr

        # a) 錯卡：receipt 綁 T02DEMO，目標換 T02OTHER
        try_clear("S4a 錯卡（receipt 卡號≠目標）被拒",
                  ["--clear", "T02OTHER", "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                   "--receipt", str(receipt_path), "--by", "rehearsal"])

        # b) 錯版本：用本地簽發工具簽一份 version 錯誤的 receipt
        wrong_path = env_dir / "receipt-wrong-version.json"
        run([PY, str(trusted_tree / "sign-receipt.py"), "--key", str(keys / "priv.pem"),
             "--task-id", "T02DEMO", "--version", "0" * 64,
             "--result", str(tag_tree / "T02-DEMO-verdict.md"),
             "--pending-ids", ",".join(pending_ids), "--nonce", "wrongver",
             "--receipt-out", str(wrong_path)])
        try_clear("S4b 錯版本（version≠執行檔）被拒",
                  ["--clear", "T02DEMO", "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                   "--receipt", str(wrong_path), "--by", "rehearsal"])

        # c) 錯簽名：改一個 byte
        tampered = env_dir / "receipt-tampered.json"
        raw = json.loads(receipt_path.read_text(encoding="utf-8"))
        sig = raw["signature_b64"]
        raw["signature_b64"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        tampered.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try_clear("S4c 錯簽名（簽章被篡改）被拒",
                  ["--clear", "T02DEMO", "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                   "--receipt", str(tampered), "--by", "rehearsal"])

        # d) 竄改受驗檔（tag 樹的申請檔被改 → preflight 雙源比對拒絕）
        req_path = tag_tree / "T02-sign-request.json"
        backup = req_path.read_text(encoding="utf-8")
        mutated = json.loads(backup)
        mutated["pending_ids"] = sorted(pending_ids + ["deadbeefcafe"])
        req_path.write_text(json.dumps(mutated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        r = run([PY, str(trusted_tree / "t02-ci-payload.py"), "preflight",
                 "--tag-tree", str(tag_tree), "--trusted-tree", str(trusted_tree),
                 "--payload-out", str(env_dir / "payload.mut.bin")], env=ci_env)
        record("S4d 竄改受驗檔（tag 樹 request 被改 → preflight 拒）", r.returncode != 0,
               f"rc={r.returncode} err={(r.stderr.strip().splitlines() or [''])[1][:90]}")
        req_path.write_text(backup, encoding="utf-8")

        # ---------- S5 正例：清除成功 ----------
        try_clear("S5 正例（合法 receipt）清除成功",
                  ["--clear", "T02DEMO", "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                   "--receipt", str(receipt_path), "--by", "rehearsal"],
                  expect_reject=False)
        rr = run([PY, str(trusted_tree / "T02-discipline-audit.py"), "--status", "T02DEMO"],
                 env=env_for(env_dir))
        status = json.loads(rr.stdout)
        record("S5b status（completion_allowed=True）", status.get("completion_allowed") is True,
               f"status={status.get('completion_allowed')}")

        # ---------- S6 反例（清除後）：重放 ----------
        try_clear("S6 重放（同 receipt 第二次）被拒",
                  ["--clear", "T02DEMO", "--result", str(tag_tree / "T02-DEMO-verdict.md"),
                   "--receipt", str(receipt_path), "--by", "rehearsal"])

        # ---------- S7 缺 key（模擬 workflow 有鑰步驟的空 key 分支） ----------
        r = subprocess.run(
            ["bash", "-c",
             'set -euo pipefail\n'
             'if [ -z "${T02_SIGNING_KEY:-}" ]; then\n'
             '  echo "environment secret T02_SIGNING_KEY 未設定 → 拒絕簽發" >&2\n'
             '  exit 1\n'
             'fi\n'
             'echo "should-not-reach"'],
            capture_output=True, text=True, check=False, env={**os.environ, "T02_SIGNING_KEY": ""},
        )
        record("S7 缺 key（空 secret → 簽名步驟拒絕）",
               r.returncode == 1 and "拒絕簽發" in r.stderr,
               f"rc={r.returncode}")

    return finish()


def finish() -> int:
    ok = sum(1 for _, passed, _ in RESULTS if passed)
    print(f"\n{ok}/{len(RESULTS)} 通過")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
