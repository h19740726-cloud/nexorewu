#!/usr/bin/env python3
"""T02 第 12 輪 e2e：用**真實工具鏈**走完整流程。

工具鏈：`gen-receipt-key.py` →（公鑰內嵌副本）→ `sign-receipt.py` → 受驗腳本 `--clear`。

情境：
  E1 建立 pending（跑 Stop hook）
  E2 攻擊 A：產出者自設 `T02_REVIEW_TOKEN_SHA256` → 清 pending 應被拒絕
  E3 攻擊 B：用「另一把私鑰」簽的 receipt → 拒絕
  E6 缺核准（C0d 核心）：合法 receipt、無獨立核准 → 拒絕
  E4 正向  ：receipt＋獨立核准**雙簽** → 清除成功
  E5 重放  ：還原 pending 後，同一組 receipt＋核准再用 → 拒絕（nonce 已用）

🔴 C0d（2026-10-17）：清除需雙信任根（receipt＋獨立核准）；本腳本的受驗副本
   **兩個公鑰常數都換成測試金鑰**。
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

BASE = pathlib.Path("/Users/wulieqiang/AI協作/work/codex")
AUDIT = BASE / "T02-discipline-audit.py"
GENKEY = BASE / "gen-receipt-key.py"
SIGN = BASE / "sign-receipt.py"
PY = "/usr/bin/python3"


def run(cmd, *, env=None, stdin=None, cwd=None):
    return subprocess.run(
        cmd, input=stdin, capture_output=True, text=True, check=False, env=env, cwd=cwd
    )


def env_for(root: pathlib.Path, extra=None):
    env = os.environ.copy()
    for k in ("T02_TASK_ID", "T02_REVIEW_TOKEN_SHA256", "T02_REVIEW_TOKEN_PATH"):
        env.pop(k, None)
    env["T02_PENDING_PATH"] = str(root / "pending.json")
    env["T02_DISCIPLINE_LOG"] = str(root / "audit.jsonl")
    env["T02_TASKS_DIR"] = str(root / "tasks")
    env["T02_NONCE_PATH"] = str(root / "nonces.json")
    env["T02_TASK_ID"] = "T02"
    env.update(extra or {})
    return env


def make_transcript(root: pathlib.Path):
    rows = [
        {"type": "message", "role": "user", "content": "<user_query>第12輪 e2e</user_query>",
         "id": "u1", "sessionId": "session-1"},
        {"type": "function_call", "name": "Edit", "arguments": "{}", "id": "e1",
         "sessionId": "session-1"},
    ]
    path = root / "session-1.jsonl"
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return path


def status_of(root: pathlib.Path, audit: pathlib.Path) -> bool:
    proc = run([PY, str(audit), "--status", "T02"], env=env_for(root))
    try:
        return json.loads(proc.stdout).get("completion_allowed")
    except json.JSONDecodeError:
        return False


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "tasks").mkdir()
        (root / "tasks" / "T02-e2e.md").write_text("# 測試卡\n", encoding="utf-8")

        # E0：產生金鑰對（receipt＋獨立核准），並做一份內嵌兩把測試公鑰的受驗腳本副本
        keys = root / "keys"
        gk = run([PY, str(GENKEY), str(keys)], cwd=str(BASE))
        if gk.returncode != 0:
            print("E0 產生金鑰失敗：", gk.stdout, gk.stderr)
            return 1
        appr_keys = root / "approval-keys"
        gk2 = run([PY, str(GENKEY), str(appr_keys)], cwd=str(BASE))
        if gk2.returncode != 0:
            print("E0 產生核准金鑰失敗：", gk2.stdout, gk2.stderr)
            return 1
        pub_pem = (keys / "t02-receipt-pub.pem").read_text(encoding="utf-8")
        approval_pub_pem = (appr_keys / "t02-receipt-pub.pem").read_text(encoding="utf-8")
        src = AUDIT.read_text(encoding="utf-8")
        audit_copy = root / "audit-e2e.py"
        # C0d：兩個信任根常數都換成測試公鑰；每個常數雙路相容（sentinel 或已裝整行替換）
        for name, pem in (("RECEIPT_PUBKEY_PEM", pub_pem),
                          ("APPROVAL_PUBKEY_PEM", approval_pub_pem)):
            sentinel = f'{name} = ""'
            if sentinel in src:
                src = src.replace(sentinel, f"{name} = " + json.dumps(pem), 1)
                continue
            lines = []
            done = False
            for line in src.splitlines(keepends=True):
                if not done and line.startswith(f"{name} = "):
                    lines.append(f"{name} = " + json.dumps(pem) + "\n")
                    done = True
                else:
                    lines.append(line)
            assert done, f"受驗腳本找不到公鑰常數（結構已變動）：{name}"
            src = "".join(lines)
        audit_copy.write_text(src, encoding="utf-8")
        version = hashlib.sha256(audit_copy.read_bytes()).hexdigest()

        # E1：建立 pending
        transcript = make_transcript(root)
        event = {"hook_event_name": "Stop", "session_id": "session-1", "generation_id": "g1",
                 "transcript_path": str(transcript), "stop_hook_active": True}
        r1 = run([PY, str(audit_copy)], env=env_for(root), stdin=json.dumps(event))
        s1 = status_of(root, audit_copy)
        results.append(("E1 建立 pending（status=False）", s1 is False, f"status={s1}"))

        # 造一份合格驗收結果檔
        verdict = root / "T02-e2e-verdict.md"
        pending = json.loads((root / "pending.json").read_text(encoding="utf-8"))
        ids = sorted(str(v.get("pending_id") or "") for v in pending.values())
        verdict.write_text(
            "判定：通過\n" + "task_id=T02\n" + f"<!-- T02-VERDICT: pass version={version} -->\n",
            encoding="utf-8",
        )

        # E2：攻擊 A（自設預期 hash）
        attacker = "producer-chosen-token"
        r2 = run(
            [PY, str(audit_copy), "--clear", "T02", "--result", str(verdict),
             "--version", version, "--by", "WorkBuddy"],
            env=env_for(root, {"T02_REVIEW_TOKEN_SHA256": hashlib.sha256(attacker.encode()).hexdigest()}),
        )
        s2 = status_of(root, audit_copy)
        results.append(("E2 攻擊A（自設 token hash）被拒", r2.returncode != 0 and s2 is False,
                        f"rc={r2.returncode} status={s2} err={r2.stderr.strip()}"))

        # E3：攻擊 B（另一把私鑰簽的 receipt）
        other = root / "other-keys"
        run([PY, str(GENKEY), str(other)], cwd=str(BASE))
        forged = root / "forged-receipt.json"
        r3sign = run(
            [PY, str(SIGN), "--key", str(other / "t02-receipt-priv.pem"), "--task-id", "T02",
             "--version", version, "--result", str(verdict), "--receipt-out", str(forged),
             "--pending-ids", ",".join(ids)],
            env=env_for(root),
        )
        r3 = run(
            [PY, str(audit_copy), "--clear", "T02", "--result", str(verdict),
             "--version", version, "--by", "codex", "--receipt", str(forged)],
            env=env_for(root),
        )
        s3 = status_of(root, audit_copy)
        results.append(("E3 攻擊B（他鑰簽發）被拒", r3.returncode != 0 and s3 is False,
                        f"rc={r3.returncode} status={s3} err={r3.stderr.strip()}"))

        # 造合法 receipt 與獨立核准（E6／E4／E5 共用）
        good = root / "receipt.json"
        run(
            [PY, str(SIGN), "--key", str(keys / "t02-receipt-priv.pem"), "--task-id", "T02",
             "--version", version, "--result", str(verdict), "--receipt-out", str(good),
             "--pending-ids", ",".join(ids)],
            env=env_for(root),
        )
        approval = root / "approval.json"
        run(
            [PY, str(SIGN), "--key", str(appr_keys / "t02-receipt-priv.pem"),
             "--approval-of", str(good), "--receipt-out", str(approval)],
            env=env_for(root),
        )

        # E6：缺核准（C0d 核心）——合法 receipt 但無獨立核准 → 拒
        r6 = run(
            [PY, str(audit_copy), "--clear", "T02", "--result", str(verdict),
             "--version", version, "--by", "WorkBuddy", "--receipt", str(good)],
            env=env_for(root),
        )
        s6 = status_of(root, audit_copy)
        results.append(("E6 缺核准（僅 receipt）被拒", r6.returncode != 0 and s6 is False,
                        f"rc={r6.returncode} status={s6} err={r6.stderr.strip()}"))

        # E4：正向（receipt＋獨立核准雙簽）
        shutil.copy2(root / "pending.json", root / "pending.pre-e4.json")
        r4 = run(
            [PY, str(audit_copy), "--clear", "T02", "--result", str(verdict),
             "--version", version, "--by", "codex", "--receipt", str(good),
             "--approval", str(approval)],
            env=env_for(root),
        )
        s4 = status_of(root, audit_copy)
        results.append(("E4 正向（receipt＋核准雙簽）清除成功", r4.returncode == 0 and s4 is True,
                        f"rc={r4.returncode} status={s4} out={r4.stdout.strip()} err={r4.stderr.strip()}"))

        # E5：重放（還原 pending 後，同一組 receipt＋核准再用）→ nonce 已用拒
        shutil.copy2(root / "pending.pre-e4.json", root / "pending.json")
        r5 = run(
            [PY, str(audit_copy), "--clear", "T02", "--result", str(verdict),
             "--version", version, "--by", "codex", "--receipt", str(good),
             "--approval", str(approval)],
            env=env_for(root),
        )
        results.append(("E5 重放同一 receipt＋核准被拒", r5.returncode != 0,
                        f"rc={r5.returncode} err={r5.stderr.strip()}"))

    print("=== T02 第 12 輪 e2e ===")
    ok = 0
    for name, passed, detail in results:
        print(f"{'✅' if passed else '❌'} {name}   [{detail}]")
        ok += 1 if passed else 0
    print(f"\n{ok}/{len(results)} 通過")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
