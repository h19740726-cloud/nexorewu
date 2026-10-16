#!/usr/bin/env python3
"""第 2 輪 A 組反例（A1～A4）**修正後複驗**：以公開介面重現四個攻擊。

與 Codex 原反例腳本（直接改模組常數 `m.USED_NONCES_PATH`）不同，本腳本**只走程式對外介面**
（CLI ＋ 環境變數 ＋ 隔離副本），因此可以在「程式內部常數已改版」後照樣重跑：

  A1 receipt 版本與受驗執行檔不符，且**省略 --version** → 應拒絕
  A2 先合法清除，再**損毀／移除防重放狀態**後重放同一 receipt → 應拒絕
  A3 先合法清除，再**改指防重放狀態路徑**（T02_NONCE_PATH）重放 → 應拒絕
  A4 同一 boundary 用於**另一張卡** → 兩張卡的 pending 必須並存（不得覆寫）

用法：/usr/bin/python3 repro-round2.py
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
SENTINEL = 'RECEIPT_PUBKEY_PEM = ""'
NONCE_DIR = "T02-used-receipt-nonces"


def run(cmd, *, env=None, stdin=None, cwd=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False,
                          env=env, cwd=cwd)


def env_for(root: pathlib.Path, extra=None):
    env = os.environ.copy()
    for key in ("T02_TASK_ID", "T02_REVIEW_TOKEN_SHA256", "T02_REVIEW_TOKEN_PATH",
                "T02_NONCE_PATH"):
        env.pop(key, None)
    env["T02_PENDING_PATH"] = str(root / "pending.json")
    env["T02_DISCIPLINE_LOG"] = str(root / "audit.jsonl")
    env["T02_TASKS_DIR"] = str(root / "tasks")
    env["T02_TASK_ID"] = "T02"
    env.update(extra or {})
    return env


def stop_once(root: pathlib.Path, audit: pathlib.Path, card: str, session: str) -> None:
    """跑一次 Stop（stop_hook_active=True）以建立／更新該卡的 pending。"""
    rows = [
        {"type": "message", "role": "user", "content": "<user_query>repro</user_query>",
         "id": "u1", "sessionId": session},
        {"type": "function_call", "name": "Edit", "arguments": "{}", "id": "e1",
         "sessionId": session},
    ]
    transcript = root / f"{session}.jsonl"
    transcript.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                          encoding="utf-8")
    event = {"hook_event_name": "Stop", "session_id": session, "generation_id": "g1",
             "transcript_path": str(transcript), "stop_hook_active": True}
    run([PY, str(audit)], env=env_for(root, {"T02_TASK_ID": card}), stdin=json.dumps(event))


def pending_ids(root: pathlib.Path, card: str) -> list[str]:
    path = root / "pending.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return sorted(str(v.get("pending_id") or "") for v in data.values()
                  if isinstance(v, dict) and str(v.get("task_id") or "") == card)


def write_verdict(root: pathlib.Path, card: str, version: str, name: str) -> pathlib.Path:
    path = root / name
    path.write_text(
        "判定：通過\n"
        f"task_id={card}\n"
        f"pending_ids={','.join(pending_ids(root, card))}\n"
        f"<!-- T02-VERDICT: pass version={version} -->\n",
        encoding="utf-8",
    )
    return path


def sign(priv: pathlib.Path, card: str, version: str, verdict: pathlib.Path,
         out: pathlib.Path, root: pathlib.Path, by: str = "codex") -> None:
    run([PY, str(SIGN), "--key", str(priv), "--task-id", card, "--version", version,
         "--result", str(verdict), "--receipt-out", str(out),
         "--pending-ids", ",".join(pending_ids(root, card))], env=env_for(root))


def main() -> int:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "tasks").mkdir()
        (root / "tasks" / "T02-x.md").write_text("# 測試卡\n", encoding="utf-8")
        (root / "tasks" / "CARD-A.md").write_text("# 測試卡\n", encoding="utf-8")
        (root / "tasks" / "CARD-B.md").write_text("# 測試卡\n", encoding="utf-8")

        keys = root / "keys"
        gk = run([PY, str(GENKEY), str(keys)], cwd=str(BASE))
        if gk.returncode != 0:
            print("產生金鑰失敗：", gk.stdout, gk.stderr)
            return 1
        pub = (keys / "t02-receipt-pub.pem").read_text(encoding="utf-8")
        priv = keys / "t02-receipt-priv.pem"

        src = AUDIT.read_text(encoding="utf-8")
        audit = root / "audit-repro.py"
        if SENTINEL in src:
            patched = src.replace(SENTINEL, "RECEIPT_PUBKEY_PEM = " + json.dumps(pub), 1)
        else:
            # 雙路相容（2026-10-16）：正式公鑰已安裝 → 整行替換成測試公鑰
            _lines = []
            _done = False
            for _line in src.splitlines(keepends=True):
                if not _done and _line.startswith("RECEIPT_PUBKEY_PEM = "):
                    _lines.append("RECEIPT_PUBKEY_PEM = " + json.dumps(pub) + "\n")
                    _done = True
                else:
                    _lines.append(_line)
            assert _done, "受驗腳本找不到公鑰常數（結構已變動）"
            patched = "".join(_lines)
        audit.write_text(patched, encoding="utf-8")
        version = hashlib.sha256(audit.read_bytes()).hexdigest()

        # ---- A1：receipt 版本與執行檔不符，省略 --version ----
        stop_once(root, audit, "T02", "session-1")
        bad_verdict = write_verdict(root, "T02", "unrelated", "a1-verdict.md")
        bad_receipt = root / "a1-receipt.json"
        sign(priv, "T02", "not-the-running-script", bad_verdict, bad_receipt, root)
        a1 = run([PY, str(audit), "--clear", "T02", "--result", str(bad_verdict),
                  "--by", "WorkBuddy", "--receipt", str(bad_receipt)],
                 env=env_for(root))
        results.append(("A1 版本不符（省略 --version）被拒", a1.returncode != 0,
                        f"rc={a1.returncode}"))
        # 被拒後 pending 應仍在
        still = run([PY, str(audit), "--status", "T02"], env=env_for(root))
        still_open = json.loads(still.stdout).get("completion_allowed") is False
        results.append(("A1 被拒後 pending 未被清除", still_open, f"still_open={still_open}"))

        # ---- A2：合法清除後，損毀防重放狀態再重放 ----
        good_verdict = write_verdict(root, "T02", version, "a2-verdict.md")
        good_receipt = root / "a2-receipt.json"
        sign(priv, "T02", version, good_verdict, good_receipt, root)
        ok = run([PY, str(audit), "--clear", "T02", "--result", str(good_verdict),
                  "--version", version, "--by", "codex", "--receipt", str(good_receipt)],
                 env=env_for(root))
        store = root / NONCE_DIR
        if store.exists():
            shutil.rmtree(store)
        a2 = run([PY, str(audit), "--clear", "T02", "--result", str(good_verdict),
                  "--version", version, "--by", "codex", "--receipt", str(good_receipt)],
                 env=env_for(root))
        results.append(("A2 防重放狀態損毀後重放被拒",
                        ok.returncode == 0 and a2.returncode != 0,
                        f"first_rc={ok.returncode} replay_rc={a2.returncode}"))

        # ---- A3：合法清除後，改指防重放狀態路徑再重放 ----
        # 🔴 用**獨立 root**：A2 已刻意刪除防重放存放區，沿用同一 root 會讓 A3 的
        #    「首次合法清除」無法建立存放區（新版保守設計），屬 fixture 缺陷而非防線失效。
        root3 = root / "a3"
        (root3 / "tasks").mkdir(parents=True, exist_ok=True)
        (root3 / "tasks" / "T02-x.md").write_text("# 測試卡\n", encoding="utf-8")
        stop_once(root3, audit, "T02", "session-3")
        v3 = write_verdict(root3, "T02", version, "a3-verdict.md")
        r3 = root3 / "a3-receipt.json"
        sign(priv, "T02", version, v3, r3, root3)
        ok3 = run([PY, str(audit), "--clear", "T02", "--result", str(v3),
                   "--version", version, "--by", "codex", "--receipt", str(r3)],
                  env=env_for(root3))
        a3 = run([PY, str(audit), "--clear", "T02", "--result", str(v3),
                  "--version", version, "--by", "codex", "--receipt", str(r3)],
                 env=env_for(root3, {"T02_NONCE_PATH": str(root3 / "redirected.json")}))
        results.append(("A3 改指防重放路徑後重放被拒",
                        ok3.returncode == 0 and a3.returncode != 0,
                        f"first_rc={ok3.returncode} replay_rc={a3.returncode}"))

        # ---- A4：同一 boundary 用於另一張卡 ----
        stop_once(root, audit, "CARD-A", "session-3")
        stop_once(root, audit, "CARD-B", "session-3")
        data = json.loads((root / "pending.json").read_text(encoding="utf-8"))
        cards = sorted(str(v.get("task_id") or "") for v in data.values() if isinstance(v, dict))
        results.append(("A4 同 boundary 跨卡兩筆並存",
                        "CARD-A" in cards and "CARD-B" in cards,
                        f"cards={cards}"))

    print("=== 第 2 輪 A 組反例 · 修正後複驗（公開介面）===")
    ok = 0
    for name, passed, detail in results:
        print(f"{'✅' if passed else '❌'} {name}   [{detail}]")
        ok += 1 if passed else 0
    print(f"\n{ok}/{len(results)} 通過")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
