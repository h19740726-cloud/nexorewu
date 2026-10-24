#!/usr/bin/env python3
"""T02 C0d 結果綁定唯一入口：只接受 Codex 撰寫的獨立候選機制結果。

依 2026-10-24 業主令（自上而下整改・第二／三階段）：
- WorkBuddy 自寫的 `T02-sign-verdict.md` 只能是施工材料，**不得**作為 receipt 綁定的最終裁決結果。
- 唯一可綁的結果檔＝`T02-c0d-codex-result.md`（格式見 `T02-c0d-codex-result-TEMPLATE.md`）。

行為（任何一項不合即拒絕、不改任何檔）：
  1) 結果檔存在、不是施工材料、`result_author=Codex`
  2) `task_id=T02` 與 `T02-VERDICT: pass version=…` 各恰一行，版本等於稽核器實算 SHA256
  3) 以 `make-sign-request.py` 為唯一產生器重生成 `T02-sign-request.json`，再回讀驗證四項綁定
  4) 印出機器可核對摘要

用法：
  python3 bind-c0d-result.py --result T02-c0d-codex-result.md [--dry]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys

AUDIT = pathlib.Path("T02-discipline-audit.py")
STORE = pathlib.Path("/Users/wulieqiang/AI協作/work/codex/T02-pending-violations.json")
REQ = pathlib.Path("T02-sign-request.json")
MAKER = pathlib.Path("make-sign-request.py")
FORBIDDEN = {"T02-sign-verdict.md"}  # WorkBuddy 自寫：施工材料，禁止綁定

VERDICT_RE = re.compile(r"<!--\s*T02-VERDICT:\s*pass\s+version=([0-9a-fA-F]{64})\s*-->")
TASK_RE = re.compile(r"^task_id=([A-Za-z0-9._:-]{1,64})[ \t]*$", re.MULTILINE)
AUTHOR_RE = re.compile(r"^result_author=(\S+)[ \t]*$", re.MULTILINE)
COMMIT_RE = re.compile(r"^reviewed_commit=([0-9a-fA-F]{40})[ \t]*$", re.MULTILINE)


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="C0d 結果綁定（只接受 Codex 獨立結果）")
    parser.add_argument("--result", default="T02-c0d-codex-result.md")
    parser.add_argument("--dry", action="store_true", help="只驗證與預覽，不寫申請檔")
    args = parser.parse_args()

    result = pathlib.Path(args.result)
    problems: list[str] = []
    if result.name in FORBIDDEN:
        problems.append("此檔是 WorkBuddy 施工材料（T02-sign-verdict.md），禁止作為結果綁定")
    if not result.is_file():
        problems.append(f"結果檔不存在：{result}")
    if not AUDIT.is_file():
        problems.append(f"稽核器不存在：{AUDIT}")
    if not STORE.is_file():
        problems.append(f"pending store 不存在：{STORE}")
    if problems:
        for item in problems:
            print(f"REFUSED: {item}", file=sys.stderr)
        return 2

    audit_sha = sha256_of(AUDIT)
    text = result.read_text(encoding="utf-8")

    authors = AUTHOR_RE.findall(text)
    if authors != ["Codex"]:
        problems.append(f"result_author 必須恰為一行 Codex（實得 {authors!r}）")
    tasks = TASK_RE.findall(text)
    if tasks != ["T02"]:
        problems.append(f"task_id 宣告必須恰為一行 T02（實得 {tasks!r}）")
    versions = VERDICT_RE.findall(text)
    if len(versions) != 1:
        problems.append(f"verdict 宣告必須恰為一個（實得 {len(versions)} 個）")
    elif versions[0].lower() != audit_sha:
        problems.append(
            "verdict 宣告版本≠稽核器實算 SHA256"
            f"（宣告={versions[0][:16]}…，實算={audit_sha[:16]}…）"
        )
    commits = COMMIT_RE.findall(text)
    if len(commits) != 1:
        problems.append(f"reviewed_commit 必須恰為一行 40 位 hex（實得 {commits!r}）")

    if problems:
        for item in problems:
            print(f"REFUSED: {item}", file=sys.stderr)
        return 2

    store = json.loads(STORE.read_text(encoding="utf-8"))
    ids = sorted(
        str(v.get("pending_id") or "")
        for v in store.values()
        if isinstance(v, dict) and str(v.get("task_id") or "") == "T02"
    )
    ids = [i for i in ids if i]
    if not ids:
        print("REFUSED: 正式 store 內沒有 T02 pending", file=sys.stderr)
        return 2

    if not MAKER.is_file():
        print(f"REFUSED: 產生器不存在：{MAKER}", file=sys.stderr)
        return 2

    if args.dry:
        print(json.dumps({
            "ok": True, "dry": True,
            "result_path": result.name, "result_sha256": sha256_of(result),
            "version": audit_sha, "pending_ids_count": len(ids),
            "reviewed_commit": commits[0],
        }, ensure_ascii=False, indent=2))
        return 0

    proc = subprocess.run(
        [sys.executable, str(MAKER), "--audit", str(AUDIT), "--pending-store", str(STORE),
         "--task-id", "T02", "--result", str(result), "--out", str(REQ)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        print(f"REFUSED: make-sign-request 失敗 rc={proc.returncode}\n{proc.stderr}", file=sys.stderr)
        return 2

    request = json.loads(REQ.read_text(encoding="utf-8"))
    checks = {
        "version == auditor": request.get("version") == audit_sha,
        "result_path == 本檔": request.get("result_path") == result.name,
        "result_sha256 == 本檔實算": request.get("result_sha256") == sha256_of(result),
        "pending_ids == store 21": request.get("pending_ids") == ids,
    }
    if not all(checks.values()):
        print("REFUSED: 回讀驗證失敗 " + json.dumps(checks, ensure_ascii=False), file=sys.stderr)
        return 2

    print(json.dumps({
        "ok": True,
        "request_sha256": sha256_of(REQ),
        "request": request,
        "checks": checks,
        "reviewed_commit": commits[0],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
