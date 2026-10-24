#!/usr/bin/env python3
"""生成 T02 簽發申請檔（`T02-sign-request.json`）與示範結果檔（fixture）。

用途：施工／彩排／最終輪把「要簽發什麼」固化進受驗 commit：
  1. `--make-verdict <路徑>`：寫一份示範用結果檔（fixture；檔頭註明性質），
     內含 `task_id=<卡>` 與 `<!-- T02-VERDICT: pass version=<稽核器 SHA> -->`。
  2. 讀稽核器 SHA、pending 存放區的目標卡 pending_ids、結果檔 SHA → 生成申請檔。

用法（範例）：
    python3 make-sign-request.py --make-verdict demo/T02-DEMO-verdict.md --verdict-task T02DEMO
    python3 make-sign-request.py \
        --audit T02-discipline-audit.py \
        --pending-store <pending.json 路徑> \
        --task-id T02DEMO \
        --result demo/T02-DEMO-verdict.md \
        --out T02-sign-request.json

本工具**不被 CI 執行**（CI 只讀申請檔）；它是施工端的一致性工具：
version／pending_ids／result_sha256 三者的值都由它從權威來源算出，避免手抄。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

VERDICT_TEMPLATE = """\
# T02 簽發鏈端到端示範 · 結果檔（fixture）

> 本檔為「受保護簽發流程」的**示範用綁定對象**，不是任何一輪的真實驗收判定。
> 真實驗收輪應由獨立驗收方提供結果檔（含同樣的機器可讀宣告格式）。

task_id={task_id}
<!-- T02-VERDICT: pass version={version} -->
"""


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_sha(path: pathlib.Path) -> str:
    return sha256_of(path)


def collect_pending_ids(store: pathlib.Path, task_id: str) -> list[str]:
    data = json.loads(store.read_text(encoding="utf-8"))
    ids = [
        str(item.get("pending_id") or "")
        for item in data.values()
        if isinstance(item, dict) and str(item.get("task_id") or "") == task_id
    ]
    return sorted(i for i in ids if i)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="生成 T02 簽發申請檔／示範結果檔")
    parser.add_argument("--audit", default="T02-discipline-audit.py", help="稽核器路徑")
    parser.add_argument("--pending-store", default="", help="pending 存放區（JSON）路徑")
    parser.add_argument("--task-id", default="", help="目標卡號")
    parser.add_argument("--result", default="", help="結果檔路徑（repo 內相對路徑亦作為 result_path）")
    parser.add_argument("--out", default="", help="申請檔輸出路徑")
    parser.add_argument("--make-verdict", default="", help="只生成示範結果檔到指定路徑")
    parser.add_argument("--verdict-task", default="T02DEMO", help="示範結果檔的 task_id")
    parser.add_argument("--result-path-declared", default="",
                        help="寫進申請檔的 result_path（預設取 --result 的檔名）")
    parser.add_argument("--unbound", action="store_true",
                        help="產生「尚未綁定結果」的申請檔：result_sha256=null、binding=pending-codex-result"
                             "（唯一合法填值者＝bind-c0d-result.py，來源只能是 Codex 獨立結果）")
    parser.add_argument("--declared-result", default="T02-c0d-codex-result.md",
                        help="--unbound 模式下宣告的結果檔名（預設 Codex 結果檔）")
    args = parser.parse_args(argv[1:])

    audit_path = pathlib.Path(args.audit)

    if args.make_verdict:
        out = pathlib.Path(args.make_verdict)
        out.parent.mkdir(parents=True, exist_ok=True)
        version = audit_sha(audit_path)
        out.write_text(
            VERDICT_TEMPLATE.format(task_id=args.verdict_task, version=version),
            encoding="utf-8",
        )
        print(json.dumps({
            "ok": True, "verdict_path": str(out),
            "task_id": args.verdict_task, "version": version,
            "verdict_sha256": sha256_of(out),
        }, ensure_ascii=False, indent=2))
        return 0

    if args.unbound:
        # 未綁定模式：結果檔還不存在（或其 SHA 尚未取得）。
        # 這裡**不填任何 sha**，避免把 WorkBuddy 自寫的施工材料混充成裁決結果。
        if not (args.task_id and args.out and args.pending_store):
            print("--unbound 需要 --task-id／--out／--pending-store", file=sys.stderr)
            return 2
        store_path = pathlib.Path(args.pending_store)
        if not store_path.is_file():
            print(f"pending 存放區不存在：{store_path}", file=sys.stderr)
            return 3
        pending_ids = collect_pending_ids(store_path, args.task_id)
        if not pending_ids:
            print(f"目標卡 {args.task_id} 在存放區沒有 pending（清除必須綁定至少一筆）",
                  file=sys.stderr)
            return 3
        declared = args.result_path_declared or args.declared_result
        if declared == "T02-sign-verdict.md":
            print("--unbound 不接受 WorkBuddy 自寫 verdict 當宣告對象", file=sys.stderr)
            return 3
        request = {
            "schema": 1,
            "task_id": args.task_id,
            "version": audit_sha(audit_path),
            "pending_ids": pending_ids,
            "result_path": declared,
            "result_sha256": None,
            "binding": "pending-codex-result",
        }
        out_path = pathlib.Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
        print(json.dumps({"ok": True, "unbound": True, "request_path": str(out_path),
                          **request}, ensure_ascii=False, indent=2))
        return 0

    if not (args.task_id and args.result and args.out and args.pending_store):
        print("缺少參數：需要 --task-id／--result／--out／--pending-store（或使用 --make-verdict）",
              file=sys.stderr)
        return 2

    result_path = pathlib.Path(args.result)
    if not result_path.is_file():
        print(f"結果檔不存在：{result_path}", file=sys.stderr)
        return 3
    store_path = pathlib.Path(args.pending_store)
    if not store_path.is_file():
        print(f"pending 存放區不存在：{store_path}", file=sys.stderr)
        return 3

    pending_ids = collect_pending_ids(store_path, args.task_id)
    if not pending_ids:
        print(f"目標卡 {args.task_id} 在存放區沒有 pending（清除必須綁定至少一筆）", file=sys.stderr)
        return 3

    request = {
        "schema": 1,
        "task_id": args.task_id,
        "version": audit_sha(audit_path),
        "pending_ids": pending_ids,
        "result_path": args.result_path_declared or result_path.name,
        "result_sha256": sha256_of(result_path),
        "binding": "bound",
    }
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "request_path": str(out_path), **request},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
