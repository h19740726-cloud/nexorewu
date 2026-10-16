#!/usr/bin/env python3
"""T02 CI 簽發工具：受保護環境 workflow 的「無鑰區」邏輯（單一真相源）。

用法（由 `.github/workflows/t02-sign-receipt.yml` 呼叫）：

    python3 t02-ci-payload.py preflight \
        --tag-tree <tag commit 的工作樹> \
        --trusted-tree <TRUSTED_COMMIT 的工作樹> \
        --request T02-sign-request.json \
        [--github-output <$GITHUB_OUTPUT 路徑>]

    python3 t02-ci-payload.py assemble \
        --trusted-tree <TRUSTED_COMMIT 的工作樹> \
        --payload-bin <payload.bin> --sig-bin <sig.bin> --pub-pem <pub.pem> \
        --receipt-out <receipt.json>

設計原則（對應 `T02-驗收意見-GitHub簽發邊界-20261014.md` 與業主最終整改指令）：

1. **本工具只在「無鑰區」執行**：它執行的時候環境中**沒有**私鑰。
   私鑰只出現在 workflow 裡一個「純 openssl 命令」的步驟（不執行任何 repo 內的程式碼）。
2. **受驗檔雙源比對**：`tag commit` 的工作樹與 `TRUSTED_COMMIT`（業主設定於受保護
   environment variable，產出者無權修改）的工作樹，對「簽發鏈用到的每一個檔案」
   逐位元比對；任一不符即拒絕。
3. **申請檔自洽**：`T02-sign-request.json` 的 `version` 必須等於受驗稽核器檔案的
   SHA256；`result_sha256` 必須等於結果檔的 SHA256（兩個工作樹皆須一致）。
4. `payload` 的位元組由**受驗稽核器**（TRUSTED_COMMIT 版）的 `canonical_payload()`
   產生——簽端與驗端共用同一支函式（單一真相源）。
5. 🔴 **防 TOCTOU 的兩次執行必須位元組一致**（2026-10-16 修復）：`nonce` 與
   `issued_at` 由 preflight 第一次執行生成、經 GITHUB_OUTPUT 導出；sign 重跑以
   `--pin-*` 重用同一組值。不固定化時，兩次獨立執行必然產生不同 payload，
   防 TOCTOU 比對必然失敗（run 38844329678 實測）。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# 會參與「雙源比對」的檔案（相對 repo 根；最後一項在兩個樹中檔名不同）。
DUAL_SOURCE_FILES = (
    "T02-discipline-audit.py",
    "T02-sign-request.json",
    "t02-ci-payload.py",
)
WORKFLOW_IN_TAG_TREE = ".github/workflows/t02-sign-receipt.yml"
WORKFLOW_IN_TRUSTED_TREE = "github-actions/t02-sign-receipt.yml"

HEX64_RE = re.compile(r"[0-9a-f]{64}")
HEX40_RE = re.compile(r"[0-9a-f]{40}")
CARD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
PENDING_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")
SAFE_REL_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_audit_module(trusted_tree: Path):
    """載入受驗稽核器（TRUSTED_COMMIT 版），取用 canonical_payload（單一真相源）。"""
    audit_path = trusted_tree / "T02-discipline-audit.py"
    spec = importlib.util.spec_from_file_location("t02_audit_module_ci", audit_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def read_request(path: Path) -> tuple[dict | None, list[str]]:
    """解析並做「形狀」驗證；回 (request, problems)。"""
    problems: list[str] = []
    if not path.is_file():
        return None, [f"申請檔不存在：{path}"]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, [f"申請檔無法解析：{exc}"]
    if not isinstance(raw, dict):
        return None, ["申請檔必須是 JSON 物件"]
    if raw.get("schema") != 1:
        problems.append(f"申請檔 schema 不支援：{raw.get('schema')!r}")
    task_id = str(raw.get("task_id") or "")
    if not CARD_ID_RE.fullmatch(task_id):
        problems.append(f"task_id 格式不合法：{task_id!r}")
    version = str(raw.get("version") or "")
    if not HEX64_RE.fullmatch(version):
        problems.append(f"version 必須是 64 位小寫十六進位：{version!r}")
    pending_ids = raw.get("pending_ids")
    if not isinstance(pending_ids, list) or not pending_ids:
        problems.append("pending_ids 必須是非空陣列（清除必須綁定至少一筆目標）")
    else:
        for item in pending_ids:
            if not isinstance(item, str) or not PENDING_ID_RE.fullmatch(item):
                problems.append(f"pending_ids 含不合法項目：{item!r}")
                break
    result_path = str(raw.get("result_path") or "")
    if not SAFE_REL_PATH_RE.fullmatch(result_path) or ".." in result_path.split("/"):
        problems.append(f"result_path 不合法（限 repo 內相對路徑）：{result_path!r}")
    result_sha = str(raw.get("result_sha256") or "")
    if not HEX64_RE.fullmatch(result_sha):
        problems.append(f"result_sha256 必須是 64 位小寫十六進位：{result_sha!r}")
    return raw, problems


def dual_source_check(tag_tree: Path, trusted_tree: Path) -> list[str]:
    """受驗檔雙源比對；回問題清單（空＝全部一致）。"""
    problems: list[str] = []
    for rel in DUAL_SOURCE_FILES:
        tag_file = tag_tree / rel
        trusted_file = trusted_tree / rel
        if not tag_file.is_file():
            problems.append(f"[tag 樹] 缺少受驗檔：{rel}")
            continue
        if not trusted_file.is_file():
            problems.append(f"[trusted 樹] 缺少受驗檔：{rel}")
            continue
        a = sha256_of(tag_file)
        b = sha256_of(trusted_file)
        if a != b:
            problems.append(f"受驗檔雙源不一致：{rel}（tag={a}，trusted={b}）")
    tag_wf = tag_tree / WORKFLOW_IN_TAG_TREE
    trusted_wf = trusted_tree / WORKFLOW_IN_TRUSTED_TREE
    if not tag_wf.is_file():
        problems.append(f"[tag 樹] 缺少 workflow 檔：{WORKFLOW_IN_TAG_TREE}")
    if not trusted_wf.is_file():
        problems.append(f"[trusted 樹] 缺少 workflow 權威副本：{WORKFLOW_IN_TRUSTED_TREE}")
    if tag_wf.is_file() and trusted_wf.is_file():
        a = sha256_of(tag_wf)
        b = sha256_of(trusted_wf)
        if a != b:
            problems.append(
                f"workflow 自指紋不一致（tag 樹 vs 權威副本）：tag={a}，trusted={b}"
            )
    return problems


PIN_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")


def validate_pin(pin_nonce: str, pin_issued_at: str) -> list[str]:
    """驗證固定化 pin（2026-10-16 TOCTOU 修復）。回問題清單（空＝通過）。

    - pin 允許「兩個都不給」（＝正常路徑：生成新值）；
    - 一旦給其中一個，**另一個也必須給**（防「半吊子固定化」：
      只固定 nonce 而 issued_at 每次重算，payload 依然非決定性）；
    - nonce：`[A-Za-z0-9_-]`、長度 8～64（與生成端 base64url 相容）；
    - issued_at：可被 `datetime.fromisoformat` 解析、且**必須帶時區**。
    """
    problems: list[str] = []
    if bool(pin_nonce) != bool(pin_issued_at):
        problems.append("pin 必須成對提供（nonce 與 issued_at 要嘛都給、要嘛都不給）")
        return problems
    if not pin_nonce:
        return problems
    if not PIN_NONCE_RE.fullmatch(pin_nonce):
        problems.append(f"pin nonce 格式不合法（限 [A-Za-z0-9_-]、8～64 字元）：{pin_nonce!r}")
    try:
        parsed = datetime.fromisoformat(pin_issued_at)
    except ValueError:
        problems.append(f"pin issued_at 不是合法 ISO 8601 時間：{pin_issued_at!r}")
    else:
        if parsed.tzinfo is None:
            problems.append(f"pin issued_at 必須帶時區（例：+00:00）：{pin_issued_at!r}")
    return problems


def build_payload(trusted_tree: Path, request: dict, env: dict,
                  pin_nonce: str = "", pin_issued_at: str = "") -> dict:
    """組 payload（欄位固定順序由 canonical_payload 正規化）。

    🔴 2026-10-16（TOCTOU 修復）：`nonce` 與 `issued_at` 支援「固定化（pin）」——
    preflight job 第一次執行生成兩值並經 GITHUB_OUTPUT 導出；
    sign job 重跑時以 `pin_nonce`/`pin_issued_at` 重用同一組值。
    唯此，兩次獨立執行才能重建出**位元組相同**的 payload，
    防 TOCTOU 的雜湊比對才可能通過（run 38844329678 實測：未固定化時必然失敗）。
    未提供 pin（＝preflight job 的正常路徑）時行為與舊版相同（生成新值）。
    """
    trusted_commit = str(env.get("T02_TRUSTED_COMMIT") or "").strip().lower()
    nonce = pin_nonce or base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
    issued_at = pin_issued_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {
        "task_id": str(request["task_id"]),
        "version": str(request["version"]),
        "pending_ids": sorted(str(x) for x in request["pending_ids"]),
        "result_sha256": str(request["result_sha256"]),
        "nonce": nonce,
        "issued_at": issued_at,
        "issued_via": "github-actions:t02-signing",
        "source_commit": trusted_commit,
        "run_id": str(env.get("GITHUB_RUN_ID") or ""),
        "run_attempt": str(env.get("GITHUB_RUN_ATTEMPT") or ""),
        "tag_ref": str(env.get("GITHUB_REF") or ""),
    }


def cmd_preflight(args: argparse.Namespace) -> int:
    tag_tree = Path(args.tag_tree).resolve()
    trusted_tree = Path(args.trusted_tree).resolve()
    problems: list[str] = []

    trusted_commit = str(os.environ.get("T02_TRUSTED_COMMIT") or "").strip().lower()
    if not HEX40_RE.fullmatch(trusted_commit):
        problems.append(
            f"T02_TRUSTED_COMMIT 未設定或格式不合法（需 40 位小寫十六進位）：{trusted_commit!r}"
        )

    if not tag_tree.is_dir():
        problems.append(f"tag 樹目錄不存在：{tag_tree}")
    if not trusted_tree.is_dir():
        problems.append(f"trusted 樹目錄不存在：{trusted_tree}")

    # 🔴 2026-10-16（TOCTOU 修復）：固定化 pin 的驗證（格式／成對性）。
    problems.extend(validate_pin(
        str(getattr(args, "pin_nonce", "") or ""),
        str(getattr(args, "pin_issued_at", "") or ""),
    ))
    if problems:
        return fail(problems)

    problems.extend(dual_source_check(tag_tree, trusted_tree))

    request, request_problems = read_request(tag_tree / args.request)
    problems.extend(request_problems)
    if problems or request is None:
        return fail(problems)

    # 申請檔自洽：version == 受驗稽核器 SHA；result 檔 SHA 兩樹一致且等於宣告值。
    audit_sha = sha256_of(trusted_tree / "T02-discipline-audit.py")
    if request["version"] != audit_sha:
        problems.append(
            "申請檔 version 與受驗稽核器 SHA256 不符"
            f"（request={request['version']}，audit={audit_sha}）"
        )
    for base in (tag_tree, trusted_tree):
        result_file = base / request["result_path"]
        if not result_file.is_file():
            problems.append(f"[{base.name}] 結果檔不存在：{request['result_path']}")
            continue
        result_sha = sha256_of(result_file)
        if result_sha != request["result_sha256"]:
            problems.append(
                f"[{base.name}] 結果檔 SHA256 與申請檔不符"
                f"（實際={result_sha}，申請={request['result_sha256']}）"
            )
    if problems:
        return fail(problems)

    audit = load_audit_module(trusted_tree)
    payload = build_payload(
        trusted_tree, request, os.environ,
        pin_nonce=str(getattr(args, "pin_nonce", "") or ""),
        pin_issued_at=str(getattr(args, "pin_issued_at", "") or ""),
    )
    canonical = audit.canonical_payload(payload)
    payload_b64 = base64.b64encode(canonical).decode("ascii")
    payload_sha = hashlib.sha256(canonical).hexdigest()
    if args.payload_out:
        Path(args.payload_out).write_bytes(canonical)

    report = {
        "ok": True,
        "task_id": payload["task_id"],
        "version": payload["version"],
        "pending_ids": payload["pending_ids"],
        "result_sha256": payload["result_sha256"],
        "nonce": payload["nonce"],
        "issued_at": payload["issued_at"],
        "run_id": payload["run_id"],
        "source_commit": payload["source_commit"],
        "payload_b64": payload_b64,
        "payload_sha256": payload_sha,
    }
    print("=== preflight 通過 ===")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    write_github_output(args.github_output, {
        "payload_b64": payload_b64,
        "payload_sha256": payload_sha,
        "payload_nonce": payload["nonce"],
        "payload_issued_at": payload["issued_at"],
    })
    write_summary(payload, report, trusted_commit, tag_tree, trusted_tree)
    return 0


def cmd_assemble(args: argparse.Namespace) -> int:
    trusted_tree = Path(args.trusted_tree).resolve()
    payload = Path(args.payload_bin).read_bytes()
    signature = Path(args.sig_bin).read_bytes()
    pub_pem = Path(args.pub_pem).read_text(encoding="utf-8")

    audit = load_audit_module(trusted_tree)
    receipt = {
        "schema": 1,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_fingerprint": audit.pubkey_fingerprint(pub_pem),
    }
    out = Path(args.receipt_out)
    out.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("=== receipt 已組裝 ===")
    print(f"receipt_path   = {out}")
    print(f"key_fingerprint= {receipt['key_fingerprint']}")
    print(f"payload_sha256 = {hashlib.sha256(payload).hexdigest()}")
    print("--- receipt 內容 ---")
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0


def write_github_output(path_text: str | None, values: dict) -> None:
    if not path_text:
        return
    path = Path(path_text)
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def write_summary(payload: dict, report: dict, trusted_commit: str, tag_tree: Path, trusted_tree: Path) -> None:
    """把「本次簽發的全部事實」寫進 GitHub Step Summary（審批人於審批前檢視用）。"""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    lines = [
        "## T02 簽發 preflight（審批前檢視）",
        "",
        "### 本次要簽發的內容（payload 明文）",
        "",
        "```json",
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "### 關鍵事實",
        "",
        "| 項目 | 值 |",
        "|:--|:--|",
        f"| TRUSTED_COMMIT（環境 variable） | `{trusted_commit}` |",
        f"| task_id | `{payload['task_id']}` |",
        f"| 稽核器 version | `{payload['version']}` |",
        f"| pending_ids | `{', '.join(payload['pending_ids'])}` |",
        f"| result_sha256 | `{payload['result_sha256']}` |",
        f"| nonce | `{payload['nonce']}` |",
        f"| run_id | `{payload['run_id']}` |",
        f"| payload_sha256 | `{report['payload_sha256']}` |",
        "",
        "### 受驗檔（雙源比對通過）",
        "",
    ]
    for rel in DUAL_SOURCE_FILES:
        lines.append(f"- `{rel}`：`{sha256_of(trusted_tree / rel)}`")
    lines.append(
        f"- `{WORKFLOW_IN_TAG_TREE}`（tag 樹）＝ `{WORKFLOW_IN_TRUSTED_TREE}`（權威副本）：`{sha256_of(tag_tree / WORKFLOW_IN_TAG_TREE)}`"
    )
    text = "\n".join(lines) + "\n"
    if summary_path:
        Path(summary_path).open("a", encoding="utf-8").write(text)


def fail(problems: list[str]) -> int:
    print("=== preflight 拒絕 ===", file=sys.stderr)
    for item in problems:
        print(f"- {item}", file=sys.stderr)
    print(json.dumps({"ok": False, "problems": problems}, ensure_ascii=False))
    return 3


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="T02 CI 簽發工具（無鑰區邏輯）")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pre = sub.add_parser("preflight", help="驗證輸入並產生 payload")
    p_pre.add_argument("--tag-tree", required=True)
    p_pre.add_argument("--trusted-tree", required=True)
    p_pre.add_argument("--request", default="T02-sign-request.json")
    p_pre.add_argument("--payload-out", default="", help="寫出 payload 位元組到指定檔案")
    p_pre.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""), help="GitHub Actions 輸出檔（寫入 payload_* 供 job outputs 使用）")
    p_pre.add_argument("--pin-nonce", default="", help="固定化 nonce（sign 重跑重用 preflight 值；須與 --pin-issued-at 成對）")
    p_pre.add_argument("--pin-issued-at", default="", help="固定化 issued_at（須與 --pin-nonce 成對）")
    p_pre.set_defaults(func=cmd_preflight)

    p_asm = sub.add_parser("assemble", help="組裝 receipt")
    p_asm.add_argument("--trusted-tree", required=True)
    p_asm.add_argument("--payload-bin", required=True)
    p_asm.add_argument("--sig-bin", required=True)
    p_asm.add_argument("--pub-pem", required=True)
    p_asm.add_argument("--receipt-out", required=True)
    p_asm.set_defaults(func=cmd_assemble)

    args = parser.parse_args(argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
