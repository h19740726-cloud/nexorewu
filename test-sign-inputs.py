#!/usr/bin/env python3
"""T02 簽發 workflow 的「輸入驗證」測試（本機可跑；不需要 GitHub、不需要任何 secret）。

🔴 與 `github-actions/sign-receipt.yml` 的驗證段**同源**（同規則、同正則）：
   改一邊就要改兩邊。這裡只驗「規則本身」，
   **不驗 GitHub 端**（workflow 尚未啟用 secret、從未簽發）。
"""
from __future__ import annotations

import re
import sys

ID_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}"
HEX_PATTERN = r"[0-9a-f]{64}"

RULES = (
    ("task_id", ID_PATTERN),
    ("pending_id", ID_PATTERN),
    ("version", HEX_PATTERN),
    ("result_sha256", HEX_PATTERN),
)


def validate(values: dict) -> list:
    problems = []
    for field, pattern in RULES:
        if not re.fullmatch(pattern, str(values.get(field, ""))):
            problems.append(f"{field} 格式不合法")
    return problems


GOOD = {"task_id": "T02", "pending_id": "abc123", "version": "a" * 64, "result_sha256": "b" * 64}

CASES = [
    ("合法輸入應通過", GOOD, []),
    ("task_id 空字串應拒", {**GOOD, "task_id": ""}, ["task_id"]),
    ("task_id 含空白應拒", {**GOOD, "task_id": "T02 x"}, ["task_id"]),
    ("task_id 含換行（注入嘗試）應拒", {**GOOD, "task_id": "T02\nrm"}, ["task_id"]),
    ("task_id 超長應拒", {**GOOD, "task_id": "A" * 65}, ["task_id"]),
    ("pending_id 含分號（shell 注入嘗試）應拒", {**GOOD, "pending_id": "abc;rm -rf /"}, ["pending_id"]),
    ("version 太短應拒", {**GOOD, "version": "abc"}, ["version"]),
    ("version 大寫十六進位應拒", {**GOOD, "version": "A" * 64}, ["version"]),
    ("version 帶非十六進位字元應拒", {**GOOD, "version": "z" * 64}, ["version"]),
    ("result_sha256 太短應拒", {**GOOD, "result_sha256": "b" * 63}, ["result_sha256"]),
    ("多個欄位同時不合法應全部列出", {**GOOD, "task_id": "", "version": "x"}, ["task_id", "version"]),
]


# 🔴 第 18 輪整改④：workflow 靜態安全檢查（2026-10-14）
#   ① `uses: actions/checkout@` 必須是 40 位十六進位 commit（未鎖 action → 失敗）
#   ② 全零 TRUSTED_COMMIT 守門必須存在；抽出該段 shell **實跑**：
#      全零 → 期望 rc=1；非全零 → 期望 rc=0
import os as _os
import pathlib as _pathlib
import subprocess as _subprocess
import tempfile as _tempfile

YML_PATH = _pathlib.Path(__file__).resolve().parent / "github-actions" / "sign-receipt.yml"


def check_workflow() -> int:
    failures = 0
    if not YML_PATH.exists():
        print("❌ 找不到 sign-receipt.yml")
        return 1
    text = YML_PATH.read_text(encoding="utf-8")

    # ① checkout 必須鎖完整 commit SHA
    refs = re.findall(r"uses:\s*actions/checkout@([^\s#]+)", text)
    ok1 = bool(refs) and all(re.fullmatch(r"[0-9a-f]{40}", r or "") for r in refs)
    print(f"{'✅' if ok1 else '❌'} checkout 已鎖完整 commit SHA   [refs={refs}]")
    failures += 0 if ok1 else 1

    # ② 全零守門：存在 ＋ 實跑
    m = re.search(
        r'if \[ "\$IN_TRUSTED_COMMIT" = "0{40}" \]; then.*?exit 1.*?\n\s*fi',
        text,
        re.S,
    )
    ok2 = bool(m)
    print(f"{'✅' if ok2 else '❌'} 全零 TRUSTED_COMMIT 守門存在")
    failures += 0 if ok2 else 1
    if m:
        snippet = m.group(0)
        for label, value, expect_rc in (("全零→拒", "0" * 40, 1), ("非全零→過", "a" * 40, 0)):
            with _tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as fh:
                fh.write("set -u\n" + snippet + "\n")
                sh = fh.name
            env = {**_os.environ, "IN_TRUSTED_COMMIT": value}
            rc = _subprocess.run(["/bin/bash", sh], env=env, capture_output=True).returncode
            _os.unlink(sh)
            ok3 = rc == expect_rc
            print(f"{'✅' if ok3 else '❌'} 守門實跑 [{label}] rc={rc}（期望 {expect_rc}）")
            failures += 0 if ok3 else 1
    return failures


def main() -> int:
    failures = 0
    for label, values, expected_prefixes in CASES:
        problems = validate(values)
        if expected_prefixes:
            ok = len(problems) == len(expected_prefixes) and all(
                any(p.startswith(prefix) for p in problems) for prefix in expected_prefixes
            )
        else:
            ok = not problems
        print(f"{'✅' if ok else '❌'} {label}   [problems={problems}]")
        failures += 0 if ok else 1
    n_input = len(CASES) - failures
    wf_failures = check_workflow()
    failures += wf_failures
    print(f"\n輸入驗證 {n_input}/{len(CASES)} 通過；workflow 檢查失敗 {wf_failures} 條")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
