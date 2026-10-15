#!/usr/bin/env python3
"""T02 CI 簽發工具（`t02-ci-payload.py`）與簽發 workflow 的輸入驗證測試。

對象：
  1. `t02-ci-payload.py` 的 `preflight`：申請檔格式、受驗檔雙源比對、
     申請檔自洽（version==稽核器 SHA、result SHA 相符）、TRUSTED_COMMIT 檢查。
     本檔**實際執行**該工具（不是複製規則）——測的就是 CI 會跑的那一份。
  2. `t02-ci-payload.py` 的 `assemble`：receipt 組裝格式。
  3. `github-actions/t02-sign-receipt.yml`（權威副本）的結構斷言（純文字／正則；
     不依賴 pyyaml，任何 python3 都能跑）。

執行：`python3 test-sign-inputs.py`
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
CI_SCRIPT = BASE / "t02-ci-payload.py"
AUDIT = BASE / "T02-discipline-audit.py"
WORKFLOW_COPY = BASE / "github-actions" / "t02-sign-receipt.yml"
PY = "/usr/bin/python3"

TRUSTED_COMMIT = "a" * 40


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SignInputsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.tag_tree = self.root / "tag-tree"
        self.trusted_tree = self.root / "trusted-tree"
        for tree in (self.tag_tree, self.trusted_tree):
            (tree / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
            (tree / "github-actions").mkdir(parents=True, exist_ok=True)
            shutil.copy2(AUDIT, tree / "T02-discipline-audit.py")
            shutil.copy2(CI_SCRIPT, tree / "t02-ci-payload.py")
        shutil.copy2(WORKFLOW_COPY, self.tag_tree / ".github" / "workflows" / "t02-sign-receipt.yml")
        shutil.copy2(WORKFLOW_COPY, self.trusted_tree / "github-actions" / "t02-sign-receipt.yml")
        self.audit_sha = sha256_of(self.tag_tree / "T02-discipline-audit.py")
        self.write_verdict_and_request()

    def tearDown(self):
        self.temp.cleanup()

    # ---------------- fixture ----------------

    def write_verdict_and_request(self, *, request_overrides=None, verdict_text=None):
        verdict_text = verdict_text if verdict_text is not None else (
            "判定：通過\n" + "task_id=T02DEMO\n"
            + f"<!-- T02-VERDICT: pass version={self.audit_sha} -->\n"
        )
        for tree in (self.tag_tree, self.trusted_tree):
            (tree / "T02-DEMO-verdict.md").write_text(verdict_text, encoding="utf-8")
        verdict_sha = sha256_of(self.tag_tree / "T02-DEMO-verdict.md")
        request = {
            "schema": 1,
            "task_id": "T02DEMO",
            "version": self.audit_sha,
            "pending_ids": ["aaaa1111bbbb"],
            "result_path": "T02-DEMO-verdict.md",
            "result_sha256": verdict_sha,
        }
        request.update(request_overrides or {})
        text = json.dumps(request, ensure_ascii=False, indent=2) + "\n"
        for tree in (self.tag_tree, self.trusted_tree):
            (tree / "T02-sign-request.json").write_text(text, encoding="utf-8")
        self.request = request

    def run_preflight(self, *, trusted_commit=TRUSTED_COMMIT, extra_env=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("T02_")}
        env.update({
            "T02_TRUSTED_COMMIT": trusted_commit,
            "GITHUB_RUN_ID": "123456",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REF": "refs/tags/t02-sign-test",
        })
        env.update(extra_env or {})
        payload_out = self.root / "payload-out.bin"
        proc = subprocess.run(
            [PY, str(self.trusted_tree / "t02-ci-payload.py"), "preflight",
             "--tag-tree", str(self.tag_tree), "--trusted-tree", str(self.trusted_tree),
             "--payload-out", str(payload_out)],
            capture_output=True, text=True, check=False, env=env,
        )
        return proc, payload_out

    # ---------------- 1. 合法與基本形狀 ----------------

    def test_valid_input_passes_and_builds_payload(self):
        proc, payload_out = self.run_preflight()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(payload_out.is_file())
        payload = json.loads(payload_out.read_text(encoding="utf-8"))
        self.assertEqual(payload["task_id"], "T02DEMO")
        self.assertEqual(payload["version"], self.audit_sha)
        self.assertEqual(payload["pending_ids"], ["aaaa1111bbbb"])
        self.assertEqual(payload["source_commit"], TRUSTED_COMMIT)
        self.assertEqual(payload["run_id"], "123456")

    def test_trusted_commit_missing_or_malformed_rejected(self):
        for bad in ("", "xyz", "a" * 39, "a" * 41, "g" * 40, "0x" + "a" * 38):
            with self.subTest(trusted_commit=bad):
                proc, _ = self.run_preflight(trusted_commit=bad)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("T02_TRUSTED_COMMIT", proc.stderr)

    def test_trusted_commit_uppercase_accepted_and_normalized(self):
        """大小寫容錯：大寫 hex 接受，但一律正規化為小寫（進 payload 的是小寫）。"""
        proc, payload_out = self.run_preflight(trusted_commit="A" * 40)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        payload = json.loads(payload_out.read_text(encoding="utf-8"))
        self.assertEqual(payload["source_commit"], "a" * 40)

    # ---------------- 2. 申請檔欄位驗證 ----------------

    def test_task_id_injection_and_shape_rejected(self):
        for bad in (
            "T02; rm -rf /", "T02\nEVIL", "T02 EVIL", "ＡＢＣ", "x" * 65,
            "", "-leading-dash", "T02$(whoami)",
        ):
            with self.subTest(task_id=bad):
                self.write_verdict_and_request(request_overrides={"task_id": bad})
                proc, _ = self.run_preflight()
                self.assertNotEqual(proc.returncode, 0, f"task_id={bad!r} 應被拒")

    def test_version_shape_rejected(self):
        for bad in ("ABC" + "0" * 61, "a" * 63, "a" * 65, "g" * 64, "", "0X" + "0" * 62):
            with self.subTest(version=bad[:20]):
                self.write_verdict_and_request(request_overrides={"version": bad})
                proc, _ = self.run_preflight()
                self.assertNotEqual(proc.returncode, 0, f"version={bad!r} 應被拒")

    def test_version_must_equal_audit_sha(self):
        self.write_verdict_and_request(request_overrides={"version": "f" * 64})
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("version 與受驗稽核器", proc.stderr)

    def test_pending_ids_shape_rejected(self):
        for bad in ([], "not-a-list", ["ok", "bad id"], ["ok", 123], [""], ["a" * 65]):
            with self.subTest(pending_ids=bad):
                self.write_verdict_and_request(request_overrides={"pending_ids": bad})
                proc, _ = self.run_preflight()
                self.assertNotEqual(proc.returncode, 0, f"pending_ids={bad!r} 應被拒")

    def test_result_path_shape_rejected(self):
        for bad in ("/etc/passwd", "../evil.md", "a/../../b.md", "", "sp ace.md"):
            with self.subTest(result_path=bad):
                self.write_verdict_and_request(request_overrides={"result_path": bad})
                proc, _ = self.run_preflight()
                self.assertNotEqual(proc.returncode, 0, f"result_path={bad!r} 應被拒")

    def test_result_sha_shape_rejected(self):
        for bad in ("ABC" + "0" * 61, "a" * 63, "", "z" * 64):
            with self.subTest(result_sha=bad[:20]):
                self.write_verdict_and_request(request_overrides={"result_sha256": bad})
                proc, _ = self.run_preflight()
                self.assertNotEqual(proc.returncode, 0, f"result_sha256={bad!r} 應被拒")

    def test_result_sha_must_match_file(self):
        self.write_verdict_and_request(request_overrides={"result_sha256": "d" * 64})
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("結果檔 SHA256 與申請檔不符", proc.stderr)

    def test_schema_version_rejected(self):
        self.write_verdict_and_request(request_overrides={"schema": 2})
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)

    # ---------------- 3. 雙源比對 ----------------

    def test_dual_source_audit_mismatch_rejected(self):
        target = self.tag_tree / "T02-discipline-audit.py"
        target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("受驗檔雙源不一致", proc.stderr)

    def test_dual_source_request_mismatch_rejected(self):
        (self.tag_tree / "T02-sign-request.json").write_text("{}\n", encoding="utf-8")
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("受驗檔雙源不一致", proc.stderr)

    def test_workflow_self_fingerprint_mismatch_rejected(self):
        (self.tag_tree / ".github" / "workflows" / "t02-sign-receipt.yml").write_text(
            "name: evil\n", encoding="utf-8"
        )
        proc, _ = self.run_preflight()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("workflow 自指紋不一致", proc.stderr)

    # ---------------- 4. assemble ----------------

    def test_assemble_builds_receipt_with_fingerprint(self):
        proc, payload_out = self.run_preflight()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        sig = self.root / "sig.bin"
        sig.write_bytes(b"fake-signature-bytes")
        pub = self.root / "pub.pem"
        pub.write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", encoding="utf-8")
        receipt_out = self.root / "receipt.json"
        proc2 = subprocess.run(
            [PY, str(self.trusted_tree / "t02-ci-payload.py"), "assemble",
             "--trusted-tree", str(self.trusted_tree),
             "--payload-bin", str(payload_out), "--sig-bin", str(sig),
             "--pub-pem", str(pub), "--receipt-out", str(receipt_out)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc2.returncode, 0, proc2.stdout + proc2.stderr)
        receipt = json.loads(receipt_out.read_text(encoding="utf-8"))
        self.assertEqual(receipt["schema"], 1)
        self.assertEqual(base64.b64decode(receipt["payload_b64"]), payload_out.read_bytes())
        self.assertEqual(base64.b64decode(receipt["signature_b64"]), b"fake-signature-bytes")
        self.assertTrue(receipt["key_fingerprint"])


class WorkflowStructureTest(unittest.TestCase):
    """`github-actions/t02-sign-receipt.yml`（權威副本）的結構斷言（純文字／正則）。"""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW_COPY.read_text(encoding="utf-8")
        # 去註釋行後的「程式碼正文」（避免註釋文字造成假陽／假陰）。
        cls.code = "\n".join(
            line for line in cls.text.splitlines()
            if not line.lstrip().startswith("#")
        )

    def test_trigger_is_tag_push(self):
        self.assertIn("'t02-sign-*'", self.text)
        self.assertIn("'t02-probe-*'", self.text)

    def test_sign_job_uses_protected_environment(self):
        self.assertIn("environment: t02-signing", self.text)

    def test_checkout_locked_and_both_trees(self):
        refs = re.findall(r"uses:\s*actions/checkout@([^\s#]+)", self.text)
        self.assertTrue(refs, "找不到 checkout 步驟")
        for ref in refs:
            self.assertRegex(ref, r"^[0-9a-f]{40}$", f"checkout 未鎖 commit：{ref}")
        self.assertGreaterEqual(self.text.count("ref: ${{ github.sha }}"), 1)
        self.assertGreaterEqual(self.text.count("ref: ${{ vars.TRUSTED_COMMIT }}"), 2)

    def test_key_step_exists_and_guards_empty_secret(self):
        self.assertEqual(
            self.text.count("secrets.T02_SIGNING_KEY"), 1,
            "應恰好一個步驟持有私鑰（environment secret 引用恰一次）",
        )
        self.assertIn('if [ -z "${T02_SIGNING_KEY:-}" ]', self.text)
        self.assertIn("拒絕簽發", self.text)
        self.assertIn("umask 077", self.text)

    def test_no_shell_trace_and_openssl_out_only(self):
        self.assertNotIn("set -x", self.code, "不得開啟 shell trace（防金鑰入日誌）")
        self.assertIn('-out "$D/sig.bin"', self.code)
        self.assertIn('-out "$D/pub.pem"', self.code)

    def test_no_inputs_interpolation(self):
        """本 workflow 沒有可注入的 inputs：不得出現 ${{ inputs.* }} 插值。"""
        self.assertNotIn("${{ inputs.", self.code)
        self.assertNotIn("github.event.inputs", self.code)

    def test_other_actions_pinned(self):
        refs = re.findall(r"uses:\s*([^\s@]+)@([^\s#]+)", self.text)
        for name, ref in refs:
            self.assertRegex(ref, r"^[0-9a-f]{40}$", f"{name} 未鎖 commit：{ref}")

    def test_private_key_excludes_repo_workspace(self):
        self.assertIn('$RUNNER_TEMP/t02-sign', self.code)
        # 私鑰步驟不得引用 GITHUB_WORKSPACE（程式碼正文中不得出現）
        self.assertNotIn("GITHUB_WORKSPACE", self.code)

    def test_toctou_guard_present(self):
        self.assertIn("payload 一致性確認通過", self.text)
        self.assertIn("needs.preflight.outputs.payload_sha256", self.text)

    def test_preflight_outputs_and_artifact(self):
        self.assertIn("payload_sha256: ${{ steps.pre.outputs.payload_sha256 }}", self.text)
        self.assertIn("actions/upload-artifact@", self.text)
        self.assertIn("if-no-files-found: error", self.text)

    def test_persist_credentials_disabled(self):
        self.assertEqual(
            self.code.count("persist-credentials: false"),
            len(re.findall(r"uses:\s*actions/checkout@", self.code)),
            "每個 checkout 都要 persist-credentials: false",
        )


if __name__ == "__main__":
    sys.exit(0 if unittest.main(verbosity=2).result.wasSuccessful() else 1)
