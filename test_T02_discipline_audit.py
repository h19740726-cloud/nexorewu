#!/usr/bin/env python3
"""T02 紀律稽核器 · 隔離驗收測試（第 10 輪）。

🔴 第 10 輪整改（對應第 9 輪退件 §6 第 1、2 條）：**卡號不再從 user content 取**。
第 9 輪把「boundary 訊息的單行宣告」當成卡號來源之一；驗收方實測證明它可被
縮排 code block／未閉合 fence 偽造並取得 `PASS`。本輪起，卡號只認：

  1. 事件欄位 `event.task_id` / `event.card_id`
  2. 環境變數 `T02_TASK_ID`（測試用 `run_case(identity=...)` 注入）

⚠️ `user(..., card=...)` 參數**保留但無效**（不再寫進訊息），只是閱讀輔助；
真正的 identity 一律走 `identity=` 或 event 欄位。

測試仍會放一份 `T02_CARD_MAP` 映射（proj-1 → test-card）在環境裡，
用途是反向證明程式**不再讀它**。
"""

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


SCRIPT = Path(__file__).with_name("T02-discipline-audit.py")
OPENSSL = "/usr/bin/openssl"

# 🔴 第 12 輪：**對稱通行碼已作廢**。下列常數只留作「餌」：
# 測試照樣把它塞進環境變數，用來反向證明程式**不再讀它**（程式改為驗簽 receipt）。
TEST_REVIEW_TOKEN = "test-review-token-2026"
TEST_REVIEW_TOKEN_SHA256 = hashlib.sha256(TEST_REVIEW_TOKEN.encode("utf-8")).hexdigest()


def script_version():
    """受驗版本的識別碼：腳本本身的 SHA256。驗收結果與 receipt 都必須綁這一版。"""
    return hashlib.sha256(SCRIPT.read_bytes()).hexdigest()


# ------------------------------------------------------------------ 第 12 輪：receipt 測試工具

def canonical_payload(payload: dict) -> bytes:
    """與受驗腳本 `canonical_payload()` **逐位元一致**的正規化形式（簽／驗唯一真相源）。"""
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def pubkey_fingerprint(pem: str) -> str:
    normalized = "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def make_keypair(priv_path: Path, pub_path: Path) -> None:
    """以 openssl 產生 ECDSA P-256 金鑰對（私鑰＝外部主體持有；測試用）。"""
    subprocess.run(
        [OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(priv_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        [OPENSSL, "ec", "-in", str(priv_path), "-pubout", "-out", str(pub_path)],
        check=True, capture_output=True,
    )


def sign_bytes(priv_path: Path, workdir: Path, data: bytes) -> bytes:
    data_file = workdir / "payload.bin"
    sig_file = workdir / "sig.bin"
    data_file.write_bytes(data)
    subprocess.run(
        [OPENSSL, "dgst", "-sha256", "-sign", str(priv_path), "-out", str(sig_file), str(data_file)],
        check=True, capture_output=True,
    )
    return sig_file.read_bytes()


def make_receipt(priv_path: Path, workdir: Path, payload: dict, pub_pem: str) -> dict:
    """把 payload 簽成 receipt 物件（格式與受驗腳本 `verify_receipt()` 約定一致）。"""
    data = canonical_payload(payload)
    signature = sign_bytes(priv_path, workdir, data)
    return {
        "schema": 1,
        "payload_b64": base64.b64encode(data).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "key_fingerprint": pubkey_fingerprint(pub_pem),
    }


def patched_script(dest_dir: Path, pubkey_pem: str) -> Path:
    """複製受驗腳本，**只把內嵌公鑰常數換成測試公鑰**（受驗本體一行不動）。

    公鑰是寫死的常數，測試不可能在不改腳本的情況下換金鑰；因此測試改的是
    **自己的副本**（只替換那一行），受驗腳本本體與其 SHA256 完全不變。
    """
    src = SCRIPT.read_text(encoding="utf-8")
    sentinel = 'RECEIPT_PUBKEY_PEM = ""'
    if sentinel not in src:
        raise AssertionError("受驗腳本找不到內嵌公鑰常數（結構已變動，測試需同步）")
    patched = src.replace(sentinel, "RECEIPT_PUBKEY_PEM = " + json.dumps(pubkey_pem), 1)
    out = dest_dir / "T02-audit-with-testkey.py"
    out.write_text(patched, encoding="utf-8")
    return out


def user(session, identifier="u1", card=None, text="<user_query>測試</user_query>"):
    """本輪 user 訊息。

    🔴 第 10 輪整改：`card` 參數**保留但刻意不再寫進訊息內容**。
    卡號已不再從 user content 取（第 9 輪退件 §6 第 1、2 條），
    這個參數現在只是「這則訊息在講哪張卡」的閱讀輔助，**不構成 identity**。
    真正的 identity 一律由 `run_case(identity=...)`（＝環境變數 injector 通道）提供。
    """
    return {
        "type": "message",
        "role": "user",
        "content": text,
        "id": identifier,
        "sessionId": session,
    }


def skill(session, name, identifier, completed=True, has_content=True):
    rows = [
        {
            "type": "function_call",
            "name": "Skill",
            "arguments": json.dumps({"skill": name}),
            "id": identifier,
            "sessionId": session,
        }
    ]
    if completed:
        rows.append(
            {
                "type": "function_call_result",
                "name": "Skill",
                "callId": identifier,
                "status": "completed",
                "output": {"type": "text", "text": "skill contents" if has_content else ""},
                "sessionId": session,
            }
        )
    return rows


def tool(session, name, identifier):
    return {
        "type": "function_call",
        "name": name,
        "arguments": "{}",
        "id": identifier,
        "sessionId": session,
    }


def assistant(session, text="已經答話"):
    return {"type": "message", "role": "assistant", "content": text, "sessionId": session}


def plain_user(session, identifier="u2", text="Stop hook feedback: 測試用"):
    """沒有 <user_query> 標記、也沒有卡號宣告的 user 訊息（例：Stop hook 回饋）。"""
    return {
        "type": "message",
        "role": "user",
        "content": text,
        "id": identifier,
        "sessionId": session,
    }


def nested_user(session, identifier, text="<user_query>測試</user_query>"):
    """巢狀形狀的 user 訊息：role／content／messageId 都包在 `message` 裡。"""
    return {
        "type": "message",
        "message": {"role": "user", "content": text, "messageId": identifier},
        "sessionId": session,
    }


class DisciplineAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 第 12 輪：class 層級產生一組測試金鑰對，並做一份「內嵌測試公鑰」的受驗腳本副本。
        # 受驗腳本本體與其 SHA256 不變（只換副本裡的那一行常數）。
        cls._keydir = tempfile.TemporaryDirectory()
        kd = Path(cls._keydir.name)
        cls.priv_pem_path = kd / "test-priv.pem"
        cls.pub_pem_path = kd / "test-pub.pem"
        make_keypair(cls.priv_pem_path, cls.pub_pem_path)
        cls.pub_pem = cls.pub_pem_path.read_text(encoding="utf-8")
        cls.script = patched_script(kd, cls.pub_pem)

    @classmethod
    def tearDownClass(cls):
        cls._keydir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.log = self.root / "audit.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    # ---------------- 第 12 輪：receipt 產生輔助 ----------------

    def receipt_payload(self, card_id="test-card", *, version=None, result_path=None,
                        nonce=None, pending_ids=None, task_id=None, sha=None):
        """組一份 receipt payload；預設值＝「合法且與現況相符」。"""
        ids = self.pending_ids_for(card_id) if pending_ids is None else list(pending_ids)
        digest = sha
        if digest is None:
            digest = (
                hashlib.sha256(Path(result_path).read_bytes()).hexdigest()
                if result_path else ""
            )
        return {
            "task_id": card_id if task_id is None else task_id,
            "version": version if version is not None else script_version(),
            "pending_ids": ids,
            "result_sha256": digest,
            "issued_at": "2026-10-13T00:00:00Z",
            "nonce": nonce if nonce is not None else uuid.uuid4().hex,
        }

    def write_receipt(self, payload, *, path=None, priv_path=None, pub_pem=None):
        """把 payload 簽成 receipt 並落檔，回檔案路徑。"""
        target = Path(path) if path else (self.root / "receipt.json")
        receipt = make_receipt(
            priv_path or self.priv_pem_path,
            self.root,
            payload,
            pub_pem if pub_pem is not None else self.pub_pem,
        )
        target.write_text(json.dumps(receipt, ensure_ascii=False), encoding="utf-8")
        return target

    def isolated_env(self, env_extra=None):
        env = os.environ.copy()
        env["T02_DISCIPLINE_LOG"] = str(self.log)
        # 每個測試用獨立的 pending 存放位置，避免測試互相污染。
        env["T02_PENDING_PATH"] = str(self.root / "pending.json")
        # 第 8 輪（驗收第 6 條）：先把父程序帶進來的卡號相關變數**清乾淨**，再由
        # env_extra 明確加入本案需要的值；`T02_CARD_FILE` 也必須清（舊版會讀它）。
        for key in ("T02_TASK_ID", "T02_CARD_MAP", "T02_CARD_FILE", "T02_CARD_DECL", "T02_TASKS_DIR"):
            env.pop(key, None)
        # 第 9 輪（驗收第 3 條後半）：權威卡片清單指向測試自造的 tasks 目錄，
        # 內含本測試會用到的全部卡號檔（檔名前綴＝卡號）。
        tasks_dir = self.root / "tasks"
        # 🔴 不要用 mkdir(exist_ok=True)：WorkBuddy 沙盒的 sitecustomize broker 即使
        #    exist_ok=True、目錄已存在，仍會拋 EEXIST。改為先判斷存在再建。
        if not tasks_dir.exists():
            tasks_dir.mkdir()
        for name in (
            "test-card",
            "CARD-A",
            "CARD-B",
            "T02-disposable",
            "FROM-EVENT",
            "T02",
            "T01-2",
            "t02.audit",
            "T03",
            "SPOOFED",
        ):
            marker = tasks_dir / f"{name}.md"
            if not marker.exists():
                marker.write_text("# 測試卡片（權威清單用）\n", encoding="utf-8")
        env["T02_TASKS_DIR"] = str(tasks_dir)
        # 第 11 輪：核定通行碼（預設給測試值；要驗「未設定」就在 env_extra 覆蓋成 ""）。
        env["T02_REVIEW_TOKEN_SHA256"] = TEST_REVIEW_TOKEN_SHA256
        env["T02_REVIEW_TOKEN_PATH"] = str(self.root / "no-such-token-file")
        # 第 8 輪：測試仍然放一份「專案 → 卡號」映射，但**新程式不再讀它**。
        # 這一顆餌是刻意留的：舊程式會據此回 test-card，新程式必須忽略它。
        card_map = self.root / "card-map.json"
        if not card_map.exists():
            card_map.write_text(
                json.dumps({"proj-1": "test-card"}, ensure_ascii=False), encoding="utf-8"
            )
        env["T02_CARD_MAP"] = str(card_map)
        for key, value in (env_extra or {}).items():
            env[key] = str(value)
        return env

    def run_case(
        self,
        rows,
        session="session-1",
        project="proj-1",
        env_extra=None,
        identity="test-card",
        **event_updates,
    ):
        """跑一輪 Stop。

        第 10 輪（identity 通道）：`identity` 是**本輪卡號**，預設 `"test-card"`，
        由環境變數（＝injector 通道）注入。要驗「缺卡號」就傳 `identity=""`；
        要驗「event 提供卡號」就傳 `task_id=`／`card_id=`（此時不再注入 env，避免偽衝突）。
        **user content 不構成 identity**，訊息裡寫什麼都不影響解析結果。
        """
        extra = dict(env_extra or {})
        if "task_id" in event_updates or "card_id" in event_updates:
            extra.pop("T02_TASK_ID", None)
        elif identity:
            extra["T02_TASK_ID"] = identity
        # transcript 仍寫在「專案目錄」底下：這是為了證明**專案目錄不再影響卡號**。
        project_dir = self.root / project
        project_dir.mkdir(parents=True, exist_ok=True)
        transcript = project_dir / f"{session}.jsonl"
        transcript.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        event = {
            "hook_event_name": "Stop",
            "session_id": session,
            "generation_id": "generation-1",
            "transcript_path": str(transcript),
            "stop_hook_active": False,
        }
        event.update(event_updates)
        result = subprocess.run(
            ["/usr/bin/python3", str(self.script)],
            input=json.dumps(event),
            text=True,
            capture_output=True,
            env=self.isolated_env(extra),
            check=False,
        )
        records = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        return result, records[-1]

    def run_cli(self, *args, env_extra=None, identity="test-card"):
        """跑稽核器的 CLI 子命令（--status／--clear）。一律給 stdin，避免子行程卡住。"""
        extra = dict(env_extra or {})
        if identity:
            extra["T02_TASK_ID"] = identity
        return subprocess.run(
            ["/usr/bin/python3", str(self.script), *args],
            input="",
            text=True,
            capture_output=True,
            env=self.isolated_env(extra),
            check=False,
        )

    def run_cli_raw(self, script, *args, env_extra=None, identity="test-card"):
        """用**指定腳本**跑 CLI（第 12 輪：用來測「公鑰未安裝」時的原腳本行為）。"""
        extra = dict(env_extra or {})
        if identity:
            extra["T02_TASK_ID"] = identity
        return subprocess.run(
            ["/usr/bin/python3", str(script), *args],
            input="",
            text=True,
            capture_output=True,
            env=self.isolated_env(extra),
            check=False,
        )

    def pending_ids_for(self, card_id) -> list[str]:
        """讀 pending 存放區，回該卡所有 entry 的 pending_id（排序）。"""
        path = self.root / "pending.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        ids = [
            str(item.get("pending_id") or "")
            for item in data.values()
            if isinstance(item, dict) and str(item.get("task_id") or "") == card_id
        ]
        return sorted(ids)

    def write_verdict(self, path, card_id, version, *, task_id=True, pending_ids=True, marker=True):
        """寫一份驗收結果檔（預設齊備：`task_id` ＋ `pending_ids` ＋ VERDICT 標記）。

        第 11 輪：結果檔必須綁定目標卡與待清的 pending IDs。
        """
        lines = ["判定：通過"]
        if task_id:
            lines.append(f"task_id={card_id}")
        if pending_ids:
            lines.append("pending_ids=" + ",".join(self.pending_ids_for(card_id)))
        if marker:
            lines.append(f"<!-- T02-VERDICT: pass version={version} -->")
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def assert_consistent(self, record):
        """第 8 輪（驗收第 5 條）總判定語義不變式。"""
        if record.get("result") == "PASS":
            self.assertTrue(record.get("completion_allowed"), record)
            self.assertFalse(record.get("pending_violation"), record)
        else:
            self.assertFalse(record.get("completion_allowed", False), record)

    # ---------------- Skill 載入（既有） ----------------

    def test_interaction_skill_passes_non_mutating_turn(self):
        session = "session-1"
        result, record = self.run_case(
            [user(session), *skill(session, "daqiang-interaction-method", "s1"), assistant(session)]
        )
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        self.assertEqual(record["result"], "PASS")
        self.assert_consistent(record)

    def test_zero_skill_is_blocked(self):
        session = "session-1"
        result, record = self.run_case([user(session)])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertEqual(result.stderr, "")
        self.assertEqual(record["result"], "BLOCK")

    def test_mutation_requires_two_work_skills(self):
        session = "session-1"
        rows = [user(session), *skill(session, "daqiang-interaction-method", "s1"), tool(session, "Edit", "e1")]
        result, record = self.run_case(rows)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertEqual(record["required_skills"], ["daqiang-work-discipline", "prework-anti-fake-completion"])

    def test_work_skills_before_edit_pass(self):
        session = "session-1"
        rows = [
            user(session),
            *skill(session, "daqiang-work-discipline", "s1"),
            *skill(session, "prework-anti-fake-completion", "s2"),
            tool(session, "Edit", "e1"),
        ]
        result, record = self.run_case(rows)
        self.assertEqual((result.stdout, result.stderr, record["result"]), ("", "", "PASS"))

    def test_stale_previous_turn_skill_does_not_count(self):
        session = "session-1"
        rows = [user(session, "u1"), *skill(session, "daqiang-interaction-method", "s1"), user(session, "u2")]
        result, record = self.run_case(rows)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertEqual(record["user_boundary_id"], "u2")

    def test_late_work_skills_are_blocked(self):
        session = "session-1"
        rows = [
            user(session),
            tool(session, "Edit", "e1"),
            *skill(session, "daqiang-work-discipline", "s1"),
            *skill(session, "prework-anti-fake-completion", "s2"),
        ]
        result, record = self.run_case(rows)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertIn("晚於", "".join(record["reason"]))

    def test_skill_after_assistant_reply_is_blocked(self):
        session = "session-1"
        rows = [user(session), assistant(session), *skill(session, "daqiang-interaction-method", "s1")]
        result, record = self.run_case(rows)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertIn("第一則回覆", "".join(record["reason"]))

    def test_incomplete_skill_call_does_not_count(self):
        session = "session-1"
        result, record = self.run_case([user(session), *skill(session, "daqiang-interaction-method", "s1", False)])
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertEqual(record["observed_skills"], [])

    def test_empty_completed_result_does_not_count(self):
        session = "session-1"
        rows = [user(session), *skill(session, "daqiang-interaction-method", "s1", has_content=False)]
        result, record = self.run_case(rows)
        self.assertEqual(json.loads(result.stdout)["decision"], "block")
        self.assertEqual(record["observed_skills"], [])

    def test_session_mismatch_is_error_allow(self):
        session = "session-1"
        result, record = self.run_case([user(session)], session_id="other-session")
        self.assertEqual(result.stdout, "")
        self.assertIn("ERROR_ALLOW", result.stderr)
        self.assertEqual(record["result"], "ERROR_ALLOW")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assert_consistent(record)

    def test_second_stop_fails_open_to_prevent_loop(self):
        session = "session-1"
        result, record = self.run_case([user(session)], stop_hook_active=True)
        self.assertEqual(result.stdout, "")
        self.assertIn("FAIL_OPEN_RETRY", result.stderr)
        self.assertEqual(record["result"], "FAIL_OPEN_RETRY")

    def test_interrupted_turn_is_allowed(self):
        session = "session-1"
        result, record = self.run_case([user(session)], last_assistant_message="Interrupted by user")
        self.assertEqual((result.stdout, result.stderr), ("", ""))
        self.assertEqual(record["result"], "INTERRUPTED_ALLOW")

    def test_repeated_skill_load_is_not_late(self):
        """同一支技能在同一個視窗內載兩次時，取最早那次為準，不得判「晚於」。"""
        session = "session-1"
        rows = [
            user(session),
            *skill(session, "daqiang-interaction-method", "s1"),
            assistant(session),
            *skill(session, "daqiang-interaction-method", "s2"),
        ]
        result, record = self.run_case(rows)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(record["result"], "PASS")

    def test_retry_marks_task_unfinished(self):
        """第二次 Stop 放行時，必須留下「未完成」後果，不得因放行而取得完成資格。"""
        session = "session-1"
        rows = [user(session), tool(session, "Edit", "e1")]
        result, record = self.run_case(rows, stop_hook_active=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(record["result"], "FAIL_OPEN_RETRY")
        self.assertEqual(record.get("pending_violation"), True)
        self.assertEqual(record.get("task_status"), "進行中")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertTrue(record.get("pending_rules"))

    def test_producer_signature_cannot_clear(self):
        """空洞署名（沒有綁版本與結果的「--by」）不得清除 pending。產出者不能自己核定。"""
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        refused = self.run_cli("--clear", "test-card", "--by", "WorkBuddy")
        self.assertNotEqual(refused.returncode, 0)
        still = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(still.stdout)["completion_allowed"], False)

    # ---------------- 第 12 輪：第 11 輪攻擊回歸（先紅後綠） ----------------

    def test_attack_producer_can_set_review_hash(self):
        """🔴 第 12 輪攻擊回歸（第 11 輪退件 §5 第 1、2 條）。

        攻擊：產出者自行設定**呼叫者可控制的最高優先來源**
          `T02_REVIEW_TOKEN_SHA256`（以及 `T02_REVIEW_TOKEN_PATH`），
        再拿自己選的 token 去 `--clear`。

        期望（修復後）：**不得清除**（rc != 0、pending 仍開著）。
        修正前（第 11 輪）：此攻擊成功（rc=0、pending 被清）→ 本測試 FAIL（＝先紅）。
        """
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        before = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(before.stdout)["completion_allowed"], False)

        attacker_token = "producer-chosen-token"
        verdict = self.root / "T02-attack-verdict.md"
        self.write_verdict(verdict, "test-card", script_version())

        attacked = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "WorkBuddy",
            env_extra={
                "T02_REVIEW_TOKEN_SHA256": hashlib.sha256(
                    attacker_token.encode("utf-8")
                ).hexdigest(),
                "T02_REVIEW_TOKEN_PATH": str(self.root / "no-such-token-file"),
            },
        )
        self.assertNotEqual(
            attacked.returncode, 0,
            "產出者自設預期 hash 竟然能清除 pending（攻擊成功）",
        )
        after = self.run_cli("--status", "test-card")
        self.assertEqual(
            json.loads(after.stdout)["completion_allowed"], False,
            "被攻擊後 pending 竟被標成完成",
        )

    def test_pending_cleared_only_by_reviewer(self):
        """pending 只能由附上「合格驗收結果 ＋ 有效簽章 receipt」的 CLI 清除，之後才允許完成。"""
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        before = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(before.stdout)["completion_allowed"], False)

        verdict = self.root / "T02-驗收結果-第12輪.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict)
        )
        cleared = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertEqual(cleared.returncode, 0, cleared.stdout + cleared.stderr)
        self.assertIn("cleared", cleared.stdout)
        after = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(after.stdout)["completion_allowed"], True)

    def test_clear_rejects_version_mismatch(self):
        """receipt 綁的是別的版本時，不得清除（版本不符即拒絕）。"""
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "T02-驗收結果-第12輪.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict, version="deadbeef")
        )
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0)
        still = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(still.stdout)["completion_allowed"], False)

    def test_corrupt_pending_store_blocks_completion(self):
        """pending 存放區存在但無法解析時，一律保守拒絕完成，不得退成「沒有資料」。"""
        (self.root / "pending.json").write_text("{broken", encoding="utf-8")
        clean = [
            user("session-1", "u1"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            *skill("session-1", "daqiang-work-discipline", "s1"),
            *skill("session-1", "prework-anti-fake-completion", "s2"),
        ]
        _, record = self.run_case(clean)
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertNotEqual(record.get("result"), "PASS")
        status = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(status.stdout)["completion_allowed"], False)

    def test_deleted_pending_store_still_blocks(self):
        """pending 存放區被整個刪掉時，仍要靠不可竄改的稽核日誌回推「這張卡未完成」。"""
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        (self.root / "pending.json").unlink()
        # 第 9 輪：pending 聚合鍵改為「只按卡號」，故以卡號查（identity 預設提供 test-card）。
        status = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(status.stdout)["completion_allowed"], False)
        clean = [
            user("session-1", "u1"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            *skill("session-1", "daqiang-work-discipline", "s1"),
            *skill("session-1", "prework-anti-fake-completion", "s2"),
        ]
        _, record = self.run_case(clean)
        self.assertEqual(record.get("completion_allowed"), False)

    def test_task_id_persists_across_boundaries(self):
        """同一張卡換了 user 訊息邊界後，仍要認得未清的 pending（不能只認 boundary）。"""
        task = "T02-disposable"
        rows = [user("session-1", "u1"), tool("session-1", "Edit", "e1")]
        _, first = self.run_case(
            rows, env_extra={"T02_TASK_ID": task}, stop_hook_active=True, identity=""
        )
        self.assertEqual(first.get("completion_allowed"), False)
        clean = [
            user("session-1", "u2"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
        ]
        _, second = self.run_case(clean, env_extra={"T02_TASK_ID": task}, identity="")
        self.assertEqual(second.get("completion_allowed"), False)
        status = self.run_cli(
            "--status", task, env_extra={"T02_TASK_ID": task}, identity=""
        )
        self.assertEqual(json.loads(status.stdout)["completion_allowed"], False)

    def test_out_of_order_completion_takes_earliest(self):
        """同一支技能有兩次呼叫、完成順序交錯時，取真正最早的完成位置，不得取呼叫插入順序。"""
        session = "session-1"
        rows = [
            user(session),
            skill(session, "daqiang-interaction-method", "slow", completed=False)[0],
            *skill(session, "daqiang-interaction-method", "fast"),
            assistant(session),
            skill(session, "daqiang-interaction-method", "slow")[1],
        ]
        result, record = self.run_case(rows)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(record["result"], "PASS")

    def test_first_block_never_allows_completion(self):
        """首次 Stop 就被擋下時，紀錄不得同時宣稱「可完成」。"""
        session = "session-1"
        _, record = self.run_case([user(session)])
        self.assertEqual(record["result"], "BLOCK")
        self.assertEqual(record.get("completion_allowed"), False)

    def test_new_session_same_task_still_blocked(self):
        """換到另一個 session（新的對話檔）時，同一張卡的 pending 不得因此消失。"""
        task = "T02-disposable"
        rows = [user("session-1", "u1"), tool("session-1", "Edit", "e1")]
        self.run_case(rows, env_extra={"T02_TASK_ID": task}, stop_hook_active=True)
        other = [
            user("session-2", "u9"),
            *skill("session-2", "daqiang-interaction-method", "s0"),
            *skill("session-2", "daqiang-work-discipline", "s1"),
            *skill("session-2", "prework-anti-fake-completion", "s2"),
        ]
        _, record = self.run_case(other, session="session-2", env_extra={"T02_TASK_ID": task})
        self.assertEqual(record.get("completion_allowed"), False)

    def test_unwritable_log_blocks_completion(self):
        """稽核結果寫不進去時，不得宣稱完成（無法稽核就不得取得完成資格）。"""
        transcript = self.root / "session-1.jsonl"
        rows = [user("session-1", "u1")]
        rows += skill("session-1", "daqiang-interaction-method", "s0")
        transcript.write_text(
            "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
            encoding="utf-8",
        )
        blocked = self.root / "logdir"
        blocked.mkdir()
        event = {
            "hook_event_name": "Stop",
            "session_id": "session-1",
            "generation_id": "generation-1",
            "transcript_path": str(transcript),
            "stop_hook_active": False,
        }
        result = subprocess.run(
            ["/usr/bin/python3", str(self.script)],
            input=json.dumps(event),
            text=True,
            capture_output=True,
            env=self.isolated_env({"T02_DISCIPLINE_LOG": str(blocked)}),
            check=False,
        )
        self.assertIn('"decision":"block"', result.stdout)

    # ---------------- 第 8 輪：卡號來源與保守拒絕（驗收第 1、2 條） ----------------

    def test_project_directory_is_not_a_card_id(self):
        """驗收第 1 條（先紅後綠）：專案目錄是工作區，**不得**再被當成卡號。

        測試刻意在環境裡放一份 proj-1 → test-card 的映射：
        舊程式會回 test-card（紅），新程式必須完全忽略它並回空字串（綠）。
        """
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        # identity="" ＝ 不注入 env 卡號，模擬「正式流程沒有提供卡號」的真實形狀。
        _, record = self.run_case(rows, identity="")
        self.assertEqual(record.get("task_id"), "")
        self.assertEqual(record.get("completion_allowed"), False)

    def test_env_card_map_is_ignored(self):
        """驗收第 1 條：明確提供 T02_CARD_MAP 時，新程式仍不得拿它當卡號。"""
        mapped = self.root / "explicit-map.json"
        mapped.write_text(json.dumps({"proj-1": "MAPPED-CARD"}), encoding="utf-8")
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(rows, env_extra={"T02_CARD_MAP": str(mapped)}, identity="")
        self.assertEqual(record.get("task_id"), "")

    def test_same_project_two_cards_by_declaration(self):
        """驗收第 1 條（先紅後綠）：同一 project、**同一 session**，卡 A → 卡 B 要分得開。

        兩張卡用「訊息裡的明確宣告」區分。卡 A 留下的 pending 不得波及卡 B。
        """
        session = "session-1"
        _, rec_a = self.run_case(
            [user(session, "u1"), tool(session, "Edit", "e1")],
            stop_hook_active=True,
            identity="CARD-A",
        )
        self.assertEqual(rec_a.get("task_id"), "CARD-A")
        self.assertEqual(rec_a.get("completion_allowed"), False)
        _, rec_b = self.run_case(
            [
                user(session, "u9"),
                *skill(session, "daqiang-interaction-method", "s0"),
                assistant(session),
            ],
            identity="CARD-B",
        )
        self.assertEqual(rec_b.get("task_id"), "CARD-B")
        self.assertEqual(rec_b.get("completion_allowed"), True)
        self.assertEqual(rec_b.get("result"), "PASS")
        self.assert_consistent(rec_b)

    def test_same_project_across_sessions_two_cards(self):
        """驗收第 1 條：同一 project、**不同 session**，卡 A → 卡 B 同樣要分得開。"""
        _, rec_a = self.run_case(
            [user("session-1", "u1"), tool("session-1", "Edit", "e1")],
            session="session-1",
            stop_hook_active=True,
            identity="CARD-A",
        )
        self.assertEqual(rec_a.get("task_id"), "CARD-A")
        _, rec_b = self.run_case(
            [
                user("session-2", "u9"),
                *skill("session-2", "daqiang-interaction-method", "s0"),
                assistant("session-2"),
            ],
            session="session-2",
            identity="CARD-B",
        )
        self.assertEqual(rec_b.get("task_id"), "CARD-B")
        self.assertEqual(rec_b.get("completion_allowed"), True)

    def test_event_task_id_is_a_valid_card_source(self):
        """驗收第 1 條：事件若明確提供 task_id，即為合法卡號來源（優先於宣告）。"""
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(rows, task_id="FROM-EVENT")
        self.assertEqual(record.get("task_id"), "FROM-EVENT")
        self.assertEqual(record.get("result"), "PASS")

    def test_missing_card_is_unconditionally_rejected(self):
        """驗收第 2 條（先紅後綠）：取不到卡號 → **無條件**結構化拒絕完成。

        舊程式在「沒有任何 pending」時會直接 PASS 放行；新程式必須仍拒絕完成。
        """
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        result, record = self.run_case(rows, identity="")
        self.assertEqual(record.get("task_id"), "")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertNotEqual(record.get("result"), "PASS")
        self.assertTrue(any("無法確定當前卡號" in r for r in record.get("reason", [])))
        self.assert_consistent(record)

    def test_other_card_pending_does_not_block_this_card(self):
        """驗收第 2 條（先紅後綠）：卡 A 有 pending 時，不得誤擋乾淨的卡 B。"""
        _, rec_a = self.run_case(
            [user("session-1", "u1"), tool("session-1", "Edit", "e1")],
            stop_hook_active=True,
            identity="CARD-A",
        )
        self.assertEqual(rec_a.get("completion_allowed"), False)
        _, rec_b = self.run_case(
            [
                user("session-1", "u9"),
                *skill("session-1", "daqiang-interaction-method", "s0"),
                assistant("session-1"),
            ],
            identity="CARD-B",
        )
        self.assertEqual(rec_b.get("completion_allowed"), True)
        self.assertEqual(rec_b.get("pending_violation"), False)

    def test_r10_user_content_declaration_is_not_identity(self):
        """🔴 第 10 輪（第 9 輪退件 §6-1／§6-2）：user content 的宣告一律**不構成身份**。

        第 9 輪把它當成卡號來源之一；驗收方實測證明可被「縮排 code block」「未閉合 fence」
        偽造並取得 `PASS`。本輪起，寫在訊息裡的 `task-card:` 不能產生 identity，
        一律保守拒絕完成。
        """
        for text in (
            "<user_query>測試</user_query>\ntask-card: T02",
            "<user_query>測試</user_query>\n    task-card: T02",
            "<user_query>測試</user_query>\n```\ntask-card: T02",
            "<user_query>測試</user_query>\ntask-card: T02\u2028T03",
            "<user_query>測試</user_query>\ntask-card: T02\u0085",
            "<user_query>測試</user_query>\n~~~\ntask-card: T02",
        ):
            rows = [
                user("session-1", "u1", text=text),
                *skill("session-1", "daqiang-interaction-method", "s0"),
                assistant("session-1"),
            ]
            _, record = self.run_case(rows, identity="")
            self.assertEqual(record.get("task_id"), "", msg=repr(text))
            self.assertEqual(record.get("completion_allowed"), False, msg=repr(text))
            self.assertNotEqual(record.get("result"), "PASS", msg=repr(text))

    # ---------------- 第 8 輪：卡號白名單（驗收第 3 條） ----------------

    def test_card_id_whitelist_rejects_unicode_and_controls(self):
        """驗收第 3 條（先紅後綠）：卡號改 ASCII 白名單，控制／分行／bidi／空白一律不接受。

        舊版只拒絕碼位 < U+0020，所以 U+007F／0085／2028／2029 與 bidi 都會被放行。
        """
        bad_values = [
            "T02\u007f",
            "T02\u0085",
            "T02\u2028",
            "T02\u2029",
            "T02\u202e",
            "T02 03",
            "卡號T02",
        ]
        for bad in bad_values:
            rows = [
                user("session-1", "u1", card=None),
                *skill("session-1", "daqiang-interaction-method", "s0"),
                assistant("session-1"),
            ]
            _, record = self.run_case(rows, task_id=bad)
            self.assertEqual(record.get("task_id"), "", msg=repr(bad))
            self.assertEqual(record.get("completion_allowed"), False, msg=repr(bad))
            self.assertTrue(
                any("不合法" in r for r in record.get("reason", [])), msg=repr(bad)
            )

    def test_card_id_whitelist_accepts_plain_ascii(self):
        """白名單要能接受正常卡號（T02、CARD-A、T01-2 這類）。"""
        for good in ("T02", "CARD-A", "T01-2", "t02.audit"):
            rows = [
                user("session-1", "u1", card=None),
                *skill("session-1", "daqiang-interaction-method", "s0"),
                assistant("session-1"),
            ]
            _, record = self.run_case(rows, task_id=good)
            self.assertEqual(record.get("task_id"), good, msg=good)

    # ---------------- 第 8 輪：boundary ID（驗收第 4 條） ----------------

    def test_boundary_id_skips_illegal_top_level_to_nested(self):
        """驗收第 4 條（先紅後綠）：非空 top-level dict 不得遮蔽合法的巢狀 ID。"""
        row = {
            "type": "message",
            "role": "user",
            "content": "<user_query>測試</user_query>",
            "id": {"bad": 1},
            "message": {"role": "user", "content": "hi", "messageId": "nested-good"},
            "sessionId": "session-1",
        }
        _, record = self.run_case([row])
        self.assertEqual(record.get("user_boundary_id"), "nested-good")

    def test_boundary_id_rejects_non_string_values(self):
        """驗收第 4 條（先紅後綠）：int／bool 候選不得被 `str()` 成 boundary。"""
        row = {
            "type": "message",
            "role": "user",
            "content": "<user_query>測試</user_query>",
            "id": 123,
            "messageId": True,
            "sessionId": "session-1",
        }
        _, record = self.run_case([row])
        self.assertEqual(record.get("user_boundary_id"), "")

    def test_boundary_id_rejects_control_and_line_separators(self):
        """驗收第 4 條：含 U+2028／換行的 ID 不得成為 boundary（也不得污染 pending key）。"""
        row = {
            "type": "message",
            "role": "user",
            "content": "<user_query>測試</user_query>",
            "id": "a\u2028b",
            "messageId": "c\nd",
            "sessionId": "session-1",
        }
        _, record = self.run_case([row])
        self.assertEqual(record.get("user_boundary_id"), "")

    # ---------------- 第 8 輪：總判定語義（驗收第 5 條） ----------------

    def test_pass_does_not_clear_pending_and_is_not_pass(self):
        """驗收第 5 條（先紅後綠）：有未清除 pending 時，不得寫出 PASS + completion_allowed=false。

        舊程式會產生 `result=PASS  completion_allowed=false` 的矛盾紀錄。
        """
        session = "session-1"
        self.run_case([user(session, "u1"), tool(session, "Edit", "e1")], stop_hook_active=True)
        clean = [
            user(session, "u1"),
            *skill(session, "daqiang-interaction-method", "s0"),
            *skill(session, "daqiang-work-discipline", "s1"),
            *skill(session, "prework-anti-fake-completion", "s2"),
        ]
        _, second = self.run_case(clean)
        self.assertEqual(second.get("completion_allowed"), False)
        self.assertEqual(second.get("task_status"), "進行中")
        self.assertEqual(second.get("pending_violation"), True)
        self.assertNotEqual(second.get("result"), "PASS")
        self.assertTrue(any("未清除的未完成紀錄" in r for r in second.get("reason", [])))
        self.assert_consistent(second)

    def test_pass_records_are_self_consistent(self):
        """驗收第 5 條：PASS 紀錄必須一致（completion_allowed=True 且 pending_violation=False）。"""
        rows = [
            user("session-1", "u1"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(rows)
        self.assertEqual(record.get("result"), "PASS")
        self.assertEqual(record.get("completion_allowed"), True)
        self.assertEqual(record.get("pending_violation"), False)

    # ---------------- 第 8 輪：測試環境 hermetic（驗收第 6 條） ----------------

    def test_ambient_card_env_does_not_leak(self):
        """驗收第 6 條：父程序帶 T02_TASK_ID／T02_CARD_FILE 時，測試仍必須是 hermetic。"""
        os.environ["T02_TASK_ID"] = "ambient-card"
        os.environ["T02_CARD_FILE"] = "/does/not/exist"
        try:
            rows = [
                user("session-1", "u1", card=None),
                *skill("session-1", "daqiang-interaction-method", "s0"),
                assistant("session-1"),
            ]
            _, record = self.run_case(rows, identity="")
        finally:
            os.environ.pop("T02_TASK_ID", None)
            os.environ.pop("T02_CARD_FILE", None)
        self.assertEqual(record.get("task_id"), "")

    # ---------------- 既有：boundary 回退（不變） ----------------

    def test_latest_plain_user_becomes_boundary(self):
        """帶 <user_query> 的舊 user 之後又來一筆普通 user 時，boundary 要取較新的那一筆。"""
        session = "session-1"
        rows = [user(session, "u1"), tool(session, "Edit", "e1"), plain_user(session, "u2")]
        _, record = self.run_case(rows)
        self.assertEqual(record["user_boundary_id"], "u2")

    def test_boundary_fallback_uses_tagged_user(self):
        """最新 user 沒有 id 時，回退到「最近的 tagged user」，不是中間那筆普通 user。"""
        session = "session-1"
        rows = [
            user(session, "tagged-1"),
            plain_user(session, "middle"),
            {
                "type": "message",
                "role": "user",
                "content": "Stop hook feedback: 這一筆沒有 id",
                "sessionId": session,
            },
        ]
        _, record = self.run_case(rows)
        self.assertEqual(record["user_boundary_id"], "tagged-1")

    def test_nested_message_id_becomes_boundary(self):
        """巢狀訊息的 `message.messageId` 也要被當成 boundary ID（驗收第 5 條）。"""
        session = "session-1"
        rows = [nested_user(session, "nested-new")]
        _, record = self.run_case(rows)
        self.assertEqual(record["user_boundary_id"], "nested-new")

    def test_nested_tagged_fallback_uses_nested_id(self):
        """最新 user 無 ID 時，回退到的 tagged user 若 ID 只在 `message.messageId`，也要讀到。"""
        session = "session-1"
        rows = [
            nested_user(session, "nested-tagged"),
            {
                "type": "message",
                "role": "user",
                "content": "Stop hook feedback: 這一筆沒有 id",
                "sessionId": session,
            },
        ]
        _, record = self.run_case(rows)
        self.assertEqual(record["user_boundary_id"], "nested-tagged")

    def test_event_keys_are_recorded(self):
        """R1 實測：稽核紀錄要帶宿主實際提供的欄位名（供日後核對 Stop 事件 schema）。"""
        rows = [
            user("session-1", "u1"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(rows)
        for key in ("hook_event_name", "session_id", "generation_id", "transcript_path", "stop_hook_active"):
            self.assertIn(key, record.get("event_keys", []))


    # =================================================================
    # 第 10 輪新增（對應第 9 輪退件 §6 第 1～5 條）
    # 註：原第 9 輪的「宣告」家族測試（A2／A3a／A3b／A4）已作廢，
    #     改由 `test_r10_user_content_declaration_is_not_identity` 統一涵蓋。
    # =================================================================

    def test_r9_a3c_conflicting_sources_are_rejected(self):
        """A3：event 與 card_id 指向不同卡 → 結構化拒絕（不得靜默取先者）。"""
        session = "s1"
        rows = [
            user(session, "u1", card=None),
            *skill(session, "daqiang-interaction-method", "k1"),
            assistant(session),
        ]
        _, record = self.run_case(rows, task_id="CARD-A", card_id="CARD-B")
        self.assertEqual(record.get("task_id"), "")
        self.assertEqual(record.get("completion_allowed"), False)

    def test_r9_a3d_card_not_in_authoritative_list_is_rejected(self):
        """A3（後半）：卡號**不能只驗字形**，不在權威卡片清單 → 結構化拒絕。"""
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(rows, task_id="UNKNOWN-CARD")
        self.assertEqual(record.get("task_id"), "")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertTrue(any("權威卡片清單" in r for r in record.get("reason", [])))

    def test_r9_a3e_unreadable_authoritative_list_is_rejected(self):
        """A3（後半）：權威清單不可讀 → 保守拒絕（無法驗證權威性時不得放行）。"""
        rows = [
            user("session-1", "u1", card=None),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(
            rows, task_id="T02", env_extra={"T02_TASKS_DIR": "/does/not/exist"}
        )
        self.assertEqual(record.get("task_id"), "")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertTrue(any("權威卡片清單" in r for r in record.get("reason", [])))

    def test_r9_a5_boundary_id_trailing_blank_is_rejected(self):
        """A5：boundary ID 的尾端控制／分隔字元不得先被 Unicode trim 再接受。"""
        for bad in ("good\n", "good\u0085", "good\u2028", "good\u061C"):
            session = "s1"
            rows = [
                {
                    "type": "message",
                    "role": "user",
                    "content": "<user_query>x</user_query>",
                    "id": bad,
                    "sessionId": session,
                },
                *skill(session, "daqiang-interaction-method", "k1"),
                assistant(session),
            ]
            _, record = self.run_case(rows)
            self.assertEqual(record.get("user_boundary_id"), "", f"{bad!r} 不該被接受為 boundary ID")

    def test_r9_a6_empty_boundary_violation_records_pending_by_card(self):
        """A6：空 boundary 的違規放行，必須以**卡號**穩定留下 pending。"""
        session = "s1"
        empty_boundary = {
            "type": "message",
            "role": "user",
            "content": "<user_query>x</user_query>",
            "sessionId": session,          # 故意不給 id
        }
        rows1 = [empty_boundary, tool(session, "Edit", "e1")]
        _, rec1 = self.run_case(
            rows1, env_extra={"T02_TASK_ID": "CARD-A"}, stop_hook_active=True, identity=""
        )
        self.assertEqual(rec1.get("result"), "FAIL_OPEN_RETRY")
        self.assertTrue((self.root / "pending.json").exists(), "必須留下 pending")
        rows2 = [
            user(session, "u2"),
            *skill(session, "daqiang-interaction-method", "k1"),
            *skill(session, "daqiang-work-discipline", "k2"),
            *skill(session, "prework-anti-fake-completion", "k3"),
            assistant(session),
        ]
        _, rec2 = self.run_case(rows2, env_extra={"T02_TASK_ID": "CARD-A"}, identity="")
        self.assertEqual(rec2.get("pending_violation"), True, "空 ID 違規放行後，下一則乾淨訊息仍要被擋")
        self.assertEqual(rec2.get("completion_allowed"), False)

    def test_r9_a7a_sibling_open_entry_still_blocks(self):
        """A7：同一張卡有兩筆 open pending，只清其中一筆 → 另一筆仍須擋下。"""
        pending = {
            "u1": {"task_status": "進行中", "completion_allowed": False, "task_id": "CARD-A", "rules": ["x"]},
            "u2": {"task_status": "進行中", "completion_allowed": False, "task_id": "CARD-A", "rules": ["y"]},
        }
        (self.root / "pending.json").write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        # 模擬「只清掉 u1」：u1 標成已清，u2 仍開著
        pending["u1"]["completion_allowed"] = True
        (self.root / "pending.json").write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        session = "s1"
        rows = [
            user(session, "u3"),
            *skill(session, "daqiang-interaction-method", "k1"),
            *skill(session, "daqiang-work-discipline", "k2"),
            *skill(session, "prework-anti-fake-completion", "k3"),
            assistant(session),
        ]
        _, record = self.run_case(rows, env_extra={"T02_TASK_ID": "CARD-A"}, identity="")
        self.assertEqual(record.get("completion_allowed"), False, "u2 仍開著，不得放行")

    def test_r9_a7b_boundary_key_collision_does_not_cross_cards(self):
        """A7：別張卡的 pending 若 boundary 剛好同名，不得誤擋目前這張卡。"""
        pending = {
            "CARD-A": {"task_status": "進行中", "completion_allowed": False, "task_id": "CARD-B", "rules": ["x"]},
        }
        (self.root / "pending.json").write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        session = "s1"
        rows = [
            user(session, "CARD-A"),      # boundary 剛好叫 CARD-A，但那是別張卡的 pending
            *skill(session, "daqiang-interaction-method", "k1"),
            *skill(session, "daqiang-work-discipline", "k2"),
            *skill(session, "prework-anti-fake-completion", "k3"),
            assistant(session),
        ]
        _, record = self.run_case(rows, env_extra={"T02_TASK_ID": "CARD-A"}, identity="")
        self.assertEqual(record.get("pending_violation"), False, "CARD-B 的 pending 不該擋 CARD-A")

    def test_r9_a7c_corrupt_store_is_not_overwritten(self):
        """A7：pending 存放區損壞時，mark_pending 不得用空物件覆寫既有資料。"""
        broken = "{ 這不是合法 JSON"
        (self.root / "pending.json").write_text(broken, encoding="utf-8")
        session = "s1"
        rows = [user(session, "u1"), tool(session, "Edit", "e1")]
        _, record = self.run_case(
            rows, env_extra={"T02_TASK_ID": "CARD-A"}, stop_hook_active=True, identity=""
        )
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertEqual(
            (self.root / "pending.json").read_text(encoding="utf-8"),
            broken,
            "損壞的存放區不得被覆寫（要保留證據）",
        )

    # ---------------- 第 10 輪：pending 穩定 ID／清除核對／例外處理 ----------------

    def test_r10_a7a_pending_id_closes_only_its_own_entry(self):
        """🔴 §6-3：日誌回推以**每筆 pending 的穩定 ID** 追蹤 open／clear。

        清除之後把 pending store 整個刪掉，仍要靠日誌正確判定「這筆已清」，
        不得像第 9 輪那樣被永久誤擋。
        """
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        cleared = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertEqual(cleared.returncode, 0, cleared.stdout + cleared.stderr)
        (self.root / "pending.json").unlink()
        clean = [
            user("session-1", "u2"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            assistant("session-1"),
        ]
        _, record = self.run_case(clean)
        self.assertEqual(record.get("completion_allowed"), True, "清除後刪 store 不應再誤擋")
        self.assertEqual(record.get("result"), "PASS")

    def test_r10_a7b_clear_rejects_key_collision(self):
        """🔴 §6-4：`--clear CARD-A` 不得清掉 `task_id=CARD-B` 的 entry。"""
        pending = {
            "CARD-A": {
                "task_id": "CARD-B",
                "completion_allowed": False,
                "task_status": "進行中",
                "rules": ["x"],
            }
        }
        (self.root / "pending.json").write_text(json.dumps(pending, ensure_ascii=False), encoding="utf-8")
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "CARD-A", script_version())
        # 附一份「簽章有效」的 receipt：仍必須因為「找不到屬於 CARD-A 的 pending」而拒絕。
        receipt = self.write_receipt(
            self.receipt_payload("CARD-A", result_path=verdict, pending_ids=[])
        )
        refused = self.run_cli(
            "--clear", "CARD-A", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        after = json.loads((self.root / "pending.json").read_text(encoding="utf-8"))
        self.assertNotEqual(refused.returncode, 0, "跨卡碰撞必須拒絕")
        self.assertEqual(after["CARD-A"]["completion_allowed"], False, "CARD-B 的 entry 不得被清")

    def test_r10_a7c_clear_requires_verdict_task_binding(self):
        """🔴 §6-4：驗收結果沒有綁定目標卡（缺 `task_id=<key>`）→ 拒絕清除。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version(), task_id=False)
        receipt = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0, "缺 task_id 綁定必須拒絕")
        still = self.run_cli("--status", "test-card")
        self.assertEqual(json.loads(still.stdout)["completion_allowed"], False)

    def test_r10_a7d_unwritable_pending_store_leaves_audit_without_traceback(self):
        """🔴 §6-5：pending 路徑不可寫時，不得冒 traceback／exit 1，且必須留稽核紀錄。"""
        blocker = self.root / "not-a-dir"
        blocker.write_text("x", encoding="utf-8")
        bad = blocker / "pending.json"
        rows = [
            user("session-1", "u1"),
            *skill("session-1", "daqiang-interaction-method", "s0"),
            tool("session-1", "Edit", "e1"),
        ]
        result, record = self.run_case(
            rows, env_extra={"T02_PENDING_PATH": str(bad)}, stop_hook_active=True
        )
        self.assertNotIn("Traceback", result.stderr, result.stderr)
        self.assertIsNotNone(record, "必須留下稽核紀錄")
        self.assertEqual(record.get("completion_allowed"), False)
        self.assertTrue(
            any("pending 寫入失敗" in r for r in record.get("reason", [])),
            record.get("reason"),
        )

    # ---------------- 第 12 輪：簽章 receipt（授權邊界，取代第 11 輪對稱通行碼） ----------------

    def test_r12_a_forged_result_without_receipt_is_rejected(self):
        """🔴 第 11 輪退件 §5 第 1 條：產出者自製**完整** pass result 但不附 receipt → 拒絕。

        這正是第 10 輪的致命反例：產出者寫一份含 VERDICT／version／task_id／pending_ids
        的檔案，再用 `--by WorkBuddy` 自行清除。沒有有效簽章 receipt 時必須擋下。
        """
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "producer-forged.md"
        self.write_verdict(verdict, "test-card", script_version())
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "WorkBuddy",
        )
        self.assertNotEqual(refused.returncode, 0, "沒有 receipt 不得清除")
        after = json.loads((self.root / "pending.json").read_text(encoding="utf-8"))
        for item in after.values():
            self.assertEqual(item.get("completion_allowed"), False, "pending 不得被改寫")

    def test_r12_b_receipt_signed_by_other_key_is_rejected(self):
        """🔴 §5 第 2、3 條：receipt 不是內嵌公鑰對應的私鑰所簽 → 拒絕，pending 不得改寫。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        other_priv = self.root / "other-priv.pem"
        other_pub = self.root / "other-pub.pem"
        make_keypair(other_priv, other_pub)
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict),
            priv_path=other_priv,
            pub_pem=other_pub.read_text(encoding="utf-8"),
        )
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertTrue(
            ("公鑰指紋" in refused.stderr) or ("簽章" in refused.stderr), refused.stderr
        )
        after = json.loads((self.root / "pending.json").read_text(encoding="utf-8"))
        for item in after.values():
            self.assertEqual(item.get("completion_allowed"), False)

    def test_r12_b2_tampered_payload_is_rejected(self):
        """🔴 指紋相符但 payload 被事後改過（位元組與簽章不符）→ 拒絕。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt_path = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        raw = json.loads(receipt_path.read_text(encoding="utf-8"))
        tampered = self.receipt_payload("test-card", result_path=verdict, pending_ids=["tampered-id"])
        raw["payload_b64"] = base64.b64encode(canonical_payload(tampered)).decode("ascii")
        receipt_path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt_path),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("簽章", refused.stderr)

    def test_r12_c_uninstalled_pubkey_rejects_all_clears(self):
        """🔴 §5 第 3 條：**公鑰未安裝**（原腳本 `RECEIPT_PUBKEY_PEM` 為空）→ 一律拒絕所有清除。"""
        self.assertIn(
            'RECEIPT_PUBKEY_PEM = ""',
            SCRIPT.read_text(encoding="utf-8"),
            "本測試的前提是原受驗腳本尚未安裝公鑰；安裝後請改用「清空公鑰的副本」來測。",
        )
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        refused = self.run_cli_raw(
            SCRIPT, "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex",
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("尚未安裝核定公鑰", refused.stderr)

    def test_r12_d_receipt_pending_ids_must_match(self):
        """🔴 §5 第 2 條：receipt 綁定的 pending IDs 與實際待清集合不符 → 拒絕。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict, pending_ids=["bogus-id"])
        )
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("pending IDs", refused.stderr)

    def test_r12_e_valid_receipt_clears_pending(self):
        """正向對照：有效簽章 receipt ＋ 綁定齊備 → 清除成功（防線不是把所有清除都擋死）。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        cleared = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertEqual(cleared.returncode, 0, cleared.stdout + cleared.stderr)
        after = json.loads((self.root / "pending.json").read_text(encoding="utf-8"))
        self.assertTrue(all(v.get("completion_allowed") for v in after.values()))

    def test_r12_f_receipt_nonce_cannot_be_replayed(self):
        """🔴 receipt 為一次性核定：同一份 receipt 第二次使用 → 拒絕（防重放）。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        first = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(second.returncode, 0, "同一份 receipt 不得重複使用")
        self.assertIn("重放", second.stderr)

    def test_r12_g_receipt_result_hash_must_match(self):
        """🔴 receipt 綁定的「驗收結果雜湊」與實際檔案不符 → 拒絕。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict, sha="0" * 64)
        )
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("雜湊", refused.stderr)

    def test_r12_h_receipt_task_id_must_match_target(self):
        """🔴 receipt 綁定的卡號與 `--clear` 目標不符 → 拒絕。"""
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt = self.write_receipt(
            self.receipt_payload("test-card", result_path=verdict, task_id="OTHER-CARD")
        )
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("卡號與目標不符", refused.stderr)

    def test_r12_i_wrong_fingerprint_is_rejected(self):
        """🔴 receipt 宣告的公鑰指紋與內嵌公鑰不符 → 拒絕。

        簽章本身**有效**（用內嵌私鑰簽），本條專門測「指紋」這一道獨立防線。
        """
        self.run_case([user("session-1", "u1"), tool("session-1", "Edit", "e1")], stop_hook_active=True)
        verdict = self.root / "v.md"
        self.write_verdict(verdict, "test-card", script_version())
        receipt_path = self.write_receipt(self.receipt_payload("test-card", result_path=verdict))
        raw = json.loads(receipt_path.read_text(encoding="utf-8"))
        raw["key_fingerprint"] = "deadbeefdeadbeef"
        receipt_path.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        refused = self.run_cli(
            "--clear", "test-card", "--result", str(verdict), "--version", script_version(),
            "--by", "codex", "--receipt", str(receipt_path),
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("公鑰指紋", refused.stderr)

    def test_r12_d3_same_card_keeps_single_pending(self):
        """🔴 D003：同一張卡重複阻擋只累加次數，不長出第二筆 pending。"""
        task = "T02-disposable"
        for i in range(3):
            rows = [user("session-1", f"u{i}"), tool("session-1", "Edit", f"e{i}")]
            self.run_case(rows, env_extra={"T02_TASK_ID": task}, stop_hook_active=True, identity="")
        data = json.loads((self.root / "pending.json").read_text(encoding="utf-8"))
        entries = [v for v in data.values() if isinstance(v, dict) and v.get("task_id") == task]
        self.assertEqual(len(entries), 1, f"同卡應只留一筆，實得 {len(entries)} 筆")
        self.assertEqual(entries[0].get("count"), 3, "重複阻擋應累加次數")


if __name__ == "__main__":
    unittest.main(verbosity=2)

# <!-- 變更：Codex 桌面版 ｜ 2026-10-12 08:42 ｜ 新增 T02 隔離驗收測試 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 11:4x ｜ 第4輪新增 9 條回歸 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 17:5x ｜ 第8輪：移除專案映射卡號；補同一 project 卡 A→B（同/跨 session）、缺號無條件拒絕、他卡 pending 不誤擋、卡號 ASCII 白名單、boundary 只收合法字串、PASS 語義一致、清 T02_CARD_FILE -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 22:3x ｜ 第9輪：identity 改由 env 通道（identity=）提供，測試不再自動補宣告；補 A2 不得回看歷史、A3 拒 fence／重複／多來源衝突／權威卡片清單、A4 宣告不 Unicode strip、A5 boundary raw 先驗、A6 空 boundary 以卡號留 pending、A7 同卡多筆 open 仍擋／不跨卡／不覆寫損壞 store -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 00:1x ｜ 第10輪：`card=` 參數無效化（卡號不來自 user content）；新增 §6-1/2 文字不能造身分（含縮排與未閉合 fence）、§6-3 pending_id 逐筆追蹤 open/clear、§6-4 clear 核對 entry task_id 與驗收結果 task_id 綁定、§6-5 不可寫 store 不冒 traceback 且留 audit；作廢第 9 輪宣告家族測試（A2／A3a／A3b／A4） -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 00:4x ｜ 第11輪：新增核定通行碼（§5-1 產出者偽造完整 pass result 無通行碼須拒絕、§5-2 錯通行碼／缺 pending_ids 綁定須拒絕、§5-3 未設定通行碼時一律拒絕、正向對照）＋ `write_verdict`／`pending_ids_for` helper；既有 `--clear` 測試補 `--token` 與 pending_ids 綁定 -->


