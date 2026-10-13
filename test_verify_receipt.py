import base64
import json
import subprocess
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path

from verify_receipt import canonical, sha256, verify


class ReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        subprocess.run(["openssl", "genrsa", "-out", self.private, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.private, "-pubout", "-out", self.public], check=True, capture_output=True)
        self.ledger = self.root / "ledger.json"
        self.result = self.root / "result.md"
        self.receipt = self.root / "receipt.json"
        self.used = self.root / "used"
        self.ledger.write_text(json.dumps({"task_id": "T02", "pending": [{"id": "p1"}, {"id": "p2"}]}))
        self.result.write_text("T02-VERDICT: pass\n")
        now = int(time.time())
        self.payload = {
            "task_id": "T02", "verdict": "pass", "pending_ids": ["p1", "p2"],
            "ledger_sha256": sha256(self.ledger), "result_sha256": sha256(self.result),
            "issued_at": now - 1, "expires_at": now + 300, "receipt_id": "r1",
        }
        self.write_receipt()

    def tearDown(self):
        self.temp.cleanup()

    def write_receipt(self):
        message = self.root / "payload.json"
        signature = self.root / "signature.bin"
        message.write_bytes(canonical(self.payload))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.private, "-out", signature, message], check=True, capture_output=True)
        self.receipt.write_text(json.dumps({"payload": self.payload, "signature": base64.b64encode(signature.read_bytes()).decode()}))

    def args(self, consume=False):
        return Namespace(task="T02", receipt=self.receipt, ledger=self.ledger, result=self.result, public_key=self.public, used_dir=self.used, consume=consume)

    def test_valid_receipt_and_replay_block(self):
        self.assertEqual(verify(self.args(consume=True)), "r1")
        with self.assertRaisesRegex(ValueError, "already consumed"):
            verify(self.args(consume=True))

    def test_modified_result_fails(self):
        self.result.write_text("T02-VERDICT: fail\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify(self.args())

    def test_missing_pending_id_fails(self):
        self.payload["pending_ids"] = ["p1"]
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "every open pending"):
            verify(self.args())

    def test_expired_receipt_fails(self):
        self.payload["issued_at"] = int(time.time()) - 20
        self.payload["expires_at"] = int(time.time()) - 10
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "not currently valid"):
            verify(self.args())

    def test_forged_signature_fails(self):
        receipt = json.loads(self.receipt.read_text())
        receipt["signature"] = base64.b64encode(b"not a signature").decode()
        self.receipt.write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "invalid receipt signature"):
            verify(self.args())


if __name__ == "__main__":
    unittest.main()
