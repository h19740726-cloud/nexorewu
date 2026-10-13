#!/usr/bin/env python3
"""Verify and optionally consume an independently signed T02 receipt."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def open_pending_ids(ledger_path: Path, task: str) -> list[str]:
    ledger = json.loads(ledger_path.read_text())
    if ledger.get("task_id") != task:
        raise ValueError("ledger task_id mismatch")
    ids = [str(item["id"]) for item in ledger.get("pending", []) if item.get("status", "open") == "open"]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate pending ID in ledger")
    return sorted(ids)


def verify(args: argparse.Namespace) -> str:
    receipt = json.loads(args.receipt.read_text())
    payload = receipt.get("payload")
    if not isinstance(payload, dict) or not isinstance(receipt.get("signature"), str):
        raise ValueError("invalid receipt structure")
    required = {"task_id", "verdict", "pending_ids", "ledger_sha256", "result_sha256", "issued_at", "expires_at", "receipt_id"}
    if set(payload) != required:
        raise ValueError("receipt payload fields mismatch")
    if payload["task_id"] != args.task or payload["verdict"] != "pass":
        raise ValueError("receipt task or verdict mismatch")
    if sorted(payload["pending_ids"]) != open_pending_ids(args.ledger, args.task):
        raise ValueError("receipt does not bind every open pending ID")
    if payload["ledger_sha256"] != sha256(args.ledger) or payload["result_sha256"] != sha256(args.result):
        raise ValueError("receipt file hash mismatch")
    if f"{args.task}-VERDICT: pass" not in args.result.read_text():
        raise ValueError("result does not contain a pass verdict")
    now = int(time.time())
    if not isinstance(payload["issued_at"], int) or not isinstance(payload["expires_at"], int):
        raise ValueError("receipt timestamps must be integers")
    if payload["issued_at"] > now + 300 or payload["expires_at"] < now or payload["expires_at"] <= payload["issued_at"]:
        raise ValueError("receipt is not currently valid")
    receipt_id = str(payload["receipt_id"])
    if not receipt_id or "/" in receipt_id or receipt_id in {".", ".."}:
        raise ValueError("invalid receipt_id")
    used_path = args.used_dir / receipt_id
    if used_path.exists():
        raise ValueError("receipt already consumed")
    try:
        signature = base64.b64decode(receipt["signature"], validate=True)
    except Exception as error:
        raise ValueError("invalid signature encoding") from error
    with tempfile.TemporaryDirectory() as directory:
        message = Path(directory) / "payload.json"
        signed = Path(directory) / "signature.bin"
        message.write_bytes(canonical(payload))
        signed.write_bytes(signature)
        completed = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(args.public_key), "-signature", str(signed), str(message)],
            capture_output=True,
        )
        if completed.returncode:
            raise ValueError("invalid receipt signature")
    if args.consume:
        args.used_dir.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(used_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as target:
            target.write(sha256(args.receipt) + "\n")
    return receipt_id


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--task", required=True)
    result.add_argument("--receipt", type=Path, required=True)
    result.add_argument("--ledger", type=Path, required=True)
    result.add_argument("--result", type=Path, required=True)
    result.add_argument("--public-key", type=Path, required=True)
    result.add_argument("--used-dir", type=Path, required=True)
    result.add_argument("--consume", action="store_true")
    return result


if __name__ == "__main__":
    try:
        receipt_id = verify(parser().parse_args())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"verification failed: {error}")
    print(f"verified {receipt_id}")
