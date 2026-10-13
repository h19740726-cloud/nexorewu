# nexorewu

Minimal completion-receipt verifier for T02.

This repository does **not** issue approvals. It verifies a receipt signed by an independent RSA-SHA256 signer. The producer account must not control the signing key or the protected copy of the verifier public key.

## Verify and consume a receipt

```sh
python3 verify_receipt.py \
  --task T02 \
  --receipt clearance-receipt.json \
  --ledger pending-ledger.json \
  --result results/T02-verdict.md \
  --public-key /protected/t02-verifier-public.pem \
  --used-dir /protected/used-receipts \
  --consume
```

The receipt payload must bind `task_id`, `verdict`, every open pending ID, SHA-256 hashes of the ledger and result, issue/expiry times, and a unique receipt ID. Verification failure exits nonzero. A consumed receipt cannot be reused.

Run the regression check with `python3 -m unittest -v`.

## Trust boundary

The current repository owner is also the producer, so this repository alone is not an independent trust anchor. Final deployment requires an external signer and a public key stored where the producer cannot replace it. Ordinary work does not contact the signer; only the final completion transition does.
