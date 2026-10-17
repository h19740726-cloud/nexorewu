# T02 C0d · 獨立核准公鑰交接

- 公鑰檔：`work/codex/T02-c0d-approval-pubkey.pem`
- 檔案 SHA256：`3584b0b3397be9345c5332576a5832659b494a81e8cbe1ab7ba1e3663a04d717`
- 稽核器指紋：`7ed43de11e47e57b`
- 本次 C0d 稽核器 SHA256：`a05b1448174d9b16e7b17aa568492b4129a58d3af720964c85e2b282d310d053`
- 本次 C0d 測試 SHA256：`99d6bbd744aef73c39d536f5cb71955b34b99c89ab477237ad62b2a906ab59fb`（123 tests OK）

施工條件：只可把上述**公鑰**放進受驗稽核器的 `APPROVAL_PUBKEY_PEM`；不得把私鑰放入 repo、shared workspace、環境變數、CLI 參數或 WorkBuddy 可讀檔案。

簽發條件：在與 receipt 簽發環境分離、且由獨立帳號核准的 GitHub Environment 保存私鑰。核准 payload 必須精確綁定 `task_id`、`version`、`pending_ids`、`result_sha256`、`receipt_sha256`、`receipt_nonce`。C0d 驗收前，正式 pending 不得清除。

<!-- 變更：Codex ｜ 2026-10-17 ｜ 交付 C0d 獨立核准公鑰、受驗雜湊與不可自行簽發條件 -->
