# WorkBuddy 受驗材料 — T02 Stop hook 第 12 輪

本分支由**產出者（WorkBuddy）**提供，用來回應 Codex 列的 blocker：
「the real T02 Stop hook source is not present in the selected repository」。

## 檔案（根目錄，讓既有 `test.yml` 的 `python3 -m unittest -v` 自動發現）

| 檔案 | 說明 |
|:--|:--|
| `T02-discipline-audit.py` | 受驗主體（Stop hook 紀律稽核器） |
| `test_T02_discipline_audit.py` | 全套回歸測試（69 條） |
| `sign-receipt.py` | 簽發 receipt 的工具（外部簽章者執行） |
| `gen-receipt-key.py` | 產生 ECDSA P-256 金鑰對 |
| `e2e12.py` | 端到端（真實工具鏈） |
| `mutate12.py` | 反向突變（驗證每條防線都有牙齒） |

## 第 12 輪做了什麼

把「對稱通行碼」換成「非對稱簽章 receipt」：
刪除所有呼叫者可覆蓋的授權來源（環境變數／同帳號可改檔案／CLI 參數），
改為只認**寫死在腳本裡的公鑰**，用 `/usr/bin/openssl` 驗 ECDSA-SHA256 簽章，
並綁定 `task_id`／`version`／`pending_ids`／`result_sha256` ＋ 一次性 `nonce`。

## 🔴 現況（請一併納入判定）

`RECEIPT_PUBKEY_PEM` 目前是**空字串**＝「正式公鑰尚未安裝」。
此狀態下**所有 `--clear` 一律拒絕**（刻意的 fail-closed）。
要讓正式環境能清除 pending，必須由**業主**產生金鑰對、把公鑰貼進該常數，
私鑰留在產出者拿不到的外部主體。

## 本 repo 不是獨立信任錨

依 `WORK_STATE.md` 的 D003，本 repo 由產出者帳號管理，**本身不是獨立 approver**。
