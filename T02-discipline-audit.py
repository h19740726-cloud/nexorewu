#!/usr/bin/env python3
"""WorkBuddy Stop hook: verify same-turn discipline skill loading evidence.

## 第 8 輪整改（2026-10-12）總判定語義（對應驗收第 5 條）

本程式每一筆稽核紀錄只用一個 `result` 欄位當**總判定**，且語義唯一、彼此不矛盾：

    result == "PASS"  ⟺  completion_allowed == True  且  pending_violation == False
    result ∈ {"BLOCK","FAIL_OPEN_RETRY","ERROR_ALLOW","INTERRUPTED_ALLOW"}
                      ⟹  completion_allowed == False

也就是：**只要 `completion_allowed` 為 false，`result` 就不會是 `PASS`**（第 7 輪
`result=PASS` 與 `completion_allowed=false` 同時出現的矛盾已消除）。`result` 的差異只在
「怎麼擋」：`BLOCK`＝本輪擋下、`FAIL_OPEN_RETRY`＝第二次 Stop 放行但留下未完成後果、
`ERROR_ALLOW`／`INTERRUPTED_ALLOW`＝工具層級或使用者中斷，放行但不得取得完成資格。

## 第 8 輪整改（2026-10-12）卡號來源（對應驗收第 1、2 條）

第 5～7 輪的卡號來源都被驗收方退回：
- 第 5 輪：`transcript` 檔名（＝session ID）→ **不是卡**。
- 第 6 輪：`settings.json` 硬編 `T02_TASK_ID=T02` → **全域常數，不是逐卡識別**。
- 第 7 輪：`transcript_path` 的**專案目錄名**查映射表 → **不是卡**（專案目錄是工作區，
  同一專案本來就能跑多張卡；「不同專案」不等於「不同卡」）。

🔴 **第 10 輪整改（2026-10-12，對應第 9 輪退件 §6 第 1、2 條）：不再從 user content 取卡號。**

第 9 輪把「目前 boundary 那一則 user 訊息的單行宣告」當成卡號來源之一；驗收方實測證明
**user content 是可自由輸入的文字**，可被「縮排 code block」「未閉合 fence」偽造並取得
`task_id=T02` ＋ `PASS`。因此本輪**完全移除這條來源**。

卡號只接受「不可由文字偽造的可信來源」：

    1. 事件欄位 `event.task_id` / `event.card_id`（宿主 injector 提供）
    2. 環境變數 `T02_TASK_ID`（掛載端 injector 提供）

兩者皆無 → **一律留下結構化原因並保守拒絕完成**（訊息裡寫 `task-card: T02` 一律無效）。
來源不合法或彼此不一致 → 同樣結構化拒絕。
卡號文法＝**明確 ASCII 白名單**，且必須存在於權威卡片清單（`tasks/*.md` 檔名前綴）。

## 第 10 輪整改（2026-10-12）對應第 9 輪退件 §6 第 1～7 條

- **§6-1／§6-2**：移除 user content 卡號來源（見上），不再有任何「文字可偽造身分」的路徑。
- **§6-3**：pending 日誌回推改以**每筆 pending 的穩定 ID**（`pending_id`）逐筆追蹤
  open／clear；`PENDING_CLEARED` 只關閉**對應那一筆**。
- **§6-4**：`--clear <key>` 的 `key` 視為**卡號**，且必須與 entry 的 `task_id` 一致，
  並要求驗收結果綁定 `task_id=<key>`；碰撞／不一致一律拒絕。
- **§6-5**：`save_pending()` 捕捉目錄建立與寫入例外；寫入失敗留結構化 audit、
  **不得冒 traceback**。
- **§6-6**：反向突變 stdout 直接落檔、不覆寫；探針移除證據統一以檔案時間／hash 敘述。
- **§6-7**：B、C 組未施工，不得聲稱全部通過。

## 第 11 輪（2026-10-13）核定通行碼（已被第 12 輪取代）

第 11 輪採「業主保管核定通行碼」的**對稱**流程控制：程式只讀通行碼的 SHA256，
來源優先序為環境變數 `T02_REVIEW_TOKEN_SHA256` → 檔案 `~/.workbuddy/t02-review-token.sha256`。
第 11 輪 A 組獨立驗收**不通過**，致命反例：**產出者在 `--clear` 呼叫時自設這兩個環境變數**，
即可用自選 token 清掉 pending（rc=0）。

## 🔴 第 12 輪整改（2026-10-13）對應第 11 輪退件 §5 第 1～4 條

**病根**＝授權根取自**呼叫者可控制的位置**（環境變數／同帳號可改檔案／CLI 參數）。
把這個限制寫在文件裡不能消除可重現的繞過。

**本輪改採非對稱簽章**，把授權根移到「本機帳號之外的主體」：

    - 授權根＝外部主體（例如 GitHub Actions）用**私鑰**簽發的 receipt。
    - 本檔**只內嵌公鑰**（`RECEIPT_PUBKEY_PEM`，寫死常數），驗簽用 `openssl dgst -sha256 -verify`。
    - 不再從環境變數、同帳號可改檔案、CLI 參數或共享工作區取得任何授權根。
    - 公鑰為空（未安裝）→ **所有 `--clear` 一律拒絕**（fail-closed）。
    - receipt 綁定 `task_id` ＋ 受驗版本 ＋ 待清 `pending_ids` ＋ 驗收結果 `result_sha256`，
      並帶一次性 `nonce`（防重放）。
    - ⚠️ 本檔若被改動（例如換成攻擊者的公鑰），**腳本 SHA256 會變**，由獨立驗收核對受驗版本雜湊把關。

**D003**：同一張卡只保留一筆 open pending，重複阻擋只累加 `count`。

## 🔴 第 13 輪整改（2026-10-13）對應第 2 輪 A 組 §5 第 1～3、6 條

第 2 輪 A 組獨立驗收新增四個反例全部成立（產出者第 12 輪版本）：

    A1 receipt 綁的 version 與執行檔不符，且**省略 --version** → 舊版不驗版本仍 rc=0。
    A2 防重放狀態損壞 → 舊版退成空集合 → 舊 receipt 重放成功。
    A3 改指防重放狀態路徑（`T02_NONCE_PATH`）→ 舊 receipt 重放成功。
    A4 同一 boundary 用於另一張卡 → 舊版直接覆寫既有卡的 pending entry。

**病根**＝①版本綁定依賴呼叫者提供 `--version`（可省略即跳過）；
②防重放狀態的路徑可由呼叫者改指、且損壞時退成「可用」；
③pending 的鍵取 boundary，boundary 不是卡的身分。

本輪修正：

    - **版本綁定權威值＝受驗執行檔自身 SHA256**（`self_artifact_sha256()`）。
      receipt 的 `version`、驗收結果檔宣告的版本都必須等於它，**不因省略 `--version` 而略過**。
    - **防重放狀態改為「每筆 nonce 一個原子標記檔」**，路徑由 `PENDING_PATH` 衍生
      （移除 `T02_NONCE_PATH`）；以 `O_CREAT|O_EXCL` 消費（並行下只有一個成功）；
      存放區缺失／損壞／不可讀 → **保守拒絕**；初始化由 `mark_pending()` 完成。
    - **pending 鍵改以卡號為主**（`card_id or boundary_id`），boundary 只放 metadata；
      若目標鍵已被別的卡佔用，改用帶 `pending_id` 的複合鍵，**絕不覆寫他卡 entry**。

⚠️ 信任邊界（第 2 輪 §5 第 4 條）：本機同帳號可改寫的檔案（含本程式與狀態目錄）**不能**
由本程式自證不可改。真正防線＝**程式 SHA 鎖定 ＋ 外部持鑰 ＋ 獨立驗收**；本輪僅把
「可用參數繞過」與「重放」兩類路徑關閉，並把邊界列明。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path


LOG_PATH = Path(
    os.environ.get(
        "T02_DISCIPLINE_LOG",
        "/Users/wulieqiang/AI協作/work/codex/T02-discipline-audit.jsonl",
    )
)
MAX_TAIL_BYTES = 64 * 1024 * 1024
MUTATING_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
INTERACTION = "daqiang-interaction-method"
WORK = "daqiang-work-discipline"
PREWORK = "prework-anti-fake-completion"

# 驗收結果檔的機器可讀宣告。格式約定（**唯一且完整**）：
#   task_id=<卡號>                                       （整行，恰好 1 行）
#   <!-- T02-VERDICT: pass version=<受驗版本 SHA256> -->  （恰好 1 個，version 為 64 位十六進位）
#
# 🔴 第 14 輪（對應第 2 輪 A 組增補 §5-1）：由「全文包含字串」改為**解析欄位並等值核對**。
#    病根：舊版用 `artifact_sha not in text`，於是「marker 宣告錯版本、但附錄／內文出現
#    正確 SHA」仍會通過（反例 N2）。改為只認**宣告欄位本身**的值；重複／衝突宣告一律拒絕。
VERDICT_DECL_RE = re.compile(
    r"<!--\s*T02-VERDICT:\s*pass\s+version=([0-9a-fA-F]{64})\s*-->"
)
TASK_ID_DECL_RE = re.compile(r"^task_id=([A-Za-z0-9._:-]{1,64})[ \t]*$", re.MULTILINE)

# pending（未完成）狀態存放位置。
PENDING_PATH = Path(
    os.environ.get(
        "T02_PENDING_PATH",
        "/Users/wulieqiang/AI協作/work/codex/T02-pending-violations.json",
    )
)

# 🔴 權威卡片清單（驗收第 3 條）：卡號不能只驗字形，必須存在於真實卡片目錄。
#   來源＝`tasks/*.md` 的檔名前綴（例：`T02-紀律等做到-程式落地查核.md` → `T02`）。
TASKS_DIR = Path(
    os.environ.get(
        "T02_TASKS_DIR",
        "/Users/wulieqiang/AI協作/tasks",
    )
)

# 🔴 第 12 輪整改（第 11 輪退件 §5 第 2、3 條）：**徹底移除「呼叫者可覆蓋的信任來源」**。
#
#    第 11 輪實測的攻擊：產出者在 `--clear` 呼叫時自設環境變數 `T02_REVIEW_TOKEN_SHA256`
#    （或改指 `T02_REVIEW_TOKEN_PATH`），再拿自選 token 即清除 pending（rc=0）。
#    病根＝**授權根取自呼叫者可控制的位置**（環境變數／同帳號可改檔案／CLI 參數）。
#    把這個限制寫在文件裡，不能消除可重現的繞過（第 11 輪 §3 原話）。
#
#    本輪改採**非對稱簽章**：
#      - 授權根＝一份由「本機帳號之外的主體」簽發的 receipt（一次性核定）。
#      - 驗簽只需要**公鑰**，而公鑰**內嵌在本檔**（不從環境變數、不從可改路徑、不由 CLI 指定）。
#      - 私鑰由外部主體持有（本機帳號拿不到）⇒ 產出者無法自行簽發 receipt。
#
#    - 公鑰常數 `RECEIPT_PUBKEY_PEM`：PEM 字串直接寫死。
#      🔴 空字串＝「尚未安裝公鑰」→ **所有 `--clear` 一律拒絕**（保守，fail-closed）。
#      安裝＝由業主以 `gen-receipt-key.py` 產生金鑰對後，把**公鑰 PEM** 貼進此常數。
#    - 驗簽用 `openssl dgst -sha256 -verify`（macOS 內建 LibreSSL，無須第三方套件）。
#    - ⚠️ 本檔若被改動（例如換成攻擊者的公鑰），**腳本 SHA256 會變**，
#      由「獨立驗收」核對受驗版本雜湊把關（第 11 輪 §1 版本硬門檻）。
RECEIPT_PUBKEY_PEM = ""

# 🔴 第 13 輪（對應第 2 輪 A 組 §5 第 1 條）：受驗執行檔自身的 SHA256＝**版本綁定的權威值**。
#    receipt 的 `version`、驗收結果檔宣告的版本，都必須等於本值；且**不因省略 --version 而略過**
#    （第 2 輪 A1 反例：省略 --version 就不比對 receipt 版本 → rc=0，舊 receipt 與執行檔不符仍放行）。
SELF_ARTIFACT_PATH = Path(__file__).resolve()


def self_artifact_sha256() -> str:
    """受驗執行檔自身的 SHA256。讀不到 → 回 ""（呼叫端保守拒絕）。"""
    try:
        return hashlib.sha256(SELF_ARTIFACT_PATH.read_bytes()).hexdigest()
    except OSError:
        return ""


# 🔴 第 13 輪（對應第 2 輪 A 組 §5 第 2 條）：防重放狀態的**獨立可改路徑已移除**。
#
#    第 12 輪以「單一集合檔」記錄已用 nonce，路徑取自 `T02_NONCE_PATH`（呼叫者可改指）；
#    檔損壞／不可讀時退成空集合 → 舊 receipt 可重放（第 2 輪 A2／A3 反例）。
#
#    本輪改為「**每筆 nonce 一個原子標記檔**」，且：
#      - 存放區路徑**由 PENDING_PATH 衍生**（不再讀任何環境變數或模組常數覆蓋）
#        ⇒ 呼叫者無法單獨改指防重放狀態來源（A3）；
#      - 以 `O_CREAT|O_EXCL` 消費，天然具原子性（A2 的重放與並行由作業系統保證）；
#      - 存放區缺失／損壞 → **保守拒絕**；初始化由 `mark_pending()` 在建立 pending 時一併完成
#        （「有 pending 就必有防重放存放區」）。
#      ⚠️ 信任邊界：本機制防的是「同一 receipt 重複使用」與「以參數改指狀態來源」；
#         若攻擊者能直接改寫本檔（更換公鑰）或整個狀態目錄，防線在**程式 SHA 鎖定**與
#         **外部持鑰**，不由本機檔案提供（第 2 輪 §5 第 4 條，已於報告列明）。
NONCE_STORE_DIRNAME = "T02-used-receipt-nonces"
NONCE_STORE_MARKER = ".initialized"
# 🔴 第 14 輪（對應第 2 輪 A 組增補 §5-2）：初始化標記必須帶**固定內容**，
#    只驗「檔案存在」不算就緒（反例 N1：`.initialized` 內容被寫成 `{broken` 仍被判 ready）。
NONCE_STORE_MAGIC = "T02-nonce-store-v1"


def canonical_payload(payload: dict) -> bytes:
    """receipt payload 的正規化位元組（簽章與驗簽必須用同一種形式）。

    鍵排序、無多餘空白、UTF-8。**這一支是簽／驗的唯一真相源**：
    簽章端（外部主體）與驗簽端（本檔）都必須呼叫它，否則位元組不一致會驗不過。
    """
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def pubkey_fingerprint(pem: str) -> str:
    """公鑰指紋＝公鑰 PEM（正規化後）的 SHA256 前 16 位十六進位。"""
    normalized = "\n".join(line.strip() for line in pem.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def openssl_verify(payload_bytes: bytes, signature: bytes, pubkey_pem: str) -> bool:
    """用 openssl 驗 ECDSA-SHA256 簽章。任何例外一律回 False（fail-closed）。"""
    if not payload_bytes or not signature or not pubkey_pem.strip():
        return False
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        key_file = tmpdir / "pub.pem"
        sig_file = tmpdir / "sig.bin"
        data_file = tmpdir / "payload.bin"
        try:
            key_file.write_text(pubkey_pem.strip() + "\n", encoding="utf-8")
            sig_file.write_bytes(signature)
            data_file.write_bytes(payload_bytes)
        except OSError:
            return False
        try:
            proc = subprocess.run(
                [
                    "/usr/bin/openssl", "dgst", "-sha256",
                    "-verify", str(key_file),
                    "-signature", str(sig_file),
                    str(data_file),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0


def verify_receipt(receipt_path: str) -> tuple[dict | None, str]:
    """讀并驗收 receipt，回 (payload, 問題說明)。驗不過回 (None, 原因)。

    receipt 檔格式（JSON 物件）：
      {
        "schema": 1,
        "payload_b64":   "<base64(canonical_payload(payload))>",
        "signature_b64": "<base64(ECDSA-SHA256 DER 簽章)>",
        "key_fingerprint": "<pubkey_fingerprint(RECEIPT_PUBKEY_PEM)>"
      }

    驗簽**只認內嵌公鑰**（`RECEIPT_PUBKEY_PEM`）：不讀環境變數、不讀其他檔案、不接受 CLI 指定。
    """
    if not RECEIPT_PUBKEY_PEM.strip():
        return None, "尚未安裝核定公鑰（RECEIPT_PUBKEY_PEM 為空），保守拒絕所有清除"
    path = Path(receipt_path) if receipt_path else None
    if path is None or not path.is_file():
        return None, f"receipt 檔不存在：{receipt_path}"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"receipt 無法解析：{exc}"
    if not isinstance(raw, dict):
        return None, "receipt 不是 JSON 物件"
    if raw.get("schema") != 1:
        return None, f"receipt schema 不支援：{raw.get('schema')!r}"
    fp = str(raw.get("key_fingerprint") or "")
    expected_fp = pubkey_fingerprint(RECEIPT_PUBKEY_PEM)
    if fp != expected_fp:
        return None, "receipt 的公鑰指紋與本檔內嵌公鑰不符"
    try:
        payload_bytes = base64.b64decode(str(raw.get("payload_b64") or ""), validate=True)
        signature = base64.b64decode(str(raw.get("signature_b64") or ""), validate=True)
    except (ValueError, TypeError) as exc:
        return None, f"receipt 的 base64 欄位損壞：{exc}"
    if not openssl_verify(payload_bytes, signature, RECEIPT_PUBKEY_PEM):
        return None, "receipt 簽章驗證失敗（非內嵌公鑰之對應私鑰所簽）"
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"receipt payload 無法解析：{exc}"
    if not isinstance(payload, dict):
        return None, "receipt payload 不是 JSON 物件"
    return payload, ""


def nonce_store_dir() -> Path:
    """防重放狀態存放區路徑。

    🔴 由 `PENDING_PATH` 衍生（第 13 輪）：呼叫者無法用環境變數**單獨**改指它
    （改了 `T02_PENDING_PATH` 會連 pending 一起改，於是「找不到待清 pending」而拒絕）。
    """
    return PENDING_PATH.parent / NONCE_STORE_DIRNAME


def init_nonce_store() -> bool:
    """建立防重放狀態存放區（目錄與 `.initialized` 標記）。回是否可用。

    🔴 第 14 輪（§5-2）：只在「可信首次建置」呼叫（見 `mark_pending()`）。
    標記已存在但內容不正確時**不修復**（保守：留給人工處理，不靜默覆蓋）。
    """
    directory = nonce_store_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        marker = directory / NONCE_STORE_MARKER
        if not marker.exists():
            marker.write_text(NONCE_STORE_MAGIC + "\n", encoding="utf-8")
    except OSError:
        return False
    return nonce_store_ready()


def nonce_store_ready() -> bool:
    """防重放狀態存放區是否已就緒（目錄 ＋ **內容正確**的初始化標記）。

    缺失／損壞／不可讀一律回 False ⇒ 呼叫端保守拒絕清除
    （第 2 輪 A2；第 2 輪 A 組增補 N1）。
    """
    directory = nonce_store_dir()
    marker = directory / NONCE_STORE_MARKER
    try:
        if not directory.is_dir() or not marker.is_file():
            return False
        return marker.read_text(encoding="utf-8").strip() == NONCE_STORE_MAGIC
    except (OSError, UnicodeDecodeError):
        return False


def consume_nonce(nonce: str) -> str:
    """原子性消費 receipt nonce。回 "" 表成功；否則回拒絕原因。

    以 `O_CREAT|O_EXCL` 建立**每筆 nonce 的標記檔**：檔案已存在＝此 nonce 用過（重放）；
    無法建立＝保守拒絕。檢查與消費是同一個系統呼叫，故並行下只有一個會成功。
    """
    if not nonce:
        return "receipt 缺 nonce（一次性核定識別碼）"
    if not nonce_store_ready():
        return "防重放狀態存放區不存在或未初始化，保守拒絕清除"
    marker = nonce_store_dir() / (hashlib.sha256(nonce.encode("utf-8")).hexdigest() + ".used")
    try:
        handle = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return f"receipt nonce 已使用過（重放）：{nonce}"
    except OSError:
        return "無法記錄 receipt nonce（防重放），保守拒絕清除"
    try:
        os.write(handle, (now_iso() + " " + nonce + "\n").encode("utf-8"))
    except OSError:
        pass
    finally:
        os.close(handle)
    return ""


def parse_verdict_declaration(text: str) -> tuple[dict | None, str]:
    """解析驗收結果檔的機器可讀宣告，回 (宣告, 問題說明)。

    宣告＝`{"version": <64 位十六進位>, "task_id": <卡號>}`。

    🔴 第 14 輪（對應第 2 輪 A 組增補 §5-1）：**唯一且完整**才採用——
      - 通過宣告必須**恰好 1 個**，且 version 必須是 64 位十六進位；
      - `task_id=<卡號>` 行必須**恰好 1 行**。
    不滿足 → 回 (None, 原因)，呼叫端一律拒絕。
    ⇒ 錯的宣告版本，**不能**靠附錄或內文出現正確 SHA 補足（反例 N2）；
      重複／衝突的宣告也一律拒絕。
    """
    versions = VERDICT_DECL_RE.findall(text)
    if len(versions) != 1:
        return None, f"通過宣告必須恰好 1 個（實得 {len(versions)} 個）"
    task_ids = TASK_ID_DECL_RE.findall(text)
    if len(task_ids) != 1:
        return None, f"task_id 宣告必須恰好 1 行（實得 {len(task_ids)} 行）"
    return {"version": versions[0].lower(), "task_id": task_ids[0]}, ""


# 🔴 卡號文法（驗收第 3 條）：明確的 ASCII 白名單，不是「只排除 C0 控制字元」。
#   首字元限英數；其餘限英數與 `._:-`；長度 1～64。
#   這條文法天然排除 U+007F、U+0085、U+2028、U+2029、bidi 控制字元、所有空白與 CJK。
CARD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")

# 🔴 第 10 輪整改（第 9 輪退件 §6 第 1、2 條）：**完全移除「訊息宣告」這條卡號來源**。
#   原因：user content 是可自由輸入的文字，可被引用區塊、縮排 code block、未閉合 fence
#   偽造，因此**不能當成可驗證 identity**（第 9 輪實測：縮排與未閉合 fence 兩種寫法都能取得
#   `task_id=T02` ＋ `PASS`）。改為只認「不可由文字偽造的可信來源」＝宿主事件欄位與
#   掛載端注入的環境變數。⇒ `CARD_DECL_RE`／`CODE_FENCE_RE`／`declared_card_id()` 一併移除。

# 訊息 ID／boundary 的反例字元（驗收第 4 條）：C0/C1 控制字元、行／段落分隔、
# bidi 控制與零寬字元、BOM。
# 🔴 第 9 輪整改（驗收第 5 條）：補 U+061C（Arabic Letter Mark，bidi）與 U+00A0（NBSP）。
#   前一版漏了這兩個，於是 `"good\u061C"`、`"good\u00A0"` 會被 Unicode trim 吃掉後放行。
FORBIDDEN_IN_ID_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u00a0\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def append_log(record: dict) -> bool:
    """寫一行稽核紀錄。寫不進去時回 False（呼叫端必須保守拒絕完成）。"""
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        return True
    except OSError:
        return False


def persist_or_block(record: dict) -> int | None:
    """留下稽核紀錄。留不下來就阻擋本輪（無法稽核就不得取得完成資格）。"""
    if append_log(record):
        return None
    print(
        json.dumps(
            {"decision": "block", "reason": "稽核結果無法持久寫入，本輪不得取得完成資格"},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    return 0


def read_tail_jsonl(path: Path) -> list[dict]:
    size = path.stat().st_size
    with path.open("rb") as handle:
        start = max(0, size - MAX_TAIL_BYTES)
        handle.seek(start)
        data = handle.read()
    if start:
        _, _, data = data.partition(b"\n")
    rows = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


# ---------------------------------------------------------------- pending 存放區

def load_pending() -> tuple[dict, bool]:
    """讀 pending 存放區，回 (資料, 存放區是否可信)。

    檔不存在 → ({}, True)；檔存在但無法解析 → ({}, False)，呼叫端必須保守拒絕。
    """
    if not PENDING_PATH.exists():
        return {}, True
    try:
        raw = PENDING_PATH.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, False
    if not isinstance(value, dict):
        return {}, False
    return value, True


def save_pending(value: dict) -> bool:
    """寫入 pending 存放區，回是否成功。

    🔴 第 10 輪整改（第 9 輪退件 §6 第 5 條）：目錄建立與寫入的例外**一律捕捉**，
    回 `False` 讓呼叫端留下結構化 audit 並保守處理，**不得讓 traceback 冒出、exit 1**
    （第 9 輪實測：`T02_PENDING_PATH` 指到不可寫位置時 `exit 1` 且無 audit）。
    """
    try:
        PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
        PENDING_PATH.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError:
        return False
    return True


# ---------------------------------------------------------------- 卡號來源

def valid_card_id(value: object) -> str:
    """卡號必須符**明確 ASCII 白名單**（驗收第 3 條）。

    合法：字串、去前後空白後全長符合 `[A-Za-z0-9][A-Za-z0-9._:-]{0,63}`。
    不合法：非字串、空、含空白、含 U+007F／U+0085／U+2028／U+2029／bidi 控制字元、
    含任何非白名單字元（含 CJK）。不合法一律回空字串，由呼叫端保守拒絕。
    """
    if not isinstance(value, str):
        return ""
    # 只修剪 ASCII 空白（不是 str.strip()）：str.strip() 會把 U+0085／U+2028／U+00A0 這類
    # **Unicode 空白**一起吃掉，於是 `T02\u0085` 會被「修剪成」合法的 `T02` —— 那等於讓
    # 驗收第 3 條點名的字元繞過白名單。改用 ASCII-only 修剪，這些字元才會留在值裡被拒絕。
    text = value.strip(" \t")
    if not text:
        return ""
    return text if CARD_ID_RE.fullmatch(text) else ""


def known_card_ids() -> tuple[set[str], bool]:
    """讀權威卡片清單（`tasks/*.md` 檔名前綴）＝已知卡號集合。

    第 9 輪整改（對應 Codex 第 8 輪第 3 條後半）：卡號**不能只驗字形**，
    必須對應一張真實存在的卡。回 (集合, 是否可信)：目錄不存在／讀不到／空
    → ({}, False)，呼叫端保守拒絕（無法驗證權威性時不得放行）。
    """
    try:
        if not TASKS_DIR.is_dir():
            return set(), False
        ids = set()
        for entry in sorted(TASKS_DIR.glob("*.md")):
            stem = entry.stem
            # 同時收「完整檔名」與「第一個 `-` 之前」：真實卡片是 `T02-卡名.md`（取 T02），
            # 而卡號本身可能含 `-`（如 `CARD-A`）時完整檔名才是正解。
            for candidate in (stem, stem.split("-", 1)[0]):
                card = valid_card_id(candidate)
                if card:
                    ids.add(card)
    except OSError:
        return set(), False
    if not ids:
        return set(), False
    return ids, True


def resolve_card(event: dict) -> tuple[str, str]:
    """解析目前任務卡號，回 (卡號, 結構化問題說明)。

    🔴 第 10 輪整改（對應第 9 輪退件 §6 第 1 條）：卡號**只接受不可由文字偽造的可信來源**：

      1. 事件欄位 `event.task_id` / `event.card_id`（宿主 injector 提供）
      2. 環境變數 `T02_TASK_ID`（掛載端 injector 提供）

    **不再從 user content 解析任何宣告**（訊息裡出現 `task-card: T02` 一律無效）——
    第 9 輪實測這兩種寫法都能取得 `PASS`：縮排 code block、未閉合 fence。

    回傳語義：無來源 → ("", "")（呼叫端保守拒絕）；
    來源不合法或彼此不一致 → ("", 問題說明)。
    """
    found: list[tuple[str, str]] = []
    problems: list[str] = []
    for source, raw in (
        ("事件 task_id", event.get("task_id")),
        ("事件 card_id", event.get("card_id")),
        ("環境變數 T02_TASK_ID", os.environ.get("T02_TASK_ID")),
    ):
        if raw is None:
            continue
        card = valid_card_id(raw)
        if card:
            found.append((source, card))
        else:
            problems.append(f"{source} 提供的卡號不合法：{raw!r}")
    if problems:
        return "", "；".join(problems)
    if not found:
        return "", ""
    distinct = {card for _, card in found}
    if len(distinct) > 1:
        return "", f"卡號來源衝突（不一致）：{found!r}"
    return found[0][1], ""


def find_pending_targets(data: dict, key: str) -> list[str]:
    """找出 `--clear`／`--status` 要處理的 entry key 清單。

    🔴 第 10 輪整改（第 9 輪退件 §6 第 4 條）：`key` 一律視為**卡號**，
    且必須與 entry 的 `task_id` 一致，否則不採用。

    - 「key 精確命中」那一筆，只有它的 `task_id` 為**空**（舊資料）或**等於 key** 才採用。
    - 其餘採「`task_id == key`」的所有 entries。
    - key 精確命中但 `task_id` 指向**別的卡** → **不採用**
      （第 9 輪實測：`{"CARD-A":{"task_id":"CARD-B"}}` 會被 `--clear CARD-A` 誤清）。
    """
    if not key:
        return []
    targets: list[str] = []
    exact = data.get(key)
    if isinstance(exact, dict):
        task_id = str(exact.get("task_id") or "")
        if task_id in ("", key):
            targets.append(key)
    for stored_key, item in data.items():
        if stored_key == key:
            continue
        if isinstance(item, dict) and str(item.get("task_id") or "") == key:
            targets.append(stored_key)
    return targets


def is_open(item: object) -> bool:
    return isinstance(item, dict) and not item.get("completion_allowed", True)


def open_pending_for_card(data: dict, card_id: str) -> dict | None:
    """回「同一張卡」仍然開著的 pending（任一筆）。

    第 9 輪整改（對應 Codex 第 8 輪 A7）：
    - **只按卡號匹配**：不再讓「boundary 剛好同名」造成跨卡碰撞
      （關鍵字精確命中優先，會把別張卡的 pending 誤掛到本卡）。
    - **聚合同卡所有 open entries**：只清掉其中一筆，另一筆仍要擋。
    """
    if not card_id:
        return None
    for item in data.values():
        if not isinstance(item, dict):
            continue
        if str(item.get("task_id") or "") == card_id and is_open(item):
            return item
    return None


def log_shows_open_pending(card_id: str) -> bool:
    """從 append-only 稽核日誌回推：這張卡是否仍有**未被關閉**的 pending。

    🔴 第 10 輪整改（第 9 輪退件 §6 第 3 條）：改以**每筆 pending 的穩定 ID**
    （`pending_id`）逐筆追蹤 open／clear。`PENDING_CLEARED` 只關閉**對應那一筆**，
    不再以整張卡或任意 key 模糊關閉
    （第 9 輪實測：清除後刪掉 pending store，仍被永久誤擋）。
    """
    if not card_id:
        return False
    try:
        rows = read_tail_jsonl(LOG_PATH)
    except OSError:
        return False
    open_ids: set[str] = set()
    for row in rows:
        if str(row.get("task_id") or "") != card_id:
            continue
        pending_id = str(row.get("pending_id") or "")
        if not pending_id:
            continue
        result = row.get("result")
        if result == "PENDING_CLEARED":
            open_ids.discard(pending_id)
        elif result == "FAIL_OPEN_RETRY" and row.get("pending_violation"):
            open_ids.add(pending_id)
    return bool(open_ids)


def mark_pending(boundary_id: str, card_id: str, rules: list[str], event: dict) -> str:
    """把「被放行的違規」記成未完成，禁止它取得完成資格。回 `pending_id`（失敗回 ""）。

    第 9 輪（A6）：boundary 為空時改以卡號當鍵。
    第 10 輪（第 9 輪退件 §6 第 3、5 條）：每筆 pending 配一個**穩定 ID**
    （`pending_id`）供日誌逐筆追蹤 open／clear；存放區損壞或寫入失敗時
    **不得覆寫、不得冒 traceback**，一律回 "" 由呼叫端保守處理。
    🔴 第 12 輪 D003：**同一張卡只保留一筆 open pending**；重複阻擋只累加 `count`。
    🔴 第 13 輪（第 2 輪 A4）：**鍵改以卡號為主**（`card_id or boundary_id`），
    boundary 只放 metadata。前一版鍵取 boundary，若同一 boundary 被不同卡引用
    （例如同一個訊息 ID 用於兩張卡）會直接覆寫別張卡的 entry。
    """
    key = card_id or boundary_id
    if not key:
        return ""
    data, store_ok = load_pending()
    if not store_ok:
        return ""
    # 🔴 第 14 輪（對應第 2 輪 A 組增補 §5-2 / 反例 N3）：初始化只在「可信首次建置」——
    #    pending 存放區**原本為空**（全新狀態）才建立防重放存放區。若已存在任何 pending
    #    entry 卻沒有防重放存放區，代表歷史遺失，**不得由 mark_pending 靜默重建**；
    #    該卡之後一律保守拒絕清除。
    store_was_empty = not data
    # 已有同卡的 open pending → 只更新它（累加次數），不新增第二筆。
    if card_id:
        for item in data.values():
            if (
                isinstance(item, dict)
                and str(item.get("task_id") or "") == card_id
                and is_open(item)
            ):
                item["rules"] = list(rules)
                item["updated"] = now_iso()
                item["count"] = int(item.get("count") or 0) + 1
                item["session_id"] = str(event.get("session_id") or item.get("session_id") or "")
                item["boundary_id"] = boundary_id
                if not save_pending(data):
                    return ""
                # 此處**不**初始化防重放存放區：既有 pending 的歷史若遺失，保守拒絕。
                return str(item.get("pending_id") or "")
    pending_id = uuid.uuid4().hex[:12]
    # 🔴 不覆寫其他卡的 entry：若目標鍵已被**別的卡**佔用，改用帶 pending_id 的複合鍵。
    target_key = key
    existing = data.get(target_key)
    if isinstance(existing, dict) and str(existing.get("task_id") or "") not in ("", card_id):
        target_key = f"{key}#{pending_id}"
    data[target_key] = {
        "pending_id": pending_id,
        "task_status": "進行中",
        "completion_allowed": False,
        "task_id": card_id,
        "boundary_id": boundary_id,
        "rules": list(rules),
        "count": 1,
        "session_id": str(event.get("session_id") or ""),
        "updated": now_iso(),
        "cleared_by": "",
    }
    if not save_pending(data):
        return ""
    # 🔴 初始化只在「可信首次建置」（pending 存放區原本為空）；見上方 store_was_empty 的說明。
    if store_was_empty:
        init_nonce_store()
    return pending_id


def _refuse_clear(key: str, result_path: str, reviewer: str, reason: str) -> None:
    """留一筆 CLEAR_REFUSED 稽核紀錄（拒絕也要留痕）。"""
    append_log(
        {
            "ts": now_iso(),
            "result": "CLEAR_REFUSED",
            "user_boundary_id": key,
            "attempted_by": reviewer,
            "result_path": result_path,
            "reason": [reason],
        }
    )


def clear_pending(key: str, result_path: str, version: str, reviewer: str, receipt_path: str) -> int:
    """清除 pending。空洞署名不算數，必須附「獨立驗收結果」與**有效簽章的 receipt**。

    🔴 第 12 輪整改（第 11 輪退件 §5 第 2、3 條）：
    - **授權根**＝由本機帳號之外的主體簽發的 receipt；
      驗簽**只認本檔內嵌公鑰**（`RECEIPT_PUBKEY_PEM`）。
      不再從環境變數、同帳號可改檔案、CLI 參數或共享工作區取得任何授權根。
    - **綁定**：receipt payload 必須同時綁定 `task_id`、受驗版本、待清 `pending_ids`、
      驗收結果的 `result_sha256`。
    - **一次性**：receipt 的 `nonce` 不得重複使用（防重放）。
    """
    if not key:
        print(
            "用法：--clear <卡號> --result <驗收結果檔> --receipt <receipt.json> "
            "[--version <S256>] [--by <驗收者>]",
            file=sys.stderr,
        )
        return 2

    payload, problem = verify_receipt(receipt_path)
    if problem:
        _refuse_clear(key, result_path, reviewer, problem)
        print(f"clear refused: {problem}", file=sys.stderr)
        return 3

    # 🔴 第 13 輪（§5 第 1 條）：版本綁定的權威值＝**受驗執行檔自身 SHA256**，
    #    不再依賴 --version 是否提供（A1 反例：省略 --version 就整段略過比對）。
    artifact_sha = self_artifact_sha256()
    reason = ""
    nonce = str(payload.get("nonce") or "")
    receipt_version = str(payload.get("version") or "")
    if not artifact_sha:
        reason = "無法計算受驗執行檔雜湊，保守拒絕清除"
    elif not receipt_version:
        reason = "receipt 沒有綁定受驗版本"
    elif receipt_version != artifact_sha:
        reason = (
            "receipt 綁定的版本與受驗執行檔 SHA256 不符"
            f"（receipt={receipt_version}，執行檔={artifact_sha}）"
        )
    elif version and str(version) != artifact_sha:
        reason = f"CLI --version 與受驗執行檔 SHA256 不符（{version}）"
    elif str(payload.get("task_id") or "") != key:
        reason = f"receipt 綁定的卡號與目標不符（receipt={payload.get('task_id')!r}）"

    data: dict = {}
    targets: list[str] = []
    target_ids: list[str] = []
    if not reason:
        data, store_ok = load_pending()
        if not store_ok:
            reason = "pending 存放區無法解析，先修復再清除"
        else:
            targets = find_pending_targets(data, key)
            if not targets:
                print(f"no pending: {key}")
                return 1
            target_ids = sorted(str(data[t].get("pending_id") or "") for t in targets)
            receipt_ids = payload.get("pending_ids")
            if not isinstance(receipt_ids, list) or sorted(str(i) for i in receipt_ids) != target_ids:
                reason = (
                    "receipt 綁定的 pending IDs 與實際待清集合不符"
                    f"（receipt={receipt_ids!r}，實際={target_ids!r}）"
                )

    if not reason:
        if not result_path:
            reason = "缺少 --result：沒有驗收結果不得清除（署名不等於核定）"
        elif not Path(result_path).is_file():
            reason = f"驗收結果檔不存在：{result_path}"

    digest = ""
    if not reason:
        try:
            digest = hashlib.sha256(Path(result_path).read_bytes()).hexdigest()
        except OSError as exc:
            reason = f"驗收結果檔無法讀取：{exc}"
    if not reason:
        try:
            text = Path(result_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            text = ""
            reason = f"驗收結果檔無法讀取：{exc}"
        if not reason:
            # 🔴 第 14 輪（對應第 2 輪 A 組增補 §5-1）：解析**宣告欄位**並等值核對，
            #    不再用「全文包含字串」。⇒ 錯的宣告版本不能被附錄／內文的正確 SHA 補足（N2）。
            declaration, decl_problem = parse_verdict_declaration(text)
            if decl_problem:
                reason = f"驗收結果宣告不合格：{decl_problem}"
            elif declaration["task_id"] != key:
                reason = f"驗收結果宣告的 task_id 與目標不符（{declaration['task_id']!r}）"
            elif declaration["version"] != artifact_sha:
                reason = "驗收結果宣告的版本與受驗執行檔 SHA256 不符"
            elif str(payload.get("result_sha256") or "") != digest:
                reason = "receipt 綁定的驗收結果雜湊與實際檔案不符"

    if reason:
        _refuse_clear(key, result_path, reviewer, reason)
        print(f"clear refused: {reason}", file=sys.stderr)
        return 3

    # 一次性：先原子消費 nonce 再清 pending（避免「清成功但 nonce 未記」而可重放）。
    # 🔴 第 13 輪（§5 第 2 條）：改由 `consume_nonce()` 以 `O_CREAT|O_EXCL` 原子消費；
    #    存放區缺失／損壞、或 nonce 已用 → 一律拒絕（不再退成「空集合＝可用」）。
    nonce_problem = consume_nonce(nonce)
    if nonce_problem:
        _refuse_clear(key, result_path, reviewer, nonce_problem)
        print(f"clear refused: {nonce_problem}", file=sys.stderr)
        return 3

    cleared: list[tuple[str, str]] = []
    for target in targets:
        data[target]["completion_allowed"] = True
        data[target]["task_status"] = "已完成（獨立驗收核定）"
        data[target]["cleared_by"] = reviewer
        data[target]["cleared_at"] = now_iso()
        data[target]["cleared_by_result"] = result_path
        data[target]["cleared_result_sha256"] = digest
        cleared.append((target, str(data[target].get("pending_id") or "")))
    if not save_pending(data):
        print("clear refused: pending 存放區寫入失敗，未清除", file=sys.stderr)
        return 3
    for target, pending_id in cleared:
        append_log(
            {
                "ts": now_iso(),
                "result": "PENDING_CLEARED",
                "user_boundary_id": target,
                "task_id": key,
                "pending_id": pending_id,
                "cleared_by": reviewer,
                "result_path": result_path,
                "result_sha256": digest,
                "version": str(payload.get("version") or ""),
                "receipt_nonce": nonce,
            }
        )
    print(f"cleared {', '.join(target for target, _ in cleared)} by {reviewer}")
    return 0


def print_status(key: str) -> int:
    data, store_ok = load_pending()
    item = None
    if store_ok:
        targets = find_pending_targets(data, key)
        for target in targets:
            entry = data.get(target)
            if is_open(entry):
                item = dict(entry)
                item["stored_key"] = target
                break
        if item is None and targets:
            item = dict(data[targets[0]])
            item["stored_key"] = targets[0]
    reasons = []
    if not store_ok:
        reasons.append("pending 存放區無法解析，保守拒絕完成")
    elif item is None and log_shows_open_pending(key):
        reasons.append("pending 檔已不存在，但稽核日誌顯示這張卡仍有未清除的未完成紀錄")
    output = dict(item) if item is not None else {"task_status": "無 pending"}
    if reasons:
        output["completion_allowed"] = False
        output["task_status"] = "進行中"
        output["reason"] = reasons
    output.setdefault("completion_allowed", True)
    print(json.dumps({"user_boundary_id": key, **output}, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------- transcript 解析

def role_and_text(row: dict) -> tuple[str | None, str]:
    role = row.get("role")
    content = row.get("content", "")
    message = row.get("message")
    if isinstance(message, dict):
        role = role or message.get("role")
        content = message.get("content", content)
    if isinstance(content, str):
        return role, content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return role, "\n".join(parts)
    return role, ""


def valid_message_id(value: object) -> str:
    """訊息 ID 只接受「合法非空字串」（驗收第 4 條）。

    非字串（dict／list／int／bool）一律不接受；含控制字元、行／段落分隔、bidi 控制、
    換行的字串一律不接受。不接受就略過，讓上層繼續找下一個候選。

    第 9 輪整改（對應 Codex 第 8 輪 A5）：**先對 raw value 檢查禁字**，再做 ASCII-only 修剪。
    前一版先做 Unicode `strip()`，於是 `"good\\n"`、`"good\\u0085"` 會被修剪成 `"good"` 後放行
    —— 不同的原始 boundary 因此可能被正規化成同一個 key。
    """
    if not isinstance(value, str) or not value:
        return ""
    if FORBIDDEN_IN_ID_RE.search(value):
        return ""
    return value.strip(" \t")


def message_id(row: dict) -> str:
    """取訊息 ID：同時看 top-level 與巢狀 `row.message`，且**只接受合法字串**。

    第 8 輪整改（驗收第 4 條）：非法候選（dict／list／int／bool／含控制或換行字元）
    必須略過並繼續找下一個候選；不得對任意值 `str()`（那會讓非空 top-level dict
    遮蔽後面的合法 nested ID）。
    """
    candidates = [row.get("id"), row.get("messageId")]
    message = row.get("message")
    if isinstance(message, dict):
        candidates.extend([message.get("id"), message.get("messageId")])
    for value in candidates:
        text = valid_message_id(value)
        if text:
            return text
    return ""


def current_turn(rows: list[dict]) -> tuple[list[dict], str, int]:
    user_indexes = []
    query_indexes = []
    for index, row in enumerate(rows):
        role, text = role_and_text(row)
        if role == "user":
            user_indexes.append(index)
            if "<user_query>" in text:
                query_indexes.append(index)
    indexes = user_indexes or query_indexes
    if not indexes:
        raise ValueError("transcript 尾段找不到本輪 user 邊界")
    start = indexes[-1]
    boundary_id = message_id(rows[start])
    if not boundary_id:
        for candidate in reversed(query_indexes):
            boundary_id = message_id(rows[candidate])
            if boundary_id:
                break
    return rows[start + 1 :], boundary_id, start


def call_id(row: dict) -> str:
    return str(row.get("callId") or row.get("call_id") or row.get("id") or "")


def parse_arguments(row: dict) -> dict:
    value = row.get("arguments", {})
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def result_has_content(row: dict) -> bool:
    output = row.get("output")
    if isinstance(output, str):
        return bool(output.strip())
    if isinstance(output, dict):
        text = output.get("text")
        return isinstance(text, str) and bool(text.strip())
    return False


def inspect_turn(rows: list[dict]) -> tuple[set[str], list[str], int | None, int | None, dict[str, int]]:
    skill_calls: dict[str, tuple[str, int]] = {}
    completed_results: dict[str, int] = {}
    tools = []
    first_mutation = None
    first_response = None

    for index, row in enumerate(rows):
        role, text = role_and_text(row)
        if role == "assistant" and text.strip() and first_response is None:
            first_response = index
        row_type = row.get("type")
        name = row.get("name")
        if row_type == "function_call":
            if isinstance(name, str):
                tools.append(name)
            if name in MUTATING_TOOLS and first_mutation is None:
                first_mutation = index
            if name == "Skill":
                arguments = parse_arguments(row)
                skill = arguments.get("skill") or arguments.get("skill_name")
                if isinstance(skill, str) and call_id(row):
                    skill_calls[call_id(row)] = (skill, index)
        elif row_type == "function_call_result" and row.get("status") == "completed" and result_has_content(row):
            completed_results[call_id(row)] = index

    completed = set()
    positions: dict[str, list[int]] = {}
    for identifier, (skill, _) in skill_calls.items():
        if identifier in completed_results:
            completed.add(skill)
            positions.setdefault(skill, []).append(completed_results[identifier])
    completion_index = {skill: min(value) for skill, value in positions.items()}
    return completed, tools, first_mutation, first_response, completion_index


# ---------------------------------------------------------------- 稽核主流程

def base_record(event: dict) -> dict:
    return {
        "ts": now_iso(),
        "session_id": str(event.get("session_id") or ""),
        "generation_id": str(event.get("generation_id") or ""),
        "transcript_path": str(event.get("transcript_path") or ""),
        "stop_hook_active": bool(event.get("stop_hook_active")),
        # 記錄宿主實際提供的欄位名（第 8 輪 R1 實測用；不含值，避免外洩內容）。
        "event_keys": sorted(str(key) for key in event.keys()),
    }


def allow_error(event: dict, reason: str) -> int:
    """工具層級錯誤：放行（不卡住使用者），但這一輪不得取得完成資格。"""
    record = base_record(event)
    record.update(
        {
            "result": "ERROR_ALLOW",
            "reason": [reason],
            "task_status": "進行中",
            "completion_allowed": False,
            "pending_violation": False,
        }
    )
    print(f"discipline-audit ERROR_ALLOW: {reason}", file=sys.stderr)
    return persist_or_block(record) or 0


def parse_cli(argv: list[str]) -> tuple[list[str], dict]:
    options = {"result": "", "version": "", "by": "", "receipt": ""}
    positionals = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in ("--result", "--version", "--by", "--receipt"):
            options[token[2:]] = argv[index + 1] if len(argv) > index + 1 else ""
            index += 2
            continue
        positionals.append(token)
        index += 1
    return positionals, options


def main() -> int:
    argv = sys.argv[1:]
    if argv[:1] == ["--status"]:
        return print_status(argv[1] if len(argv) >= 2 else "")
    if argv[:1] == ["--clear"]:
        positionals, options = parse_cli(argv[1:])
        key = positionals[0] if positionals else ""
        return clear_pending(key, options["result"], options["version"], options["by"], options["receipt"])

    try:
        event = json.load(sys.stdin)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return allow_error({}, f"Stop 輸入不是有效 JSON：{exc}")

    if event.get("hook_event_name") != "Stop":
        return allow_error(event, "hook_event_name 不是 Stop")
    if event.get("last_assistant_message") == "Interrupted by user":
        record = base_record(event)
        record.update(
            {
                "result": "INTERRUPTED_ALLOW",
                "reason": ["使用者中斷"],
                "task_status": "進行中",
                "completion_allowed": False,
                "pending_violation": False,
            }
        )
        return persist_or_block(record) or 0

    transcript_text = str(event.get("transcript_path") or "")
    session_id = str(event.get("session_id") or "")
    transcript = Path(transcript_text)
    if not transcript_text or not transcript.is_file():
        return allow_error(event, "transcript_path 不存在")
    if not session_id or transcript.stem != session_id:
        return allow_error(event, "session_id 與 transcript 檔名不一致")

    try:
        all_rows = read_tail_jsonl(transcript)
        turn_rows, boundary_id, boundary_index = current_turn(all_rows)
    except (OSError, ValueError) as exc:
        return allow_error(event, str(exc))

    completed, tools, first_mutation, first_response, completion_index = inspect_turn(turn_rows)
    required = {INTERACTION}
    if first_mutation is not None:
        required = {WORK, PREWORK}
    missing = sorted(required - completed)
    deadlines = [index for index in (first_response, first_mutation) if index is not None]
    first_action = min(deadlines) if deadlines else None
    late = sorted(
        skill
        for skill in required & completed
        if first_action is not None and completion_index[skill] > first_action
    )
    resolved_card, card_problem = resolve_card(event)

    # 🔴 驗收第 3 條（後半）：卡號不能只驗字形，必須存在於權威卡片清單。
    if resolved_card:
        known, known_ok = known_card_ids()
        if not known_ok:
            card_problem = (
                (card_problem + "；") if card_problem else ""
            ) + "權威卡片清單不可讀，無法驗證卡號"
            resolved_card = ""
        elif resolved_card not in known:
            card_problem = (
                (card_problem + "；") if card_problem else ""
            ) + f"卡號 {resolved_card!r} 不在權威卡片清單"
            resolved_card = ""

    reasons = []
    if missing:
        reasons.append("缺少已完成的 Skill 載入：" + "、".join(missing))
    if late:
        reasons.append("Skill 晚於第一則回覆或第一個修改工具：" + "、".join(late))

    # 🔴 驗收第 1、2 條：取不到卡號或來源損壞 → **一律**結構化拒絕完成（無條件）。
    if not resolved_card:
        if card_problem:
            reasons.append("卡號來源不合法／損壞：" + card_problem + "。保守拒絕完成")
        else:
            reasons.append(
                "無法確定當前卡號：本輪沒有可信 identity 來源"
                "（宿主未提供 event.task_id／card_id，且未設定 T02_TASK_ID）。"
                "user 訊息文字不構成身分，保守拒絕完成"
            )

    # pending 判定（驗收第 2 條）：**只認目前卡**，不再掃「所有卡的全域 pending」。
    data, store_ok = load_pending()
    open_item = None
    if not store_ok:
        open_item = {"reason": "pending 存放區無法解析"}
    else:
        # 第 9 輪（A7）：只按**卡號**聚合查（同卡任一筆 open 就擋），
        # 不再讓「boundary 名稱精確命中」優先，那會把別張卡的 pending 誤掛到本卡。
        open_item = open_pending_for_card(data, resolved_card)
    # 存放區被刪／改版時，靠 append-only 稽核日誌回推（同樣只認卡號）。
    log_open = False
    if open_item is None and resolved_card:
        log_open = log_shows_open_pending(resolved_card)
    pending_open = open_item is not None or log_open

    record = base_record(event)
    record.update(
        {
            "user_boundary_id": boundary_id,
            "task_id": resolved_card,
            "observed_skills": sorted(completed),
            "observed_tools": tools,
            "required_skills": sorted(required),
            "assistant_response_seen": first_response is not None,
        }
    )

    if pending_open:
        reasons.append("本卡存在未清除的未完成紀錄：不得宣告完成")

    completion_allowed = not reasons
    record.update(
        {
            "reason": reasons,
            "pending_violation": bool(pending_open),
            "task_status": "可完成" if completion_allowed else "進行中",
            "completion_allowed": completion_allowed,
        }
    )

    if completion_allowed:
        # result=PASS ⟺ completion_allowed=True ∧ pending_violation=False（單一語義）。
        record["result"] = "PASS"
        return persist_or_block(record) or 0

    if event.get("stop_hook_active"):
        # 第二次 Stop：放行以免無限迴圈，但**當下就把這張卡記成未完成**（留下後果）。
        # 既然記了 pending，這一輪的 pending_violation 就必須為真 —— 否則稽核日誌會
        # 留下「放行了、也記了 pending、卻宣稱沒有 pending」的矛盾紀錄，日後存放區被
        # 刪除時就無法靠日誌回推（第 8 輪：讓 FAIL_OPEN_RETRY 與 pending 狀態一致）。
        marked = mark_pending(boundary_id, resolved_card, reasons, event)
        record["result"] = "FAIL_OPEN_RETRY"
        extra = ["第二次 Stop 放行，避免無限迴圈"]
        if not marked:
            # 🔴 第 10 輪（第 9 輪退件 §6 第 5 條）：pending 寫入失敗／存放區損壞時，
            #    留下結構化 audit，不得冒 traceback；語義上仍保守視為「本輪未完成」。
            extra.append("pending 寫入失敗：存放區不可寫或已損壞")
        record["reason"] = reasons + extra
        record["pending_rules"] = list(record["reason"])
        record["pending_id"] = marked
        record["pending_violation"] = True
        record["task_status"] = "進行中"
        record["completion_allowed"] = False
        print("discipline-audit FAIL_OPEN_RETRY: " + "；".join(record["reason"]), file=sys.stderr)
        return persist_or_block(record) or 0

    record["result"] = "BLOCK"
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": "紀律驗收不通過："
                + "；".join(reasons)
                + "。請實際載入必要技能後再完成本輪。",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    return persist_or_block(record) or 0


if __name__ == "__main__":
    raise SystemExit(main())

# <!-- 變更：Codex 桌面版 ｜ 2026-10-12 08:42 ｜ 新增 T02 Stop 紀律驗收器 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 11:1x ｜ 放行即標未完成＋修重複載入假陽性 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 11:3x ｜ 第4輪整改 -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 17:5x ｜ 第8輪整改：移除 project/cwd/session 冒充卡號；卡號改為明確宣告且缺號無條件保守拒絕；卡號改 ASCII 白名單；message_id 只收合法字串；總判定語義單一化；記錄 event_keys -->
# <!-- 變更：WorkBuddy ｜ 2026-10-12 22:3x ｜ 第9輪整改：宣告只認目前 boundary（A2）；拒 code fence 與多宣告、拒來源衝突、卡號對照權威卡片清單（A3）；宣告值不先 Unicode strip（A4）；boundary raw 先驗禁字再 ASCII trim（A5）；空 boundary 以卡號留 pending（A6）；pending 只按卡號聚合、損壞不覆寫（A7） -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 00:0x ｜ 第10輪整改（對應第9輪退件§6）：移除 user content 卡號來源（§6-1/2）；pending 以穩定 pending_id 逐筆追蹤 open/clear（§6-3）；--clear 核對 entry task_id 與驗收結果 task_id 綁定（§6-4）；save_pending 捕捉例外不冒 traceback（§6-5） -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 00:4x ｜ 第11輪整改（對應第10輪退件§5 第1～3條）：新增「核定通行碼」防線（--token，只比 SHA256；未設定則拒絕所有清除，§5-2/3）；驗收結果必須綁定 pending_ids（§5-2）；並在文件明示「流程控制非密碼學保證」的限制（§5-3） -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 09:xx ｜ 第12輪整改（對應第11輪退件§5 第1～4條）：移除對稱通行碼與所有呼叫者可覆蓋的授權來源（env／可改檔案／CLI）；改採非對稱簽章 receipt（內嵌公鑰驗簽、openssl，§5-2/3）；receipt 綁定 task_id／version／pending_ids／result_sha256 ＋ 一次性 nonce；公鑰未安裝一律拒絕；D003 同卡 pending 去重（count 累加） -->
# <!-- 變更：WorkBuddy ｜ 2026-10-13 16:0x ｜ 第13輪整改（對應第2輪A組§5 第1～3、6條）：版本綁定改以「受驗執行檔自身 SHA256」為權威值、省略 --version 亦不得略過（A1）；防重放狀態改為每筆 nonce 一個 O_EXCL 原子標記檔、路徑由 PENDING_PATH 衍生並移除 T02_NONCE_PATH、缺失／損壞保守拒絕、mark_pending 一併初始化（A2/A3＋並行原子性）；pending 鍵改以卡號為主、boundary 僅 metadata、不覆寫他卡 entry（A4）；並列明信任邊界（§5 第 4 條，未施工） -->


