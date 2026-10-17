# T02 受保護簽發 · 結果檔（C0d 版）

> **性質**：本檔為 T02 受保護簽發鏈所綁定的結果檔，隨受驗 commit 鎖定。
> 「pass」宣告＝「受驗版本（version）對其目標 pending 集合（pending_ids）之清除處置，
> 經受驗鏈（雙源比對、申請檔自洽、防 TOCTOU）核對通過」。
> **T02「紀律＝做到」之最終完成判定權，仍屬獨立驗收方；本檔不代替該判定。**
> 簽發授權：GitHub 受保護環境 `t02-signing`（業主審批）；私鑰不出環境 secret。
>
> **C0d 修訂（2026-10-17，依 Codex 獨立驗收 C0c 判定之整改①②）**：清除授權與產出者
> 隔離。稽核器已安裝**第二信任根**（獨立核准公鑰；來源＝Codex 交接
> `T02-c0d-approval-handoff.md` 與 `T02-c0d-approval-pubkey.pem`，指紋
> `7ed43de11e47e57b`）。`--clear` 現須**雙簽**：受保護環境簽發之 receipt，加獨立核准者對
> 同一份 receipt 簽發之核准（精確綁定 task_id／version／pending_ids／
> result_sha256／receipt_sha256／receipt_nonce）。缺核准、偽造核准、冒充核准
> 公鑰指紋，一律拒絕；`cleared_by` 改記核准公鑰指紋，呼叫者自填之 `--by`
> 文字永不入庫。產出者（WorkBuddy）自清必被拒（實證見
> `T02-c0d-evidence/refusals/`）。

task_id=T02
pending_ids=013d9ce10b7e,02ce2ec81472,1bd79d0aca7c,2ae94819a899,2fcce6dd283a,35cb99f02cf8,5249997396af,56bb4afd191e,5a79712ab238,91ebcad26a36,9e214e94e8a7,ab7ddd3b04d1,b30532701e6d,c047d8a2866f,cf6fd5c549e6,d7fecaef7aa8,dbc5b1117f86,e33fb44be75f,e3d63019d981,eb46f38833d4,f4f056fa90b9
<!-- T02-VERDICT: pass version=ae79a6a25fff4b26aecbf7f0acc42f5d5c24706c3eeb460b610d19bf157c7671 -->
