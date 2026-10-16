# T02 受保護簽發 · 結果檔（C0c 版）

> **性質**：本檔為 T02 受保護簽發鏈所綁定的結果檔，隨受驗 commit 鎖定。
> 「pass」宣告＝「受驗版本（version）對其目標 pending 集合（pending_ids）之清除處置，
> 經受驗鏈（雙源比對、申請檔自洽、防 TOCTOU）核對通過」。
> **T02「紀律＝做到」之最終完成判定權，仍屬獨立驗收方；本檔不代替該判定。**
> 簽發授權：GitHub 受保護環境 `t02-signing`（業主審批）；私鑰不出環境 secret。
>
> **C0c 修訂（2026-10-16，依 Codex 獨立驗收整改第 1、2 條）**：正式 pending 存放區已完成
> 「malformed 記錄遷移」：21 筆「無卡號（task_id 為空）」的歷史記錄（產生於 2026-10-12~10-13
> 施工早期、稽核器尚無法解析卡號時逐輪寫入）已原樣移入 `T02-legacy-pending-archive.json`
> （含完整遷移 metadata 與原文；工具＝`migrate-legacy-pending.py`，dry-run 預設、備份＋前後 SHA 對照）。
> 主 store 現只含可識別卡號的記錄（T02：21 筆，即本檔所綁定之集合）。

task_id=T02
pending_ids=013d9ce10b7e,02ce2ec81472,1bd79d0aca7c,2ae94819a899,2fcce6dd283a,35cb99f02cf8,5249997396af,56bb4afd191e,5a79712ab238,91ebcad26a36,9e214e94e8a7,ab7ddd3b04d1,b30532701e6d,c047d8a2866f,cf6fd5c549e6,d7fecaef7aa8,dbc5b1117f86,e33fb44be75f,e3d63019d981,eb46f38833d4,f4f056fa90b9
<!-- T02-VERDICT: pass version=ae945086de9786d26114dbb7a35c02341abd92783dad2097835bfa835035376e -->
