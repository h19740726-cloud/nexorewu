# T02 第 13 輪受驗材料（對應 Codex 第 2 輪 A 組四反例整改）

受驗對象＝`T02-discipline-audit.py`（WorkBuddy Stop hook 紀律稽核器）。

## 受驗版本（逐檔 SHA256）

| 檔案 | bytes | SHA256 |
|:--|--:|:--|
| `T02-discipline-audit.py` | 56799 | `7d0468ab875ae96af560b98797e470bcedd8ac4188c6cce5cb46b268045679ba` |
| `test_T02_discipline_audit.py` | 80007 | `e6896b55025df17b2a58145dc4df0993b37fe9dbd15af64b39fd3aa03d697dae` |
| `mutate12.py` | 5634 | `d5a584caf24782a06428795dc4fec338b87db3806cd3a7ecb0f0db920e0c14a6` |
| `repro-round2.py` | 8675 | `238e1c2a5c2d7f4c93dac570e4948abf6cec794327835cc1e402486e15168e6c` |
| `e2e12.py` | 7280 | `f9cff20634f6454e67f77c0b9152fa2a24c48d097d2d0b51037c729b2e25bfb9` |
| `sign-receipt.py` | 5925 | `6c77ec63e37d424dbdb54504ab57adc4c3300641cfbc5cfe0cdd4183a46baf50` |
| `gen-receipt-key.py` | 1876 | `c128c49689f3c9c98129d69eb8d95b9d884bb79cdd2eda1b4035f288752551ee` |

## 怎麼跑

```bash
python3 -m unittest -v test_T02_discipline_audit          # 應 OK（74 條）
env -u T02_TASK_ID -u T02_NONCE_PATH python3 e2e12.py      # 應 5/5
python3 mutate12.py                                        # 應精準 9/9、還原逐位元相同
env -u T02_TASK_ID -u T02_NONCE_PATH python3 repro-round2.py  # 應 5/5（公開介面複驗）
```

## 本輪修正（對應第 2 輪 A 組 §5 第 1～3、6 條）

1. 版本綁定＝受驗執行檔自身 SHA256（省略 `--version` 亦不得略過）。（A1）
2. 防重放狀態＝每筆 nonce 一個 `O_CREAT|O_EXCL` 原子標記檔；路徑由 pending 路徑衍生、
   移除 `T02_NONCE_PATH`；缺失／損壞一律拒絕；初始化由 `mark_pending()` 完成。（A2／A3）
3. pending 鍵以卡號為主、boundary 僅 metadata、不覆寫他卡。（A4）

## 未施工（不得算通過）

- §5-4 正式持鑰與簽發權隔離（待業主決定私鑰裝置）。
- §5-5 同 commit CI run URL 與正式全鏈（需業主於 GitHub 網頁開 PR）。
- B／C 組未施工。

> 本分支只放受驗材料；未動 `main`、未動其他分支與 PR。
