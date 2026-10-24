#!/bin/bash
# T02 C0d 第四階段：凍結態驗證執行器（同一 commit、單輪；可分批突變後彙總）
#
# 用法：
#   ./run-c0d-battery.sh <commit_sha>                         # 只跑測試鏈，產 pre-freeze.json（不含結果綁定）
#   ./run-c0d-battery.sh <commit_sha> --result-sha <64hex>    # 額外要求 request 已綁 Codex 結果，通過才產 frozen.json
#   ./run-c0d-battery.sh <commit_sha> --skip-mutation         # 突變已另行分批跑完（讀既有 mutate-full18.out）
#
# 前置（機械檢查，任一不合即中止、不改任何受驗檔）：
#   1) 目前 HEAD == <commit_sha>，且 tracked 工作區乾淨（受驗檔必須就是凍結版）
#   2) 受驗稽核器在整輪執行前後 SHA256 相同
#   3) --result-sha 模式下：request.result_path 必須是本輪 Codex 獨立結果檔（非 T02-sign-verdict.md）
#
# 輸出（全部落在 T02-c0d-evidence/battery/，檔名與出包器 gen-c0d-package.py 對齊）：
#   suite-123-final.out／test-sign-inputs.out／e2e12.out／repro.out／rehearse.out／mutate-full18.out
#   battery-meta.json（本輪執行指紋）／pre-freeze.json 或 frozen.json
#
# 門檻（缺一即失敗，日誌整批移入 battery-failure/）：
#   123 tests、30 sign-input、6/6 e2e、5/5 repro、18/18 mutation、稽核器 bytes 不變、
#   pending 21 筆且 0 筆已清、request.version == 稽核器實算
set -euo pipefail
cd "$(dirname "$0")"

COMMIT="${1:?用法：run-c0d-battery.sh <commit_sha> [--result-sha <64hex>] [--skip-mutation]}"
shift || true
RESULT_SHA=""
SKIP_MUTATION=0
while [ $# -gt 0 ]; do
  case "$1" in
    --result-sha) RESULT_SHA="${2:?缺少 --result-sha 的值}"; shift 2 ;;
    --skip-mutation) SKIP_MUTATION=1; shift ;;
    *) echo "未知參數：$1" >&2; exit 2 ;;
  esac
done

E="/Users/wulieqiang/AI協作/work/codex/T02-c0d-evidence"; B="$E/battery"; F="$E/battery-failure"
mkdir -p "$B" "$F"

# ---- 前置 1：HEAD 與工作區 ----
HEAD_SHA=$(git rev-parse HEAD)
if [ "$HEAD_SHA" != "$COMMIT" ]; then
  echo "[battery] ABORT: HEAD=$HEAD_SHA 與指定 commit=$COMMIT 不符（受驗版必須就是凍結版）" >&2
  exit 2
fi
DIRTY=$(git status --porcelain -uno)
if [ -n "$DIRTY" ]; then
  echo "[battery] ABORT: tracked 工作區不乾淨，受驗版不是凍結版：" >&2
  echo "$DIRTY" >&2
  exit 2
fi

AUDIT_BEFORE=$(shasum -a 256 T02-discipline-audit.py | awk '{print $1}')
echo "[battery] commit=$COMMIT auditor(before)=$AUDIT_BEFORE result_binding=${RESULT_SHA:-（無，pre-freeze 模式）}"

# ---- 測試鏈（單輪；rc 全部留檔，不因單項紅就中斷，讓彙總一次講清楚）----
run() { # run <標籤> <輸出檔> <指令...>
  local tag="$1" out="$2"; shift 2
  local t0=$SECONDS
  echo "[battery] start $tag $(date '+%F %T')" >&2
  "$@" > "$B/$out" 2>&1 || true
  echo "[battery] done  $tag rc? elapsed=$((SECONDS - t0))s" >&2
}

run suite-123        suite-123-final.out      python3 test_T02_discipline_audit.py
run sign-inputs-30   test-sign-inputs.out     python3 test-sign-inputs.py
run e2e12            e2e12.out                python3 e2e12.py
run repro-round2     repro.out                python3 repro-round2.py
run rehearse         rehearse.out             python3 rehearse-final-chain.py

if [ "$SKIP_MUTATION" -eq 1 ]; then
  echo "[battery] mutation 沿用既有 $B/mutate-full18.out（--skip-mutation）" >&2
else
  run mutate18 mutate-full18.out            python3 mutate12.py
fi

AUDIT_AFTER=$(shasum -a 256 T02-discipline-audit.py | awk '{print $1}')

python3 - "$COMMIT" "$RESULT_SHA" "$AUDIT_BEFORE" "$AUDIT_AFTER" <<'PY'
import datetime, hashlib, json, pathlib, re, subprocess, sys

commit, result_sha, audit_before, audit_after = sys.argv[1:5]
base = pathlib.Path(".")
B = pathlib.Path("/Users/wulieqiang/AI協作/work/codex/T02-c0d-evidence/battery")
F = pathlib.Path("/Users/wulieqiang/AI協作/work/codex/T02-c0d-evidence/battery-failure")
STORE = pathlib.Path("/Users/wulieqiang/AI協作/work/codex/T02-pending-violations.json")
CODEX_RESULT = "T02-c0d-codex-result.md"

def read(name):
    p = B / name
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

problems = []

suite = read("suite-123-final.out")
m = re.search(r"Ran (\d+) tests", suite)
if not (m and m.group(1) == "123") or "\nOK" not in suite:
    problems.append(f"123 tests 未達標（實得 {m.group(1) if m else '無'}）")

tsi = read("test-sign-inputs.out")
m = re.search(r"Ran (\d+) tests", tsi)
if not (m and m.group(1) == "30") or "\nOK" not in tsi:
    problems.append(f"30 sign-input 未達標（實得 {m.group(1) if m else '無'}）")

if "6/6 通過" not in read("e2e12.out"):
    problems.append("e2e 未達 6/6")
if "5/5 通過" not in read("repro.out"):
    problems.append("repro 未達 5/5")
if "18/18 通過" not in read("rehearse.out"):
    problems.append("rehearse 未達 18/18")

# 突變：支援分批（每批尾端一行「精準 k/m」），彙總必須 18/18
mut = read("mutate-full18.out")
pairs = [(int(a), int(b)) for a, b in re.findall(r"精準 (\d+)/(\d+)", mut)]
mut_ok = sum(a for a, b in pairs)
mut_total = sum(b for a, b in pairs)
if not pairs or mut_ok != 18 or mut_total != 18:
    problems.append(f"mutation 未達 18/18（彙總 {mut_ok}/{mut_total}，批數 {len(pairs)}）")
if "正式受驗檔未被寫入（前後 SHA256 相同）：True" not in mut:
    problems.append("mutation 未證明正式受驗檔未被寫入")
# 突變日誌來源校驗（--skip-mutation 時，日誌必須出自同一顆稽核器 bytes）
if f"正式受驗檔 SHA256：{audit_before}" not in mut:
    problems.append(f"mutation 日誌的稽核器 SHA256 不是本輪的 {audit_before[:12]}…（跨版本沿用）")

if audit_before != audit_after:
    problems.append("受驗稽核器在驗證期間被改動")

audit_sha = sha("T02-discipline-audit.py")
if audit_sha != audit_before:
    problems.append("稽核器現況 SHA256 與執行前不符")

request = json.loads((base / "T02-sign-request.json").read_text(encoding="utf-8"))
if request.get("version") != audit_sha:
    problems.append("request.version 與稽核器不符")

store = json.loads(STORE.read_text(encoding="utf-8"))
entries = [v for v in store.values() if isinstance(v, dict) and str(v.get("task_id")) == "T02"]
ids = sorted(str(v.get("pending_id")) for v in entries)
cleared = sum(1 for v in entries if v.get("cleared_by"))
if len(ids) != 21 or len(set(ids)) != 21:
    problems.append(f"pending 集合不是 21 筆（實得 {len(set(ids))}）")
if cleared != 0:
    problems.append(f"pending 有 {cleared} 筆已被清除")
if request.get("pending_ids") != ids:
    problems.append("pending 集合與 request 不符")

binding_note = "none"
if result_sha:
    if request.get("result_sha256") != result_sha:
        problems.append("request.result_sha256 與指定結果不符")
    if request.get("result_path") != CODEX_RESULT:
        problems.append(f"request.result_path 不是 Codex 獨立結果（實得 {request.get('result_path')}）")
    if not (base / CODEX_RESULT).is_file():
        problems.append(f"repo 內沒有 {CODEX_RESULT}")
    else:
        text = (base / CODEX_RESULT).read_text(encoding="utf-8")
        if not re.search(r"^result_author=Codex[ \t]*$", text, re.MULTILINE):
            problems.append("Codex 結果檔缺 result_author=Codex 宣告")
        if sha(base / CODEX_RESULT) != result_sha:
            problems.append("Codex 結果檔實算 SHA256 與 --result-sha 不符")
    binding_note = "codex-result"

meta = {
    "commit": commit,
    "auditor_sha256": audit_sha,
    "mode": binding_note,
    "started_finished": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
    "logs": {p.name: {"bytes": p.stat().st_size, "sha256": sha(p)}
             for p in sorted(B.glob("*")) if p.is_file() and p.suffix in {".out"}},
    "mutation_batches": len(pairs),
}

if problems:
    meta["problems"] = problems
    (B / "battery-meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for line in problems:
        print(f"[battery] FAIL: {line}", file=sys.stderr)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    for p in sorted(B.iterdir()):
        if p.is_file():
            p.rename(F / f"{stamp}-{p.name}")
    sys.exit(2)

(B / "battery-meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

record = {
    "commit": commit,
    "auditor_sha256": audit_sha,
    "request_path": request.get("result_path"),
    "request_sha256": sha("T02-sign-request.json"),
    "pending_ids_count": len(ids),
    "pending_cleared": cleared,
    "tests": {"suite": "123", "sign_inputs": "30", "e2e": "6/6", "repro": "5/5",
              "rehearse": "18/18", "mutation": "18/18"},
    "mutation_batches": len(pairs),
    "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
}
if result_sha:
    record["result_sha256"] = result_sha
    record["result_path"] = request.get("result_path")
    (B / "frozen.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("[battery] OK — frozen.json 已寫入（已綁 Codex 結果）")
else:
    record["binding"] = "pending-codex-result"
    (B / "pre-freeze.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("[battery] OK — 測試鏈全綠，pre-freeze.json 已寫入（尚未綁 Codex 結果，不出 frozen.json）")
print(json.dumps(record, ensure_ascii=False, indent=2))
PY
