#!/usr/bin/env bash
# 鸵鸟重试判定：判断一个任务会话是否属于"异常"需要重试。
# 原则：只重试"卡死 / 异常中断"的任务；正常的仅超时失败（一直工作到预算
# 结束仍未收敛）绝不重试——那只是时间不够，重试徒增成本。
#
# 用法: bash should_retry.sh <RC> <ELAPSED> <TIMEOUT> <session.jsonl> <finalize.json> [session.log]
# 输出: 0=不重试 1=A提前退出 2=B未达上限失败 3=C卡死超时 4=D请求级异常
set -u
RC="$1"
ELAPSED="$2"
TIMEOUT="$3"
SESSION="$4"
FINALIZE="$5"
SESSLOG="${6:-}"

# 从 finalize.json 判断任务是否成功
task_success=0
if [ -f "$FINALIZE" ]; then
  success_val=$(python3 -c "
import json,sys
try:
    d=json.load(open('$FINALIZE'))
    ls=d.get('last_submit') or {}
    print(1 if ls.get('fix_verified_success') else 0)
except Exception:
    print(0)
" 2>/dev/null || echo 0)
  [ "$success_val" = "1" ] && task_success=1
fi

# 已成功则绝不重试
if [ "$task_success" = "1" ]; then
  echo 0
  exit 0
fi

# 会话最后活动的相对时间（秒）= session.jsonl 最后一个事件 - 首个事件。
# opencode 在 LLM 流式请求挂起期间不写任何日志，所以卡死会话的最后事件
# 远早于预算结束；正常干满到超时的会话最后事件接近预算终点。该值即"实际
# 活动跨度"，卡死则远小于 ELAPSED。无法解析时输出 -1（保守：不重试）。
last_rel=$(python3 -c "
import json, sys
path = '$SESSION'
ts = []
try:
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            t = r.get('timestamp')
            if t:
                ts.append(t)
except Exception:
    ts = []
if len(ts) >= 2:
    span = (ts[-1] - ts[0]) / 1000
    print('%.0f' % span if span >= 0 else '-1')
else:
    print('-1')
" 2>/dev/null || echo -1)

# A类: 异常提前退出（非正常结束、非超时/强杀，且远没跑满时限）
if [[ "$RC" != "0" && "$RC" != "124" && "$RC" != "137" ]]; then
  if (( ELAPSED < TIMEOUT / 2 )); then
    echo 1
    exit 0
  fi
fi

# B类: 正常结束(RC=0)但任务失败，且远没跑满时限（模型早早放弃/走偏）
if [[ "$RC" == "0" ]]; then
  if (( ELAPSED < TIMEOUT / 2 )); then
    echo 2
    exit 0
  fi
fi

# C类: 卡死超时——超时/强杀(RC=124/137) 且会话中途停止活动（最后活动早于
# 预算一半 → 剩余预算全被闲置浪费）。正常干满超时的任务最后活动接近预算
# 终点，不会命中此判定。opencode 层 chunkTimeout 已把请求挂起提前中止（10min
# 无 chunk 即报错），此判定作为 watchdog 强杀后的兜底仍有效。
if [[ "$RC" == "124" || "$RC" == "137" ]]; then
  if [[ "$last_rel" != "-1" ]] && (( last_rel < TIMEOUT / 2 )); then
    echo 3
    exit 0
  fi
fi

# D类: 请求级异常——opencode 的 LLM 请求反复超时/中止（chunkTimeout 触发或
# 网络错误），>=3 次说明环境故障，即使 elapsed 已过一半也值得重试（不是
# "干满超时"而是"反复失败"）。排除 models.dev 的启动期噪音（离线环境下每次
# 启动都有一条）。这是 chunkTimeout 引入的新失败形态的补充判定。
if [ -n "$SESSLOG" ] && [ -f "$SESSLOG" ]; then
  # 严格模式：整行匹配 ERROR + 关键词，且不含 models.dev 噪音
  req_err=$(grep -E 'level=ERROR' "$SESSLOG" 2>/dev/null | grep -iE 'timeout|abort|timed out|APICallError' | grep -v 'models.dev' | wc -l)
  if (( req_err >= 3 )); then
    echo 4
    exit 0
  fi
fi

echo 0
exit 0
