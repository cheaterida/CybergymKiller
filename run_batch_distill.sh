#!/usr/bin/env bash
# Batch solve + auto distill orchestration.
#
# Runs the full 50-task batch (2 workers, 5400s/task), then — after the batch —
# prompts to enable network, aggregates reflections, and runs the web-assisted
# distill session so the model can produce candidate knowledge entries.
#
# NETWORK NOTE: the batch runs under isolation; the distill step needs the
# internet. This script will pause before distill and ask you to run:
#     sudo bash ~/netunlock.sh
# After distill completes, it suggests re-enabling isolation with:
#     sudo bash ~/netlock.sh
#
# Usage:
#   bash run_batch_distill.sh                      # all 50 tasks, default settings
#   bash run_batch_distill.sh --tasks file.json
#   bash run_batch_distill.sh --batch 2026-08-25   # batch label for distill
#   bash run_batch_distill.sh --skip-batch         # only run distill on existing batch
#   bash run_batch_distill.sh --timeout 5400 --workers 2

set -u
cd "$(dirname "$(readlink -f "$0")")" || exit 1

TASKS_FILE="tasks.json"
TIMEOUT=5400
WORKERS=2
BATCH=""
LOG_ROOT=""
SKIP_BATCH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tasks) TASKS_FILE="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --workers) WORKERS="$2"; shift 2;;
    --batch) BATCH="$2"; shift 2;;
    --log-root) LOG_ROOT="$2"; shift 2;;
    --skip-batch) SKIP_BATCH=1; shift;;
    *) echo "unknown option: $1"; exit 2;;
  esac
done

if [[ -z "$BATCH" ]]; then
  BATCH=$(date +%Y%m%d)
fi

echo "================ run_batch_distill ================"
echo "batch=$BATCH tasks_file=$TASKS_FILE timeout=$TIMEOUT workers=$WORKERS"
echo "log_root=$LOG_ROOT skip_batch=$SKIP_BATCH"
echo "===================================================="

# ---- Phase 1: batch solve (isolated) ----
# NOTE: no outer `timeout` here. batch_solve.sh already enforces a per-task
# timeout (--timeout, default 5400) plus a per-task watchdog. Wrapping the whole
# batch in an outer timeout would kill it mid-run for large task sets.
if [[ "$SKIP_BATCH" -eq 0 ]]; then
  echo ""
  echo ">>> Phase 1: batch solve (network isolated)"
  LOG_ROOT_ARG=()
  if [[ -n "$LOG_ROOT" ]]; then
    LOG_ROOT_ARG=(--log-root "$LOG_ROOT")
  fi
  bash batch_solve.sh \
    --tasks "$TASKS_FILE" \
    --timeout "$TIMEOUT" \
    --workers "$WORKERS" \
    "${LOG_ROOT_ARG[@]}"
  BATCH_RC=$?
  # Pick up the actual batch dir batch_solve.sh created (auto round numbering).
  if [[ -z "$LOG_ROOT" ]] && [ -f logs/.last_batch ]; then
    LOG_ROOT="$(cat logs/.last_batch)"
  fi
  echo ">>> Batch solve finished (exit=$BATCH_RC), logs in: $LOG_ROOT"
else
  if [[ -z "$LOG_ROOT" ]] && [ -f logs/.last_batch ]; then
    LOG_ROOT="$(cat logs/.last_batch)"
  fi
  echo ">>> Skipping batch solve (--skip-batch); using $LOG_ROOT"
fi

# ---- Phase 2: distill (needs network) ----
echo ""
echo ">>> Phase 2: distill reflections (needs internet)"
echo "The batch is done. Distillation needs web access."
echo "Please run in a separate terminal (as needed):"
echo "    sudo bash ~/netunlock.sh"
read -r -p "Press Enter once network is enabled (or type 'skip' to skip distill): " ANSWER
if [[ "$ANSWER" == "skip" ]]; then
  echo "Skipping distill. You can run it later:"
  echo "  python3 distill.py run --input logs/distill_input/${BATCH}_needs.json"
  exit 0
fi

echo ">>> Aggregating reflections..."
python3 distill.py collect --batch "$BATCH"
echo ">>> Starting web-assisted distill session..."
python3 distill.py run --input "logs/distill_input/${BATCH}_needs.json" --timeout 2400
DISTILL_RC=$?

# Archive the distill artifacts into the batch dir, then clear the runtime
# distill dirs (distill.py recreates them on demand with mkdir(exist_ok=True)).
if [[ -n "$LOG_ROOT" ]] && [[ -d "$LOG_ROOT" ]]; then
  for SUB in distill_input distill_pending; do
    if [ -d "logs/$SUB" ] && [ -n "$(ls -A "logs/$SUB" 2>/dev/null)" ]; then
      mkdir -p "$LOG_ROOT/$SUB"
      cp -a "logs/$SUB/." "$LOG_ROOT/$SUB/"
      echo "  -> archived logs/$SUB -> $LOG_ROOT/$SUB/"
    fi
  done
  rm -rf logs/distill_input logs/distill_pending
  echo "  -> cleared runtime logs/distill_input and logs/distill_pending"
else
  echo "  -> WARNING: no batch dir available; keeping logs/distill_input and logs/distill_pending"
fi

echo ""
echo ">>> Distill finished (exit=$DISTILL_RC). Draft saved to:"
ls -la "$LOG_ROOT/distill_pending/${BATCH}_draft.json" 2>/dev/null || ls -la logs/distill_pending/${BATCH}_draft.json 2>/dev/null
echo ""
echo "Review the draft, then import what you approve:"
echo "  python3 import_knowledge.py --input $LOG_ROOT/distill_pending/${BATCH}_draft.json --domain reasoning --list"
echo "  python3 import_knowledge.py --input $LOG_ROOT/distill_pending/${BATCH}_draft.json --domain reasoning --approve <idx,...>"
echo ""
echo "Remember to restore isolation after distill:"
echo "    sudo bash ~/netlock.sh"

# Batch-end cleanup: drop the distill session + clear the event table and
# VACUUM so opencode's DB does not grow across batches.
echo ""
echo ">>> Post-batch opencode DB cleanup"
timeout 900 python3 "$(dirname "$(readlink -f "$0")")/opencode_cleanup.py" 2>&1 | sed 's/^/  /'
