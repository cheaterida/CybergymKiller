# Architecture — CybergymKiller (opencode-driven)

> 当前主导版本架构说明（2026-08-25 更新）。

## 1. 总体结构

本项目是 CyberGym 漏洞利用求解框架。模型（通过 opencode）自主完成
"读任务 → 分析漏洞 → 构造 PoC 输入 → 实验验证 → 提交判定 → 反思沉淀"。
项目刻意保持**薄封装 + 模型主导**：桥接层只做确定性能力封装，不含任何
调查/推理逻辑。

```
┌────────────────────────────── opencode（每任务独立 headless 会话）──────────────┐
│  AGENTS.md：判据 / 工具 / 工作区 / 隔离 / 认知引导                                 │
│  .opencode/tools/*.ts：12 个自定义工具（@opencode-ai/plugin）                      │
└──────────────────────────────┬───────────────────────────────────────────────────┘
                               │ 调用
┌──────────────────────────────▼───────────────────────────────────────────────────┐
│  opencode_bridge.py（thin CLI，无推理逻辑）                                        │
│  ├─ experiment / experiment_fix ── dynamic_experiment.py（vul/fix 二进制实验）     │
│  ├─ dyn_start/exec/stop/cleanup ── whole_session.py（动态容器会话）                 │
│  ├─ format_identify/blueprint/template ── tools/format_kb_tool.py → vendor/format_kb│
│  ├─ knowledge_search ── 经验库关键词检索（knowledge/format + reasoning）           │
│  ├─ submit / finalize ── 确定性验证与归档（logs/archive）                          │
│  ├─ reflect / reflect_outcome ── 反思记录（含任务成败来源标记）                    │
│  └─ stats ── 批次统计聚合                                                        │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### 依赖闭包（当前版本必要文件）

- 入口脚本：`batch_solve.sh`、`run_batch_distill.sh`、`should_retry.sh`
- Python 核心链：
  - `opencode_bridge.py` → `dynamic_experiment.py` → `config.py`
  - `opencode_bridge.py` → `whole_session.py` → `dynamic_experiment.py` → `config.py`
  - `opencode_bridge.py` → `tools/format_kb_tool.py` → `config.py` + `vendor/format_kb/`
  - `opencode_bridge.py` → `task_io.py`（任务目录解析）+ `postcheck.py`（/submit-fix 验证）→ `config.py`
  - `distill.py`（标准库）、`import_knowledge.py` → `knowledge/maintain.py` → `core/llm.py` + `config.py`
- 配置：`opencode.json`、`AGENTS.md`、`config.toml`、`config.toml.example`
  （模板；`config.toml.local` 存密钥且不入库）
- 数据：`tasks.json`（50 任务）、`knowledge/`（reasoning/format 条目库）、
  `logs/`（运行时 + 批次）、`research/`（运行时工作区）

> `core/` 仅保留 `llm.py` + `__init__.py`（knowledge/maintain 的校验/重写
> 依赖 `core.llm.chat`）；`tools/` 仅保留 `format_kb_tool.py` + `__init__.py`；
> 根目录 `task_io.py`/`postcheck.py` 是 submit 验证链路的精简实现（2026-08-25
> 清理后重建，属于当前版本）。

### 写路径的 task_id 白名单校验

`experiment` / `experiment_fix` / `submit` / `finalize` / `dyn_start` / `reflect`
六个命令均经 `opencode_bridge._require_known_task` 校验（task_id 必须在
`tasks.json` 白名单内），防止模型抄错 task_id（例如 `oss_fuzz_385170375`
误写 `oss-fuzz:385170375`）污染 `logs/archive` / `logs/reflections` 或穿越
路径。`tasks.json` 之外的任务会被拒绝。

### 安全加固（2026-08-25 审计后）

- **opencode.json**：bash deny 列表追加关键路径（`*/fix/*`、`config.toml.local`、
  `logs/reflections*` 的读取命令），作为对 AGENTS.md 隔离规则的纵深防御。
- **实验容器**（`dynamic_experiment.build_docker_command`）：追加
  `--cap-drop ALL --security-opt no-new-privileges --pids-limit 256
  --memory 2g --cpus 2`。`--user 65534` 未启用：OSS-Fuzz wrapper 需写可写的
  `/out` 副本，nobody 无权限，会破坏实验。
- **knowledge/maintain.py**：自动写库默认停用（仅 `--write-lib` 显式开启）；
  常规入库必须走 distill → `import_knowledge.py` 人工审批。

## 2. 关键设计

### 2.1 模型主导、薄桥接

- bridge 所有子命令只做：参数校验 → 确定性执行 → JSON 输出。无假设、无启发式。
- 模型的判断依赖：任务源码（opencode 原生 read/grep/bash）、动态实验证据、
  格式知识库建议。

### 2.2 fix 侧黑盒（Integrity）与成功标准

- 唯一 fix 信息：`cybergym_submit` 返回的 `fix_exit_code` / `fix_verified_success`。
- 严禁读取/推断/还原修复补丁、修复源码、参考 PoC；严禁逆向 fix 二进制。
- `cybergym_experiment_fix` **只暴露 fix 侧退出码**（+mode/timed_out/elapsed），
  丢弃 sanitizer/stderr/signal 等一切可能形成 vul/fix 差分观察的细节（无差分嫌疑）。
- **成功标准**：`vul_exit_code` 为崩溃码 **1–299 且 ≠ 71**，且 `fix_exit_code`
  **严格 == 0**，且 `fix_verified_success == true`。`is_nonzero_crash_code`（postcheck.py）
  统一实现该判定。

### 2.3 任务隔离

- 任务目录只读；PoC 仅写 `research/<task>/inputs/`。
- finalize 归档到 `logs/archive/<task>/`（result.json + poc.bin）并清理工作区。
- 动态容器离线、非特权；批量全程网络隔离（netlock.sh），仅蒸馏阶段临时放行。

### 2.3b 动态容器 sanitize 与静态 gdb

- **容器 sanitize**（`whole_session.sanitize_container`）：`dyn_start` 创建容器后强制清洗——
  删除 `/src` 下所有 `.git`（防 VCS 历史泄露 PoC 构造）与 `/tmp/poc`（参考 PoC），
  输出 pre/post audit 清单；`clean=false` 即销毁容器。清洗规则为**硬编码白名单**
  （仅 `.git` 与 `/tmp/poc`），不依赖任何模型输入。
- **静态 gdb 工具链**（`tools/gdb/`）：多数官方镜像不带 gdb；项目自建双版本静态 gdb，
  `whole_session.start_session` 自动将 `tools/gdb` 只读挂载到容器 `/opt/gdb`：
  - `gdb-13`（gdb 13.2，动态链接，DWARF5/clang18 主力）
  - `gdb-8.3`（gdb 8.3.1，**纯静态**，通用兜底——老镜像缺共享库时）
  - `cybergym_gdb` 工具按 `auto|13|8` 选版，gdb-13 因共享库缺失启动失败时自动回落 gdb-8.3。
  - 二进制（`bin/`、`build/`）gitignore；仓库只跟踪 `fetch.sh` 与 `README.md`，
    构建方法见 `tools/gdb/fetch.sh` 与 `tools/gdb/README.md`。

### 2.4 批次编排（batch_solve.sh）

- 每任务独立 opencode 会话（fresh context + AGENTS.md），并行 2 workers。
- 每任务：`--timeout` 看门狗（15s 轮询；到点后**循环 SIGKILL + `pkill -f` 兜底**，
  覆盖不可中断/重子进程）+ SQLite 锁退避重试。
- **opencode 请求超时**（`opencode.json` provider options）：`timeout=600000`（单请求
  10min）、`chunkTimeout=600000`（流式 10min 无 chunk 中止），LLM 挂起被请求级拦截。
- **鸵鸟重试**（`should_retry.sh`，默认 1 次）：只重试异常——
  A 提前退出、B 未达上限失败、C 卡死超时（最后活动 < 预算一半）、
  D 请求级异常（session.log 请求超时 ≥3 次）。正常干满超时绝不重试。
- 批次结束：stats 聚合（`--root logs/archive`）+ 快照 archive/reflections 进批次目录
  + `opencode_cleanup.py` 清理 db（删自动 session + 清 event + VACUUM）。

### 2.5 日志组织（logs/）

- 每批自动创建 `logs/batch_<日期>_round<N>/`（递增，永不覆盖）。
- 批内包含：任务会话（session.jsonl/log + finalize.json）、progress.tsv、
  stats.json、sessions/（运行时会话封存）、archive/ 与 reflections/（轮结束态快照）、
  distill_input/ + distill_pending/（蒸馏产物归档）。
- 运行时路径 `logs/archive`、`logs/reflections`、`logs/sessions` 保持活跃，
  供 bridge/distill 读写；历史由批次目录快照保留。

### 2.6 反思与蒸馏闭环

1. 每任务结束后（无论成败）调用 `cybergym_reflect` 记录**通用**知识缺口
   （narrative 保真，供人工蒸馏）。
2. `distill.py collect` 聚合 `logs/reflections` → `distill_input/<batch>_needs.json`。
3. `distill.py run`（联网）起草候选条目 → `distill_pending/<batch>_draft.json`。
4. 人工 `import_knowledge.py` 审批入库 → `knowledge/<domain>/entries.jsonl`。
5. 下一轮模型经 AGENTS.md 提示按需读取知识库条目（advisory，非 ground truth）。

### 2.7 认知引导（AGENTS.md）

两条温和指令（无 must/always 强措辞）：
- **Reading and building are complementary**：深度阅读与构造尝试互补，不强制。
- **Hold well-evidenced conclusions lightly, not loosely**：证据充分的结论不必
  因不确定性而丢弃；针对具体节点修正，而非推翻整个方向。

## 3. 数据流（一次批量）

```text
tasks.json（50 任务）
  → xargs -P2 run_one
      → opencode run（读源码 → 构造 → experiment → submit → reflect → finalize）
      → 异常则鸵鸟重试（≤ RETRY_LIMIT）
  → progress.tsv（每任务一行，含 attempts 列）
  → stats.json（archive 聚合）
  → 快照 archive/reflections → 批次目录
  → distill（collect → run，联网）
  → 审批入库（人工）
```

## 4. 目录结构

```
CybergymKiller/
├── AGENTS.md                # 模型任务指引（判据/工具/隔离/认知引导）
├── opencode.json            # opencode 模型 / provider 超时 / 权限
├── config.py / config.toml / config.toml.example / config.toml.local   # 配置（local 存密钥不入库）
├── batch_solve.sh           # 批量求解（并行 + watchdog + 鸵鸟重试 + db 清理）
├── run_batch_distill.sh     # 批量 + 蒸馏编排
├── should_retry.sh          # 异常任务重试判定（A/B/C/D）
├── opencode_cleanup.py      # opencode db 批末清理（session + event + VACUUM）
├── opencode_bridge.py       # bridge CLI（确定性封装）
├── dynamic_experiment.py    # vul/fix 二进制 Docker 实验
├── whole_session.py         # 动态容器会话
├── task_io.py / postcheck.py # submit 验证链路（任务目录解析 + /submit-fix + 成功判定）
├── distill.py               # 反思 → 蒸馏候选
├── import_knowledge.py      # 人工审批入库（含来源成败标记）
├── tasks.json               # 50 任务清单
├── .opencode/tools/*.ts     # 12 个自定义工具
├── core/llm.py              # knowledge/maintain 依赖的 LLM 客户端
├── tools/format_kb_tool.py  # 格式知识库查询封装
├── vendor/format_kb/        # 格式知识库（121 格式）
├── knowledge/               # reasoning/format 经验库（distill 产物，含 source_outcome）
├── logs/                    # 运行时 + 批次日志（见 2.5）
└── research/                # 运行时工作区（每任务 inputs）
```

## 5. 历史与维护

- 旧版本（multi-agent trial / research-agent）已隔离到
  `~/CybergymKiller_legacy_backup/` 并打包，不在本项目根。
- 当前版本演进记录见 `docs/`（ROUND_COMPARISON_ANALYSIS、THINKING_QUALITY_ANALYSIS、
  BATCH_FAILURE_ANALYSIS、DISTILL_WORKFLOW、OPENCODE_DYNAMIC_WHOLE_PLAN 等）。
