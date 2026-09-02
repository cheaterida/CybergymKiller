"""
统一配置 — 优先级: 环境变量 > config.toml.local > config.toml > 默认值
所有路径以项目根目录 (config.py 所在目录) 为基准
"""

import os
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib

# ========== 项目根目录 ==========
PROJECT_ROOT = Path(os.getenv("AGENT_ROOT", str(Path(__file__).parent))).resolve()


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base (nested dicts merged per-key; scalars replaced)."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_toml(path: Path) -> dict:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


_config = {}
_config_path = Path(os.getenv("AGENT_CONFIG", str(PROJECT_ROOT / "config.toml")))
_config = _load_toml(_config_path)
# Local override file (config.toml.local) wins over config.toml — it holds
# secrets (api_key) that must never be committed; see .gitignore.
_local_config_path = Path(os.getenv("AGENT_LOCAL_CONFIG", str(PROJECT_ROOT / "config.toml.local")))
_local = _load_toml(_local_config_path)
if _local:
    _config = _deep_merge(_config, _local)


def _resolve(path_str: str, relative_to: Path = None) -> Path:
    """解析路径：~ → 展开，相对路径 → 以 relative_to 为基准"""
    p = os.path.expanduser(path_str)
    path = Path(p)
    if not path.is_absolute():
        ref = relative_to or PROJECT_ROOT
        path = ref / path
    return path.resolve()


def _as_bool(value, default: bool = False) -> bool:
    """Parse TOML booleans and environment-string booleans consistently."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


# ========== Agent 配置 ==========
_agent = _config.get("agent", {})
LLM_MODEL = os.getenv("LLM_MODEL", _agent.get("model", "test/glm-5.2")).strip()
LLM_BASE_URL = os.getenv("LLM_BASE_URL", _agent.get("base_url", "http://localhost:8000/v1")).strip()
# api_key 从 config.toml / config.toml.local 读取（local 优先，不入库）。
LLM_API_KEY = os.getenv("LLM_API_KEY", _agent.get("api_key", "")).strip()
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", _agent.get("timeout", 1200)))

# CyberGym 提交服务器 API key（submit-fix 私有路由鉴权）。同样从配置读取。
CYBERGYM_API_KEY = os.getenv("CYBERGYM_API_KEY", _agent.get("cybergym_api_key", "")).strip()

ROLE_MODELS = {
    "plaintiff": os.getenv("MODEL_PLAINTIFF", _agent.get("model_plaintiff", LLM_MODEL)).strip(),
    "plaintiff_lawyer": os.getenv("MODEL_LAWYER", _agent.get("model_lawyer", LLM_MODEL)).strip(),
    "defense": os.getenv("MODEL_DEFENSE", _agent.get("model_defense", LLM_MODEL)).strip(),
    "judge": os.getenv("MODEL_JUDGE", _agent.get("model_judge", LLM_MODEL)).strip(),
    "prosecutor": os.getenv("MODEL_PROSECUTOR", _agent.get("model_prosecutor", LLM_MODEL)).strip(),
    "administration": os.getenv("MODEL_ADMIN", _agent.get("model_admin", LLM_MODEL)).strip(),
}

# Experimental binary-format phases remain frozen until manually validated.
ENABLE_P2_SCHEMA = _as_bool(os.getenv("ENABLE_P2_SCHEMA", _agent.get("enable_p2_schema", False)))
ENABLE_P3_VALIDATOR = _as_bool(os.getenv("ENABLE_P3_VALIDATOR", _agent.get("enable_p3_validator", False)))

# Codex evidence collector (uses cybergym-evidence skill to collect source evidence)
ENABLE_MODEL_EVIDENCE = _as_bool(os.getenv("ENABLE_MODEL_EVIDENCE", _agent.get("enable_model_evidence", False)))
MODEL_EVIDENCE_MODEL = os.getenv(
    "MODEL_EVIDENCE_MODEL",
    _agent.get("model_evidence_model", "kimi-k2.6"),
).strip()

# Per-role completion token budgets. Reasoning models consume most of the
# budget on internal reasoning; keep values configurable and uniform.
PLAINTIFF_REVISION_MAX_TOKENS = int(os.getenv("PLAINTIFF_REVISION_MAX_TOKENS", _agent.get("plaintiff_revision_max_tokens", 24000)))
PLAINTIFF_REVISION_RETRY_MAX_TOKENS = int(os.getenv("PLAINTIFF_REVISION_RETRY_MAX_TOKENS", _agent.get("plaintiff_revision_retry_max_tokens", 32000)))
PLAINTIFF_LAWYER_MAX_TOKENS = int(os.getenv("PLAINTIFF_LAWYER_MAX_TOKENS", _agent.get("plaintiff_lawyer_max_tokens", 24000)))
DEFENSE_MAX_TOKENS = int(os.getenv("DEFENSE_MAX_TOKENS", _agent.get("defense_max_tokens", 24000)))
MODEL_EVIDENCE_MAX_TOKENS = int(os.getenv("MODEL_EVIDENCE_MAX_TOKENS", _agent.get("model_evidence_max_tokens", 24000)))
FRONTEND_MAX_TOKENS = int(os.getenv("FRONTEND_MAX_TOKENS", _agent.get("frontend_max_tokens", 12000)))

# ========== 路径配置 ==========
_paths = _config.get("paths", {})
AGENT_HOME = PROJECT_ROOT
CYBERGYM_HOME = _resolve(os.getenv("CYBERGYM_HOME", _paths.get("cybergym_home", "../cybergym")))
TASKS_DIR = _resolve(os.getenv("TASKS_DIR", _paths.get("tasks_dir", "tasks")), CYBERGYM_HOME)
LOGS_DIR = _resolve(os.getenv("LOGS_DIR", _paths.get("logs_dir", "logs")))

# 工具路径
_tools = _config.get("tools", {})
# 外部格式知识库（format_kb）：已并入项目内 vendor/format_kb（src 在
# vendor/format_kb/src），FORMAT_KB_HOME 指向其根目录；仍可被环境变量/配置覆盖
# 以指向外部副本。
FORMAT_KB_HOME = Path(os.getenv("FORMAT_KB_HOME", _tools.get("format_kb_home", "vendor/format_kb"))).resolve()

# ========== 沙箱配置 ==========
_sandbox = _config.get("sandbox", {})
CMD_TIMEOUT = int(os.getenv("CMD_TIMEOUT", _sandbox.get("command_timeout", 30)))
SUBMIT_TIMEOUT = int(os.getenv("SUBMIT_TIMEOUT", _sandbox.get("submit_timeout", 120)))

# ========== 经验认知库配置 ==========
_knowledge = _config.get("knowledge", {})
KNOWLEDGE_HOME = Path(os.getenv("KNOWLEDGE_HOME", _knowledge.get("home", "knowledge"))).resolve()
KNOWLEDGE_DOMAINS = ("reasoning", "format")
KNOWLEDGE_ENTRY_FIELDS = ("id", "title", "summary", "content", "status")
KNOWLEDGE_STATUSES = ("candidate", "verified", "deprecated")

# ========== 记忆层（上下文压缩）配置 ==========
# 参考 docs/ENGINEERING-UPGRADE-DESIGN-2026-08-18.md §5/§5.6（可调默认，待实测定标）
# 冒烟观察：频率过高（每 6 轮）导致压缩产物无推进且丢失思维链——已调大间隔/阈值
_compaction = _config.get("compaction", {})
COMPACTION_ENABLED = _as_bool(os.getenv("COMPACTION_ENABLED", _compaction.get("enabled", False)))
# 字符估算触发阈值（≈ tokens×4；定标后按 model_context - output - buffer 推导）
COMPACTION_THRESHOLD_CHARS = int(os.getenv("COMPACTION_THRESHOLD_CHARS", _compaction.get("threshold_chars", 300000)))
COMPACTION_MIN_INTERVAL_ROUNDS = int(os.getenv("COMPACTION_MIN_INTERVAL_ROUNDS", _compaction.get("min_interval_rounds", 12)))
COMPACTION_FALLBACK_ROUNDS = int(os.getenv("COMPACTION_FALLBACK_ROUNDS", _compaction.get("fallback_rounds", 20)))
# 保留窗口：最近消息按字符预算保留原文不动（单条工具输出可截断到 16k，
# 若按条数 16 保留会吞噬 200k+ 字符，导致 head 空无一物——按预算而非条数）。
# preserve_messages 仅作最小条数下限，避免窗口只有 1 条。
# 实测：字符预算在消息普遍小时会失控（tail 全吞全部轮次），模型被旧探索转储
# 带偏、压缩后重复探索。改为按轮次保留（preserve_rounds，默认 2 轮）：tail 只
# 保留最近 N 轮（以 assistant 消息为边界），压缩状态已承载历史，tail 仅衔接。
COMPACTION_PRESERVE_MESSAGES = int(os.getenv("COMPACTION_PRESERVE_MESSAGES", _compaction.get("preserve_messages", 16)))
COMPACTION_PRESERVE_ROUNDS = int(os.getenv("COMPACTION_PRESERVE_ROUNDS", _compaction.get("preserve_rounds", 2)))
COMPACTION_PRESERVE_CHARS = int(os.getenv("COMPACTION_PRESERVE_CHARS", _compaction.get("preserve_chars", 12000)))
COMPACTION_STATE_MAX_TOKENS = int(os.getenv("COMPACTION_STATE_MAX_TOKENS", _compaction.get("state_max_tokens", 2048)))
# 任务场景以"初期源码探索"为主：read/lines/function/search 等探索工具结果原文
# 是 transient 转储（结论已进入模型推理/note，源码随时可重读），压缩总结时把
# 这类工具结果裁剪为一行占位，保留 note/exp_run 等模型产出，让 head 聚焦思路。
COMPACTION_CROP_EXPLORE_TOOLS = _as_bool(os.getenv("COMPACTION_CROP_EXPLORE_TOOLS", _compaction.get("crop_explore_tools", True)))
# 压缩用独立模型（默认空=用 LLM_MODEL；实测 deepseek-v4-flash 总结能力不足，可指定更强模型）
COMPACTION_MODEL = os.getenv("COMPACTION_MODEL", _compaction.get("model", "")).strip()
BUILDER_MODEL = os.getenv("BUILDER_MODEL", _agent.get("builder_model", "kimi-k2.6")).strip()
BUILDER_TIMEOUT = int(os.getenv("BUILDER_TIMEOUT", _agent.get("builder_timeout", 1200)))
BUILDER_MAX_TURNS = int(os.getenv("BUILDER_MAX_TURNS", _agent.get("builder_max_turns", 3)))
BUILDER_MAX_TOKENS = int(os.getenv("BUILDER_MAX_TOKENS", _agent.get("builder_max_tokens", 16000)))
BUILDER_SCRIPT_TIMEOUT = int(os.getenv("BUILDER_SCRIPT_TIMEOUT", _agent.get("builder_script_timeout", 120)))
