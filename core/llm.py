"""
LLM 调用模块 — 纯 HTTP 请求，零外部依赖
"""

import json, time, urllib.request
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError, URLError
from typing import Callable
from config import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL, LLM_TIMEOUT, ROLE_MODELS


class LLMError(RuntimeError):
    """Structured LLM failure so callers can classify without string parsing."""

    def __init__(self, error_type: str, message: str, *, role: str = "", http_status: int | None = None):
        super().__init__(message)
        self.error_type = error_type
        self.role = role
        self.http_status = http_status


def _classify_exception(exc: BaseException, http_status: int | None = None) -> str:
    """Classify the final failure into a stable error_type for audit/triage."""
    if http_status is not None:
        if http_status == 429:
            return "rate_limited"
        if 500 <= http_status < 600:
            return "http_5xx"
        return "http_error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, (ConnectionError, URLError)):
        return "transport"
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return "timeout"
    if "connect" in name or "remote" in name or "badstatus" in name:
        return "transport"
    return "unknown"


# Tie-break priority: transport is the most actionable signal for flaky servers.
_DOMINANT_PRIORITY = {
    "transport": 5,
    "rate_limited": 4,
    "http_5xx": 3,
    "timeout": 2,
    "http_error": 1,
    "config": 0,
    "unknown": 0,
}


def _dominant_error_type(counts: dict[str, int], fallback_exc: BaseException | None, fallback_http: int | None) -> str:
    """Pick the most frequent error type across retries (not just the last one)."""
    if not counts:
        return _classify_exception(fallback_exc, fallback_http)
    return max(counts, key=lambda key: (counts[key], _DOMINANT_PRIORITY.get(key, 0)))


def _model_family(model: str) -> str:
    name = str(model or "").lower()
    if "kimi" in name:
        return "kimi"
    if "deepseek" in name:
        return "deepseek"
    if "glm" in name:
        return "glm"
    return "default"


def _build_body(model: str, messages: list[dict], temperature: float, max_tokens: int) -> dict:
    body = {"model": model, "messages": messages, "max_tokens": max_tokens}
    family = _model_family(model)
    if family == "kimi":
        return body
    body["temperature"] = temperature
    if family == "deepseek":
        body["reasoning_effort"] = "medium"
    return body


def chat(messages: list[dict], temperature: float = 0.2, max_tokens: int = 4096, *, event_fn: Callable[[dict], None] | None = None, role: str = "", model: str | None = None) -> tuple[str, dict]:
    """发送消息到 LLM，返回 (文本, usage统计)"""
    if not (LLM_API_KEY or "").strip():
        raise LLMError(
            "config",
            "LLM_API_KEY is not configured (config.toml api_key is empty and env LLM_API_KEY unset); refusing to call the model with a placeholder credential",
            role=role,
        )
    url = LLM_BASE_URL.rstrip("/") + "/chat/completions"
    effective_model = model or ROLE_MODELS.get(role, LLM_MODEL)
    body = _build_body(effective_model, messages, temperature, max_tokens)
    data = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    }

    last_err = ""
    last_error_type = ""
    last_exc: BaseException | None = None
    last_http_status: int | None = None
    error_counts: dict[str, int] = {}
    for retry in range(4):
        started = time.time()
        if event_fn:
            event_fn({"event": "request_started", "role": role, "retry": retry, "max_tokens": max_tokens, "payload_bytes": len(data)})
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
                response_body = resp.read()
                result = json.loads(response_body.decode("utf-8"))
                msg = result.get("choices", [{}])[0].get("message", {})
                usage = dict(result.get("usage", {}))
                text = msg.get("content") or ""
                if not text and msg.get("reasoning_content"):
                    # Reasoning models may return only internal reasoning when the
                    # output budget is exhausted. Reasoning text is not the final
                    # answer; mark truncation and let the caller retry/parse.
                    usage["truncated"] = True
                    usage["reasoning_only"] = True
                if event_fn:
                    event_fn({"event": "response_received", "role": role, "retry": retry, "elapsed_seconds": round(time.time() - started, 2), "response_bytes": len(response_body), "truncated": bool(usage.get("truncated"))})
                return text, usage
        except HTTPError as e:
            last_exc = e
            last_http_status = e.code
            try:
                response_detail = e.read(1000).decode("utf-8", errors="replace")
            except Exception:
                response_detail = ""
            last_err = f"{e}; response={response_detail[:500]}"
            last_error_type = "http_429" if e.code == 429 else "http_error"
            attempt_type = _classify_exception(e, e.code)
            error_counts[attempt_type] = error_counts.get(attempt_type, 0) + 1
            retry_after = 0
            if e.code == 429:
                header = e.headers.get("Retry-After") if e.headers else None
                try:
                    retry_after = max(0, int(header)) if header else 0
                except ValueError:
                    try:
                        retry_after = max(0, int(parsedate_to_datetime(header).timestamp() - time.time())) if header else 0
                    except Exception:
                        retry_after = 0
            if event_fn:
                event_fn({"event": "request_error", "role": role, "retry": retry, "elapsed_seconds": round(time.time() - started, 2), "error_type": last_error_type, "classified": attempt_type, "http_status": e.code, "retry_after_seconds": retry_after, "error": last_err})
            if retry < 3:
                if e.code == 429:
                    # Rate limits (per-minute token windows) need time to reset;
                    # back off much longer than ordinary HTTP errors.
                    delay = min(180, retry_after or (30 * (2 ** retry)))
                else:
                    delay = min(120, retry_after or (5 * (2 ** retry)))
                if event_fn:
                    event_fn({"event": "request_retry", "role": role, "retry": retry + 1, "delay_seconds": delay, "reason": last_error_type})
                time.sleep(delay)
        except Exception as e:
            last_exc = e
            last_err = str(e)[:200]
            last_error_type = type(e).__name__
            attempt_type = _classify_exception(e)
            error_counts[attempt_type] = error_counts.get(attempt_type, 0) + 1
            if event_fn:
                event_fn({"event": "request_error", "role": role, "retry": retry, "elapsed_seconds": round(time.time() - started, 2), "error_type": last_error_type, "classified": attempt_type, "error": last_err})
            if retry < 3:
                # Transport failures (RemoteDisconnected / connection resets) are
                # often transient; back off longer than ordinary errors.
                delay = min(120, 15 * (2 ** retry)) if attempt_type == "transport" else min(60, 5 * (2 ** retry))
                if event_fn:
                    event_fn({"event": "request_retry", "role": role, "retry": retry + 1, "delay_seconds": delay, "reason": last_error_type})
                time.sleep(delay)
    dominant = _dominant_error_type(error_counts, last_exc, last_http_status)
    raise LLMError(
        dominant,
        f"LLM call failed after 4 retries: {last_error_type}: {last_err}",
        role=role,
        http_status=last_http_status,
    )
