"""Compact, public, bounded collection health history.

Only append when an actual monitoring collection runs. Do not record code-only
push deployments as collection runs. Never include credentials or response bodies.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone

MAX_RUNS = 40


def github_run_url(environ=None) -> str:
    env = environ if environ is not None else os.environ
    run_id = env.get("GITHUB_RUN_ID", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    if (re.fullmatch(r"[0-9]+", run_id) and
            re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)):
        return f"https://github.com/{repository}/actions/runs/{run_id}"
    return ""


def summarize_sources(sources: dict) -> dict:
    result = {}
    for name, data in sorted(sources.items()):
        if not isinstance(data, dict):
            continue
        result[name] = {
            "state": str(data.get("state") or "unknown"),
            "count": data.get("count") if isinstance(data.get("count"), int) else None,
            "last_success": str(data.get("last_success") or ""),
            "last_attempt": str(data.get("last_attempt") or ""),
            "error_type": str(data.get("error_type") or ""),
            "error": str(data.get("error") or "")[:260],
            "consecutive_failures": data.get("consecutive_failures", 0),
        }
    return result


def record_run(status: dict, *, started_at: str, finished_at: str,
               duration_seconds: float | None = None,
               run_url: str = "") -> dict:
    if status.get("failed"):
        result = "failed"
    elif status.get("partial"):
        result = "degraded"
    else:
        result = "healthy"
    return {
        "started_at": started_at,
        "finished_at": finished_at,
        "result": result,
        "run_url": run_url,
        "stored_records": status.get("stored_records", 0),
        "new_relevant_alerts": status.get("new_relevant_alerts", 0),
        "source_errors": list(status.get("source_errors") or []),
        "duration_seconds": (round(duration_seconds, 2)
                             if duration_seconds is not None else None),
        "sources": summarize_sources(status.get("sources") or {}),
    }


def append_history(history: object, entry: dict, *, limit: int = MAX_RUNS) -> list[dict]:
    """Most recent first, bounded and idempotent for the same workflow run."""
    if not isinstance(history, list):
        history = []
    key = entry.get("run_url") or entry.get("finished_at")
    items = [entry]
    for old in history:
        if not isinstance(old, dict):
            continue
        if (old.get("run_url") or old.get("finished_at")) == key:
            continue
        items.append(old)
    items.sort(key=lambda item: item.get("finished_at", ""), reverse=True)
    return items[:min(max(limit, 1), MAX_RUNS)]
