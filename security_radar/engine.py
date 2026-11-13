"""Collect, merge, score and publish security advisories as static JSON."""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .model import enrich, merge, utcnow
from .sources import SOURCES

LOG = logging.getLogger("security_radar")


def read_json(path: Path, fallback):
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


def coalesce(records: list[dict], existing: list[dict], now: str) -> dict[str, dict]:
    by_id: dict[str, dict] = {}
    aliases: dict[str, str] = {}

    def insert(row: dict):
        keys = [row["id"]] + row.get("aliases", [])
        target = next((aliases[key] for key in keys if key in aliases), row["id"])
        previous = by_id.get(target, {"id": target, "aliases": [target]})
        updated = merge(previous, row, now)
        by_id[target] = updated
        for key in updated["aliases"]:
            aliases[key] = target
        # If two older rows were already stored separately, join them.
        for key in keys:
            duplicate = by_id.get(key)
            if key != target and duplicate is not None:
                by_id[target] = merge(by_id.pop(key), by_id[target], now)
                for name in by_id[target]["aliases"]:
                    aliases[name] = target

    for record in existing:
        insert(record)
    for record in records:
        insert(record)
    return by_id


def process(*, now: datetime, previous: list[dict], fetched: list[dict],
            watchlist: list[str], retention_days: int = 180,
            max_entries: int = 2500,
            focus_topics: list[str] | None = None) -> tuple[list[dict], list[dict]]:
    timestamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    earlier = {alias for row in previous for alias in [row["id"]] + row.get("aliases", [])}
    merged = coalesce(fetched, previous, timestamp)
    cutoff = (now - timedelta(days=retention_days)).date().isoformat()
    recent = []
    for row in merged.values():
        # Keep existing advisories when recently modified, even if first disclosed years ago.
        if max(row.get("modified", ""), row.get("published", ""))[:10] < cutoff:
            continue
        recent.append(enrich(row, watchlist, focus_topics=focus_topics))
    levels = {"investigate": 0, "review": 1, "information": 2}
    recent.sort(key=lambda row: row.get("modified", ""), reverse=True)
    recent.sort(key=lambda row: (-row.get("attention_score", 0), levels[row["priority"]]))
    recent = recent[:max_entries]
    fresh = [row for row in recent
             if row["priority"] != "information"
             and not any(alias in earlier for alias in row.get("aliases", [row["id"]]))]
    fresh.sort(key=lambda row: (levels[row["priority"]], row.get("modified", "")))
    return recent, fresh[:20]


def run(config_path: Path, data_dir: Path) -> int:
    config = read_json(config_path, {})
    watchlist = config.get("watchlist", [])
    if not isinstance(watchlist, list) or not all(isinstance(w, str) for w in watchlist):
        raise ValueError("config.watchlist must be an array of strings")
    focus_topics = config.get("focus_topics", [])
    now = datetime.now(timezone.utc)
    now_string = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    old_rows = read_json(data_dir / "advisories.json", [])
    status = read_json(data_dir / "status.json", {})
    old_sources = status.get("sources", {})
    new_sources = dict(old_sources)
    fetched: list[dict] = []
    success = 0
    errors = []
    for name, collector in SOURCES.items():
        if not config.get("collectors", {}).get(name, True):
            continue
        previous_success = old_sources.get(name, {}).get("last_success")
        lookback_days = 3
        if previous_success:
            try:
                last = datetime.fromisoformat(previous_success.replace("Z", "+00:00"))
                lookback_days = min(110, max(3, (now - last).days + 2))
            except ValueError:
                pass
        LOG.info("Collecting %s (lookback %d days)", name, lookback_days)
        try:
            records = collector(now, days=lookback_days)
            fetched.extend(records)
            new_sources[name] = {
                "state": "ok", "last_success": now_string, "count": len(records), "error": ""
            }
            LOG.info("%s: %d advisories", name, len(records))
            success += 1
        except Exception as exc:
            # Isolate upstream failures; never report this as an empty successful feed.
            message = f"{type(exc).__name__}: {exc}"
            LOG.warning("%s failed: %s", name, message)
            errors.append(name)
            new_sources[name] = {
                **old_sources.get(name, {}),
                "state": "error", "error": message[:350],
                "last_attempt": now_string
            }
    if not success:
        LOG.error("All enabled sources failed (or none were enabled). Keeping previous data.")
        return 1

    records, fresh = process(now=now, previous=old_rows, fetched=fetched,
                             watchlist=watchlist, focus_topics=focus_topics,
                             retention_days=int(config.get("retention_days", 180)),
                             max_entries=int(config.get("max_entries", 2500)))
    # On initial run, populate history without posting months of backlog.
    is_initial = not status.get("last_run")
    alerts = [] if is_initial else fresh
    write_json(data_dir / "advisories.json", records)
    write_json(data_dir / "alerts.json", {
        "generated_at": now_string, "initial_baseline": is_initial,
        "alerts": alerts,
        "note": "Watchlist match is not verified local exposure."
    })
    write_json(data_dir / "status.json", {
        "last_run": now_string, "last_successful_run": now_string,
        "partial": bool(errors), "source_errors": errors,
        "sources": new_sources, "stored_records": len(records),
        "new_relevant_alerts": len(alerts),
        "message": "Source outages are displayed and do not erase older records."
    })
    LOG.info("Stored %d records and %d new relevant alerts; errors: %s",
             len(records), len(alerts), errors)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Security Radar data")
    parser.add_argument("--config", type=Path, default=Path("config/monitor.json"))
    parser.add_argument("--data-dir", type=Path, default=Path("docs/data"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    return run(args.config, args.data_dir)
