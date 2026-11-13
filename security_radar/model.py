"""Normalized advisory model, merging, and explicit uncertainty labels."""
from __future__ import annotations

import re
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def iso_date(value: str | None) -> str:
    if not value:
        return ""
    value = str(value).strip()
    if len(value) == 10 and re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return value + "T00:00:00Z"
    return value.replace("+00:00", "Z")


def cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def make_advisory(*, identifier: str, title: str, summary: str = "",
                  severity: str = "unknown", cvss: float | None = None,
                  exploited: bool = False, affected: list[str] | None = None,
                  ecosystems: list[str] | None = None, aliases: list[str] | None = None,
                  source: str, url: str, published: str = "", modified: str = "") -> dict:
    severity = severity.lower()
    if severity not in {"critical", "high", "medium", "low", "unknown"}:
        severity = "unknown"
    return {
        "id": identifier, "title": title.strip()[:300],
        "summary": " ".join(summary.split())[:900],
        "severity": severity, "cvss": cvss, "exploited": bool(exploited),
        "affected": sorted(set(affected or []))[:60],
        "ecosystems": sorted(set(ecosystems or [])),
        "aliases": sorted(set([identifier] + (aliases or []))),
        "sources": [{"name": source, "url": url}] if url.startswith("https://") else [],
        "published": iso_date(published), "modified": iso_date(modified or published),
    }


def merge(old: dict, new: dict, now: str) -> dict:
    """Combine observations without discarding stronger existing evidence."""
    out = dict(old)
    out["id"] = old["id"]
    out["aliases"] = sorted(set(old.get("aliases", [old["id"]]) + new.get("aliases", [new["id"]])))
    out["affected"] = sorted(set(old.get("affected", []) + new.get("affected", [])))[:60]
    out["ecosystems"] = sorted(set(old.get("ecosystems", []) + new.get("ecosystems", [])))
    seen = {(s["name"], s["url"]) for s in old.get("sources", [])}
    out["sources"] = list(old.get("sources", []))
    for source in new.get("sources", []):
        key = (source["name"], source["url"])
        if key not in seen:
            out["sources"].append(source)
            seen.add(key)
    out["exploited"] = bool(old.get("exploited") or new.get("exploited"))
    ranks = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    out["severity"] = max((old.get("severity", "unknown"), new.get("severity", "unknown")),
                          key=lambda x: ranks.get(x, 0))
    scores = [v for v in (old.get("cvss"), new.get("cvss")) if isinstance(v, (int, float))]
    out["cvss"] = max(scores) if scores else None
    if len(new.get("summary", "")) > len(old.get("summary", "")):
        out["summary"] = new["summary"]
    if (not old.get("title") or old.get("title") == old["id"]) and new.get("title"):
        out["title"] = new["title"]
    out["published"] = min(filter(None, [old.get("published"), new.get("published")]), default="")
    out["modified"] = max(old.get("modified", ""), new.get("modified", ""))
    out["first_seen"] = old.get("first_seen", now)
    out["last_seen"] = now
    return out


def enrich(advisory: dict, watchlist: list[str]) -> dict:
    """Keywords indicate possible relevance, NEVER confirmed institutional exposure."""
    result = dict(advisory)
    searchable = " ".join([advisory.get("title", ""), advisory.get("summary", ""),
                            " ".join(advisory.get("affected", [])),
                            " ".join(advisory.get("ecosystems", []))])
    matches = [word for word in watchlist
               if re.search(r"(?<![A-Za-z0-9])" + re.escape(word) + r"(?![A-Za-z0-9])",
                            searchable, re.IGNORECASE)]
    result["matched_topics"] = sorted(set(matches), key=str.lower)
    if matches and advisory.get("exploited"):
        priority = "investigate"
    elif matches and (advisory.get("severity") in ("critical", "high")):
        priority = "review"
    else:
        priority = "information"
    result["priority"] = priority
    # Only order leads within the dashboard. A high score is not confirmed exposure.
    severity_points = {"critical": 45, "high": 25, "medium": 5, "low": 0, "unknown": 0}
    result["attention_score"] = (80 if advisory.get("exploited") else 0) + (
        severity_points.get(advisory.get("severity"), 0)
    ) + (30 if matches else 0)
    result["exposure"] = "not assessed"
    return result
