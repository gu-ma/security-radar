"""Offline-testable Teams Workflows notification payloads.

Integration contract: a university-managed Workflow using the HTTP webhook
trigger accepts {"text":"..."} and explicitly maps its text property to the
Teams "Post a message in a chat or channel" action.

A successful HTTP response means the trigger accepted the request, not proof
that the message was delivered in Teams. Teams is disabled by default.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from .engine import read_json

MAX_TEXT = 9000
MAX_ALERTS = 6
PRIORITY_ORDER = {"investigate": 0, "review": 1, "information": 2}
CATEGORY_LABELS = {
    "applications": "Applications",
    "dependencies": "Libraries & dependencies",
    "containers": "Containers & registries",
    "infrastructure": "Servers & infrastructure",
    "cloud-identity": "Cloud & identity",
    "ai-ml": "AI & ML tooling",
    "unclassified": "Unclassified",
}


def valid_public_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username


def dashboard_link(base: str, advisory: dict) -> str:
    if not valid_public_url(base):
        return ""
    params = {"q": advisory["id"]}
    return base.rstrip("/") + "/?" + urlencode(params) + "#findings"


def select_alerts(alerts: list[dict], *, categories: list[str] | None = None,
                  max_alerts: int = MAX_ALERTS, min_severity: str = "high") -> list[dict]:
    """No alerts solely because they are critical: watchlist relevance required."""
    severities = {
        "low": {"low", "medium", "high", "critical"},
        "medium": {"medium", "high", "critical"},
        "high": {"high", "critical"},
        "critical": {"critical"},
    }
    allowed = severities.get(min_severity, severities["high"])
    chosen = [
        row for row in alerts
        if row.get("matched_topics")
        and (row.get("exploited") or row.get("severity") in allowed)
        and (not categories or set(row.get("categories", [])) & set(categories))
    ]
    chosen.sort(key=lambda row: (
        PRIORITY_ORDER.get(row.get("priority", "information"), 2),
        -(row.get("attention_score") or 0),
        str(row.get("id", "")),
    ))
    return chosen[:max(0, max_alerts)]


def render_text(alerts: list[dict], dashboard_url: str,
                *, heading: str = "Security Radar | New advisories") -> str:
    if not alerts:
        return ""
    lines = [heading, "",
             "Public-source investigation leads. Local exposure has NOT been assessed.", ""]
    for row in alerts[:MAX_ALERTS]:
        cats = " / ".join(CATEGORY_LABELS.get(x, x) for x in row.get("categories", []))
        severity = row.get("severity", "unknown").upper()
        score = row.get("cvss")
        score_label = (f"CVSS {score:g}" if isinstance(score, (int, float))
                       else "CVSS not scored")
        lines.append(f"[{severity} | {score_label}] {row['id']} | {cats or 'Unclassified'}")
        lines.append(str(row.get("title") or "Untitled advisory")[:170])
        summary = str(row.get("why_it_matters") or row.get("summary") or
                      "The source did not provide a summary.")
        lines.append("Why it matters: " + summary[:280])
        lines.append("Next step: " + str(row.get("suggested_next_step") or
                                            "Review the original advisory.")[:230])
        sources = row.get("sources") or []
        url = next((s.get("url", "") for s in sources
                    if valid_public_url(s.get("url", ""))), "")
        if url:
            lines.append("Source: " + url)
        link = dashboard_link(dashboard_url, row)
        if link:
            lines.append("Details: " + link)
        lines.append("")
    message = "\n".join(lines)
    if len(message) > MAX_TEXT:
        raise ValueError("Notification exceeds maximum size; reduce alert count")
    return message


def workflow_payload(alerts: list[dict], dashboard_url: str) -> dict:
    """Stable, serializable JSON contract mapped to triggerBody()?['text']."""
    return {"text": render_text(alerts, dashboard_url)}


def validate_payload(payload: dict) -> None:
    if not isinstance(payload, dict) or set(payload) != {"text"}:
        raise ValueError("Expected a single text property")
    value = payload["text"]
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
        raise ValueError("The text field must be non-empty and <= MAX_TEXT")


def send(webhook_url: str, payload: dict, *, transport=None) -> int:
    """Send only to an explicitly configured HTTPS trigger URL."""
    if not valid_public_url(webhook_url):
        raise ValueError("An HTTPS Teams Workflow endpoint is required")
    validate_payload(payload)
    request = Request(webhook_url, data=json.dumps(payload).encode("utf-8"),
                      headers={"Content-Type": "application/json",
                               "User-Agent": "SecurityRadar/0.2"},
                      method="POST")
    opener = transport or urlopen
    with opener(request, timeout=20) as response:
        code = response.status
    if code not in (200, 201, 202):
        raise RuntimeError(f"Workflow rejected notification (HTTP {code})")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description="Teams Workflow notification adapter")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate payload locally; NEVER perform an HTTP request")
    parser.add_argument("--preview-file", type=Path,
                        help="Save JSON preview to an offline file")
    parser.add_argument("--alerts-file", type=Path, default=Path("docs/data/alerts.json"))
    parser.add_argument("--category", action="append", default=[],
                        help="Limit to technology category slug; repeat to select multiple")
    args = parser.parse_args()
    data = read_json(args.alerts_file, {"alerts": []})
    alerts = select_alerts(data.get("alerts") or [],
                           categories=args.category or None)
    if not alerts:
        print("No qualifying new advisories. Nothing to send.")
        return 0
    base = os.environ.get("RADAR_DASHBOARD_URL", "https://apps.massol.me/security-radar/")
    payload = workflow_payload(alerts, base)
    validate_payload(payload)
    if args.preview_file:
        args.preview_file.parent.mkdir(parents=True, exist_ok=True)
        args.preview_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                                     encoding="utf-8")
    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    webhook = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not webhook:
        raise SystemExit("Missing TEAMS_WEBHOOK_URL. Sender remains disabled.")
    status = send(webhook, payload)
    print(f"Workflow trigger accepted request (HTTP {status}). "
          "Channel delivery must be confirmed by the authorized Teams owner.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
