"""Optional Teams Workflows notifier. The core monitor never requires Teams."""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

from .engine import read_json


def message(alerts: list[dict], dashboard_url: str) -> str:
    lines = [f"Security Radar: {len(alerts)} new advisory(s) for review",
             "Potential relevance only; local exposure has NOT been verified.", ""]
    for a in alerts[:8]:
        link = a.get("sources", [{}])[0].get("url", "") if a.get("sources") else ""
        lines.append(f"[{a['priority'].upper()}] {a['id']}: {a['title'][:120]}")
        lines.append(link)
    if len(alerts) > 8:
        lines.append(f"...plus {len(alerts) - 8} more.")
    if dashboard_url:
        lines.append("Dashboard: " + dashboard_url)
    return "\n".join(lines)


def send(webhook_url: str, text: str) -> None:
    if not webhook_url.startswith("https://"):
        raise ValueError("Teams webhook must use HTTPS")
    body = json.dumps({"text": text}).encode("utf-8")
    request = Request(webhook_url, data=body,
                      headers={"Content-Type": "application/json",
                               "User-Agent": "SecurityRadar/0.1"},
                      method="POST")
    with urlopen(request, timeout=20) as response:
        if response.status not in (200, 201, 202):
            raise RuntimeError(f"Teams webhook returned HTTP {response.status}")


def main() -> int:
    webhook = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not webhook:
        raise SystemExit("TEAMS_WEBHOOK_URL is missing; Teams notifications are disabled.")
    data = read_json(Path("docs/data/alerts.json"), {"alerts": []})
    alerts = data.get("alerts", [])
    if not alerts:
        print("No new alerts to notify.")
        return 0
    url = os.environ.get("RADAR_DASHBOARD_URL", "")
    send(webhook, message(alerts, url))
    print(f"Sent one summary of {len(alerts)} alerts to the Teams Workflow.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
