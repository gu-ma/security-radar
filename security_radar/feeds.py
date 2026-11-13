"""Build public RSS 2.0 and Atom 1.0 feeds from normalized advisory JSON.

No external services, network calls, secrets, markdown-to-HTML rendering, or AI.
Only public, watchlist-matched high/critical or KEV-listed advisories are emitted.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree as ET

BASE_URL = "https://apps.massol.me/security-radar/"
ATOM_NS = "http://www.w3.org/2005/Atom"
MAX_ITEMS = 50
ET.register_namespace("atom", ATOM_NS)

CATEGORY_LABELS = {
    "applications": "Applications",
    "dependencies": "Libraries & dependencies",
    "containers": "Containers & registries",
    "infrastructure": "Servers & infrastructure",
    "cloud-identity": "Cloud & identity",
    "ai-ml": "AI & ML tooling",
    "unclassified": "Unclassified",
}


def _clean(value: object) -> str:
    """Drop characters forbidden by XML 1.0, including untrusted control bytes."""
    output = []
    for ch in str(value or ""):
        n = ord(ch)
        if n in (9, 10, 13) or 0x20 <= n <= 0xD7FF or 0xE000 <= n <= 0xFFFD or 0x10000 <= n <= 0x10FFFF:
            output.append(ch)
    return "".join(output).replace("\u2014", " - ")


def _dt(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _time(row: dict, field: str) -> datetime:
    # Missing publication dates use modified, then first_seen. Never use a
    # publication/update time fabricated from a CVSS score or CISA status.
    candidates = (field, "modified", "published", "first_seen")
    for key in dict.fromkeys(candidates):
        parsed = _dt(row.get(key))
        if parsed is not None:
            return parsed
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _iso(date: datetime) -> str:
    return date.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_https(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        url = urlsplit(value)
        if url.scheme == "https" and url.netloc and url.hostname and not url.username and not url.password:
            return value
    except ValueError:
        pass
    return ""


def original_source(row: dict) -> str:
    for source in row.get("sources", []):
        if isinstance(source, dict):
            url = _safe_https(source.get("url"))
            if url:
                return url
    return ""


def advisory_link(base: str, row: dict) -> str:
    return base.rstrip("/") + "/?q=" + quote(str(row["id"]), safe="") + "#findings"


def _eligible(row: dict) -> bool:
    return bool(row.get("id") and row.get("matched_topics") and (
        row.get("exploited") or row.get("severity") in ("critical", "high")
    ))


def select_entries(records: list[dict], limit: int = MAX_ITEMS) -> list[dict]:
    """Most recently updated high-signal advisories, one item per canonical ID."""
    if not isinstance(records, list):
        raise ValueError("advisory data must be a JSON array")
    if not isinstance(limit, int) or limit < 1 or limit > 200:
        raise ValueError("feed limit must be an integer from 1 to 200")
    eligible = [row for row in records if isinstance(row, dict) and _eligible(row)]
    eligible.sort(key=lambda row: (_time(row, "modified"), str(row["id"])), reverse=True)
    result = []
    seen = set()
    for row in eligible:
        ident = str(row["id"])
        if ident not in seen:
            result.append(row)
            seen.add(ident)
            if len(result) == limit:
                break
    return result


def _description(row: dict) -> str:
    parts = []
    severity = str(row.get("severity") or "unknown").upper()
    cvss = row.get("cvss")
    version = str(row.get("cvss_version") or "").strip()
    score = f" / CVSS {cvss:g}" if isinstance(cvss, (int, float)) else ""
    if score and version:
        score += f" (v{version})"
    parts.append(f"Severity: {severity}{score}")
    description = _clean(row.get("why_it_matters") or row.get("summary"))
    if description:
        parts.append("Summary: " + description[:900])
    action = _clean(row.get("suggested_next_step"))
    if action:
        parts.append("Suggested next step: " + action[:400])
    original = original_source(row)
    if original:
        parts.append("Original advisory: " + original)
    parts.append("Watchlist match only. Local exposure has not been assessed.")
    return "\n\n".join(parts)


def _categories(row: dict) -> list[str]:
    named = [CATEGORY_LABELS.get(c, c) for c in row.get("categories", []) if isinstance(c, str)]
    topics = [tag for tag in row.get("security_topics", []) if isinstance(tag, str)]
    return list(dict.fromkeys(_clean(c) for c in named + topics if c))


def _xml(root: ET.Element) -> bytes:
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def rss_bytes(rows: list[dict], base: str = BASE_URL) -> bytes:
    root = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(root, "channel")
    ET.SubElement(channel, "title").text = "Security Radar | High-signal advisories"
    ET.SubElement(channel, "link").text = base
    ET.SubElement(channel, "description").text = (
        "Public high/critical or KEV-listed advisories matching the Security Radar watchlist. "
        "Not evidence of local exposure."
    )
    ET.SubElement(channel, "language").text = "en"
    ET.SubElement(channel, "ttl").text = "360"
    ET.SubElement(channel, f"{{{ATOM_NS}}}link", {
        "href": base.rstrip("/") + "/rss.xml", "rel": "self", "type": "application/rss+xml"
    })
    last_update = max((_time(row, "modified") for row in rows),
                      default=datetime(1970, 1, 1, tzinfo=timezone.utc))
    ET.SubElement(channel, "lastBuildDate").text = format_datetime(last_update, usegmt=True)
    for row in rows:
        item = ET.SubElement(channel, "item")
        link = advisory_link(base, row)
        ET.SubElement(item, "title").text = _clean(row.get("title") or row["id"])
        ET.SubElement(item, "link").text = link
        ET.SubElement(item, "guid", {"isPermaLink": "true"}).text = link
        ET.SubElement(item, "pubDate").text = format_datetime(_time(row, "published"), usegmt=True)
        ET.SubElement(item, "description").text = _description(row)
        for category in _categories(row):
            ET.SubElement(item, "category").text = category
        source_url = original_source(row)
        if source_url:
            ET.SubElement(item, f"{{{ATOM_NS}}}link", {
                "rel": "related", "href": source_url, "type": "text/html"
            })
    return _xml(root)


def atom_bytes(rows: list[dict], base: str = BASE_URL) -> bytes:
    root = ET.Element(f"{{{ATOM_NS}}}feed")
    def sub(parent: ET.Element, name: str, value: str = "", attrs: dict | None = None):
        element = ET.SubElement(parent, f"{{{ATOM_NS}}}{name}", attrs or {})
        if value:
            element.text = _clean(value)
        return element

    sub(root, "title", "Security Radar | High-signal advisories")
    sub(root, "subtitle", "Selected public advisories. Institutional exposure has not been assessed.")
    sub(root, "id", base.rstrip("/") + "/")
    sub(root, "link", attrs={"rel": "self", "href": base.rstrip("/") + "/atom.xml",
                             "type": "application/atom+xml"})
    sub(root, "link", attrs={"rel": "alternate", "href": base})
    author = sub(root, "author")
    sub(author, "name", "Security Radar")
    last_update = max((_time(row, "modified") for row in rows),
                      default=datetime(1970, 1, 1, tzinfo=timezone.utc))
    sub(root, "updated", _iso(last_update))
    for row in rows:
        entry = sub(root, "entry")
        link = advisory_link(base, row)
        sub(entry, "id", link)
        sub(entry, "title", str(row.get("title") or row["id"]))
        sub(entry, "published", _iso(_time(row, "published")))
        sub(entry, "updated", _iso(_time(row, "modified")))
        sub(entry, "link", attrs={"rel": "alternate", "href": link,
                                  "type": "text/html"})
        source_url = original_source(row)
        if source_url:
            sub(entry, "link", attrs={"rel": "related", "href": source_url,
                                      "type": "text/html"})
        sub(entry, "summary", _description(row), {"type": "text"})
        for category in _categories(row):
            sub(entry, "category", attrs={"term": category})
    return _xml(root)


def render_feeds(records: list[dict], base: str = BASE_URL,
                 limit: int = MAX_ITEMS) -> dict[str, bytes]:
    if not _safe_https(base):
        raise ValueError("Feed base must be a public HTTPS URL")
    entries = select_entries(records, limit=limit)
    return {"rss.xml": rss_bytes(entries, base), "atom.xml": atom_bytes(entries, base)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate public RSS and Atom from advisory JSON")
    parser.add_argument("--input", type=Path, default=Path("docs/data/advisories.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("docs"))
    parser.add_argument("--base-url", default=BASE_URL)
    parser.add_argument("--limit", type=int, default=MAX_ITEMS)
    args = parser.parse_args()
    records = json.loads(args.input.read_text(encoding="utf-8"))
    artifacts = render_feeds(records, base=args.base_url, limit=args.limit)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, contents in artifacts.items():
        path = args.output_dir / name
        if not path.exists() or path.read_bytes() != contents:
            path.write_bytes(contents)
        print(f"{path}: {len(contents)} bytes")
    print(f"Published {len(select_entries(records, args.limit))} high-signal advisories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
