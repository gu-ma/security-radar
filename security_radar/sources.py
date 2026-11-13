"""First-party collectors for CISA KEV, GitHub Advisories and NVD CVE API."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from .http import SourceError, get_json
from .model import cvss_to_severity, make_advisory

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cutoff_date(now: datetime, days: int) -> str:
    return (now - timedelta(days=days)).date().isoformat()


def parse_kev(payload: dict, *, since: str) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise SourceError("Unexpected CISA KEV schema")
    result = []
    for item in payload["vulnerabilities"]:
        if item.get("dateAdded", "") < since or not item.get("cveID"):
            continue
        cve = item["cveID"]
        result.append(make_advisory(
            identifier=cve,
            title=item.get("vulnerabilityName") or cve,
            summary=item.get("shortDescription", ""),
            exploited=True,
            affected=[part for part in (item.get("vendorProject"), item.get("product")) if part],
            source="CISA KEV",
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            published=item.get("dateAdded", ""),
            modified=item.get("dateAdded", "")))
    return result


def parse_ghsa(payload: list) -> list[dict]:
    if not isinstance(payload, list):
        raise SourceError("Unexpected GitHub advisory schema")
    output = []
    for item in payload:
        if not isinstance(item, dict) or not item.get("ghsa_id"):
            continue
        # GHSA is an independent authoritative identifier when no CVE is assigned.
        ident = item.get("cve_id") or item["ghsa_id"]
        packages, ecosystems = [], []
        for entry in item.get("vulnerabilities") or []:
            package = (entry or {}).get("package") or {}
            if package.get("name"):
                packages.append(package["name"])
            if package.get("ecosystem"):
                ecosystems.append(package["ecosystem"])
        score = (item.get("cvss") or {}).get("score")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        output.append(make_advisory(
            identifier=ident,
            aliases=[item["ghsa_id"]],
            title=item.get("summary") or ident,
            summary=item.get("description") or "",
            severity=item.get("severity", "unknown"),
            cvss=score, affected=packages, ecosystems=ecosystems,
            source="GitHub Advisory Database",
            url=item.get("html_url") or ("https://github.com/advisories/" + item["ghsa_id"]),
            published=item.get("published_at", ""),
            modified=item.get("updated_at", "")))
    return output


def _cpe_products(configurations: list) -> list[str]:
    names = set()

    def walk(obj):
        if isinstance(obj, dict):
            crit = obj.get("criteria")
            if isinstance(crit, str) and crit.startswith("cpe:2.3:"):
                fields = crit.split(":")
                if len(fields) > 4:
                    names.add(fields[3].replace("_", " ") + " " + fields[4].replace("_", " "))
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(configurations)
    return sorted(names)[:60]


def parse_nvd(payload: dict) -> list[dict]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise SourceError("Unexpected NVD schema")
    result = []
    for row in payload["vulnerabilities"]:
        cve = row.get("cve") or {}
        ident = cve.get("id")
        if not ident or cve.get("vulnStatus") in {"Rejected"}:
            continue
        descriptions = cve.get("descriptions") or []
        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics") or {}
        score, severity = None, "unknown"
        for name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(name):
                entries = metrics[name]
                preferred = next((x for x in entries if x.get("type") == "Primary"), entries[0])
                block = preferred.get("cvssData") or {}
                try:
                    score = float(block["baseScore"])
                except (TypeError, ValueError, KeyError):
                    score = None
                severity = (block.get("baseSeverity") or preferred.get("baseSeverity") or
                            cvss_to_severity(score)).lower()
                break
        result.append(make_advisory(
            identifier=ident, title=(description[:150] or ident), summary=description,
            severity=severity, cvss=score,
            affected=_cpe_products(cve.get("configurations", [])),
            source="NIST NVD", url="https://nvd.nist.gov/vuln/detail/" + ident,
            published=cve.get("published", ""), modified=cve.get("lastModified", "")))
    return result


def collect_kev(now: datetime, *, days: int = 90) -> list[dict]:
    return parse_kev(get_json(KEV_URL), since=cutoff_date(now, days))


def collect_ghsa(now: datetime, *, days: int = 7) -> list[dict]:
    since = cutoff_date(now, days)
    found = []
    # The 'modified' qualifier includes published and updated advisories.
    for page in range(1, 6):
        params = urlencode({"type": "reviewed", "modified": ">=" + since,
                            "per_page": 100, "page": page, "sort": "updated", "direction": "desc"})
        batch = get_json(GHSA_URL + "?" + params, api="github")
        found.extend(parse_ghsa(batch))
        if len(batch) < 100:
            break
    else:
        raise SourceError("GitHub results exceeded five pages; refusing incomplete snapshot")
    return found


def collect_nvd(now: datetime, *, days: int = 7) -> list[dict]:
    # NVD accepts extended ISO-8601 timestamps for last-modified windows.
    # NVD prohibits windows longer than 120 days.
    start = (now - timedelta(days=min(days, 110))).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    index, output = 0, []
    while True:
        params = urlencode({"lastModStartDate": start, "lastModEndDate": end,
                            "resultsPerPage": 1000, "startIndex": index})
        payload = get_json(NVD_URL + "?" + params, api="nvd")
        output.extend(parse_nvd(payload))
        total = payload.get("totalResults")
        if not isinstance(total, int):
            raise SourceError("NVD did not return totalResults")
        index += len(payload["vulnerabilities"])
        if index >= total:
            break
        if not payload["vulnerabilities"]:
            raise SourceError("NVD pagination stopped unexpectedly")
        # Without an API key NVD limits request frequency.
        time.sleep(6)
        if index >= 10000:
            raise SourceError("NVD returned >10000 records; increase pagination capacity")
    return output

SOURCES = {"cisa_kev": collect_kev, "github_advisories": collect_ghsa, "nist_nvd": collect_nvd}
