"""First-party collectors for CISA KEV, GitHub Advisories and NVD CVE API."""
from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from .http import SourceError, SourcePaginationError, SourceSchemaError, get_json, get_github_page
from . import schema
from .model import cvss_to_severity, make_advisory

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cutoff_date(now: datetime, days: int) -> str:
    return (now - timedelta(days=days)).date().isoformat()


def parse_kev(payload: dict, *, since: str) -> list[dict]:
    records = schema.kev(payload)
    result = []
    for item in records:
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
    records = schema.ghsa(payload)
    output = []
    for item in records:
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
        version = ""
        vector = (item.get("cvss") or {}).get("vector_string") or ""
        if isinstance(vector, str) and vector.startswith("CVSS:"):
            version = vector.partition("/")[0].removeprefix("CVSS:")
        output.append(make_advisory(
            identifier=ident,
            aliases=[item["ghsa_id"]],
            title=item.get("summary") or ident,
            summary=item.get("description") or "",
            severity=item.get("severity", "unknown"),
            cvss=score, cvss_version=version, affected=packages, ecosystems=ecosystems,
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
    records = schema.nvd(payload)
    result = []
    for row in records:
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


def collect_ghsa(now: datetime, *, days: int = 3) -> list[dict]:
    """Fetch selected GitHub advisories using API Link-header cursors.

    Global advisories do not support numbered pagination. A repeated cursor,
    repeated result page or excessive pagination fails closed and leaves the
    previous snapshot in place, rather than publishing truncated results.
    """
    since = cutoff_date(now, days)
    found = []
    for kind, severity in (("reviewed", "critical"), ("reviewed", "high"),
                           ("unreviewed", "critical")):
        params = urlencode({"type": kind, "severity": severity,
                            "modified": ">=" + (cutoff_date(now, 1) if kind == "unreviewed" else since),
                            "per_page": 100, "sort": "updated", "direction": "desc"})
        url = GHSA_URL + "?" + params
        visited = set()
        seen_ids = set()
        for _ in range(50):
            if url in visited:
                raise SourcePaginationError(f"GitHub {kind}/{severity}: repeated cursor")
            visited.add(url)
            batch, next_url = get_github_page(url)
            # Catch APIs that ignore cursors and serve the same full page again.
            identifiers = [row.get("ghsa_id") for row in schema.ghsa(batch)]
            if len(set(identifiers)) != len(identifiers):
                raise SourcePaginationError(f"GitHub {kind}/{severity}: duplicate IDs in response page")
            if set(identifiers) & seen_ids:
                raise SourcePaginationError(f"GitHub {kind}/{severity}: repeated result page")
            seen_ids.update(identifiers)
            found.extend(parse_ghsa(batch))
            if not next_url:
                break
            if not batch:
                raise SourcePaginationError(f"GitHub {kind}/{severity}: empty page has next cursor")
            url = next_url
        else:
            raise SourcePaginationError(f"GitHub {kind}/{severity}: exceeded 50 cursor pages")
    return found


def collect_nvd(now: datetime, *, days: int = 3) -> list[dict]:
    """Recent NVD CVEs already scored CRITICAL using CVSS v3.

    Narrowing by severity prevents the API's very large all-severity modification
    backlog from hiding the entire source. Other new CVEs can appear in GHSA/KEV.
    """
    start = (now - timedelta(days=min(days, 110))).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    index, output = 0, []
    while True:
        params = urlencode({"lastModStartDate": start, "lastModEndDate": end,
                            "cvssV3Severity": "CRITICAL",
                            "resultsPerPage": 1000, "startIndex": index})
        payload = get_json(NVD_URL + "?" + params, api="nvd")
        if not isinstance(payload, dict):
            raise SourceSchemaError("Unexpected NVD response")
        output.extend(parse_nvd(payload))
        total = payload.get("totalResults")
        if not isinstance(total, int):
            raise SourceError("NVD did not return totalResults")
        index += len(payload["vulnerabilities"])
        if index >= total:
            break
        if not payload["vulnerabilities"]:
            raise SourceError("NVD pagination stopped unexpectedly")
        time.sleep(6)  # NVD without API key enforces low request frequency.
        if index >= 10000:
            raise SourceError("NVD critical results exceeded 10000; narrow the collection window")
    return output


REDHAT_CVE_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
REDHAT_CVE_DETAILS = "https://access.redhat.com/hydra/rest/securitydata/cve/"


def parse_redhat_quay(items: list[dict]) -> list[dict]:
    """Parse public Red Hat Security Data API CVE records for Quay products."""
    records = schema.redhat(items)
    results = []
    for item in records:
        cve = item.get("CVE") or item.get("cve_id")
        bugzilla = item.get("bugzilla") or {}
        if isinstance(bugzilla, list):
            bugzilla = bugzilla[0] if bugzilla else {}
        desc = (bugzilla.get("description") if isinstance(bugzilla, dict) else None)
        details = item.get("details") or item.get("description") or ""
        if isinstance(details, list):
            details = next((entry for entry in details if isinstance(entry, str)), "")
        if not isinstance(details, str):
            details = ""
        title = str(desc or item.get("title") or details[:150] or
                    ("Red Hat Quay security advisory " + cve))
        score = item.get("cvss3_score") or item.get("cvss_score")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        severity = str(item.get("severity") or cvss_to_severity(score)).lower()
        if severity == "important":
            severity = "high"
        if severity == "moderate":
            severity = "medium"
        results.append(make_advisory(
            identifier=cve, title=title, summary=details or title,
            severity=severity, cvss=score,
            affected=["Red Hat Quay"],
            source="Red Hat Security Data API",
            url="https://access.redhat.com/security/cve/" + cve,
            published=str(item.get("public_date") or ""),
            modified=str(item.get("public_date") or "")))
    return results


def collect_redhat_quay(now: datetime, *, days: int = 7) -> list[dict]:
    """Red Hat's official API scoped to its Quay products, not all Red Hat CVEs."""
    since = cutoff_date(now, days)
    results = []
    for page in range(1, 11):
        params = urlencode({"after": since, "product": "Red Hat Quay",
                            "per_page": 100, "page": page, "isCompressed": "false"})
        payload = get_json(REDHAT_CVE_URL + "?" + params)
        schema.redhat(payload)
        # List items are intentionally compact; enrich Quay descriptions using
        # Red Hat's public per-CVE endpoint when available.
        for item in payload:
            cve = (item or {}).get("CVE") if isinstance(item, dict) else None
            if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I):
                try:
                    full = get_json(REDHAT_CVE_DETAILS + cve + ".json")
                    if isinstance(full, dict):
                        item = {**item, **full}
                except SourceError:
                    pass  # A missing detail endpoint must not discard an advisory.
            results.extend(parse_redhat_quay([item]))
        if len(payload) < 100:
            break
    else:
        raise SourceError("Red Hat Quay CVEs exceeded ten pages; results incomplete")
    return results


SOURCES = {"cisa_kev": collect_kev, "github_advisories": collect_ghsa,
           "nist_nvd": collect_nvd, "redhat_quay": collect_redhat_quay}
