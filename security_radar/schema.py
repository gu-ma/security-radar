"""Minimal, strict source-specific structural checks.

Schema changes are visible failures, not silently dropped records. Empty lists
are valid because date- or product-filtered queries may genuinely have no hits.
Optional advisory fields can be absent without invalidating the record.
"""
from __future__ import annotations

import re

from .http import SourceSchemaError


def _list(value, source: str, key: str) -> list:
    if not isinstance(value, list):
        raise SourceSchemaError(f"{source}: {key} must be an array")
    return value


def _items(items: list, source: str) -> list:
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise SourceSchemaError(f"{source}: item {index} must be an object")
    return items


def kev(payload: object) -> list:
    if not isinstance(payload, dict):
        raise SourceSchemaError("CISA KEV: response must be an object")
    records = _items(_list(payload.get("vulnerabilities"), "CISA KEV", "vulnerabilities"), "CISA KEV")
    for index, item in enumerate(records):
        if not isinstance(item.get("cveID"), str) or not item["cveID"].strip():
            raise SourceSchemaError(f"CISA KEV: missing cveID at index {index}")
        if not isinstance(item.get("dateAdded"), str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["dateAdded"]):
            raise SourceSchemaError(f"CISA KEV: invalid dateAdded at index {index}")
    return records


def ghsa(payload: object) -> list:
    records = _items(_list(payload, "GitHub Advisories", "response"), "GitHub Advisories")
    for index, item in enumerate(records):
        if not isinstance(item.get("ghsa_id"), str) or not item["ghsa_id"].startswith("GHSA-"):
            raise SourceSchemaError(f"GitHub Advisories: missing/invalid ghsa_id at index {index}")
        if item.get("vulnerabilities") is not None:
            _items(_list(item["vulnerabilities"], "GitHub Advisories", "vulnerabilities"), "GitHub Advisories")
            for v in item["vulnerabilities"]:
                if v.get("package") is not None and not isinstance(v["package"], dict):
                    raise SourceSchemaError("GitHub Advisories: vulnerability.package must be an object")
        if item.get("cvss") is not None and not isinstance(item["cvss"], dict):
            raise SourceSchemaError("GitHub Advisories: cvss must be an object")
    return records


def nvd(payload: object) -> list:
    if not isinstance(payload, dict):
        raise SourceSchemaError("NIST NVD: response must be an object")
    records = _items(_list(payload.get("vulnerabilities"), "NIST NVD", "vulnerabilities"), "NIST NVD")
    for index, item in enumerate(records):
        cve = item.get("cve")
        if not isinstance(cve, dict) or not isinstance(cve.get("id"), str) or not cve["id"].strip():
            raise SourceSchemaError(f"NIST NVD: missing cve.id at index {index}")
        if cve.get("descriptions") is not None:
            _items(_list(cve["descriptions"], "NIST NVD", "descriptions"), "NIST NVD")
        if cve.get("metrics") is not None:
            if not isinstance(cve["metrics"], dict):
                raise SourceSchemaError("NIST NVD: metrics must be an object")
            for key, entries in cve["metrics"].items():
                if key.startswith("cvssMetric"):
                    _items(_list(entries, "NIST NVD", key), "NIST NVD")
    return records


def redhat(payload: object) -> list:
    records = _items(_list(payload, "Red Hat Quay", "response"), "Red Hat Quay")
    for index, item in enumerate(records):
        cve = item.get("CVE") or item.get("cve_id")
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I):
            raise SourceSchemaError(f"Red Hat Quay: missing/invalid CVE at index {index}")
    return records
