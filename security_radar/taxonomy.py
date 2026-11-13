"""Deterministic technology and security-topic tags, with no generative service.

Categories are an editorial grouping based on evidence in public advisory text.
They are not a declaration of an affected installed product.
"""
from __future__ import annotations

import re

CATEGORIES = (
    ("applications", "Applications"),
    ("dependencies", "Libraries & dependencies"),
    ("containers", "Containers & registries"),
    ("infrastructure", "Servers & infrastructure"),
    ("cloud-identity", "Cloud & identity"),
    ("ai-ml", "AI & ML tooling"),
)
CATEGORY_LABELS = dict(CATEGORIES)
TOPICS = (
    "Supply chain",
    "Remote code execution",
    "Privilege escalation",
    "Authentication & authorization",
    "Data exposure",
    "Denial of service",
)
_CATEGORY_RULES: dict[str, tuple[str, ...]] = {
    "applications": (
        r"\b(?:browser|chrome|chromium|firefox|outlook|microsoft office|office 365|adobe reader|acrobat|desktop app|safari|wordpress|thunderbird)\b",
    ),
    "dependencies": (
        r"\b(?:python|pypi|pip|conda|npm|node\.js|javascript|package|dependency|dependencies|libraries|library|maven|gradle|nuget|ruby gem|cargo|django|flask|spring framework)\b",
    ),
    "containers": (
        r"\b(?:quay|docker|container|registry|registries|kubernetes|k8s|podman|helm|oci image|container image|image signing)\b",
    ),
    "infrastructure": (
        r"\b(?:linux|kernel|openssh|openbsd|ssh server|nginx|apache http|httpd|web server|network appliance|firewall|hypervisor|vmware|virtualization|postgresql|mysql|redis|server)\b",
    ),
    "cloud-identity": (
        r"\b(?:aws|amazon web services|azure|google cloud|gcp|cloud service|cloud computing|keycloak|okta|entra|active directory|identity provider|oauth|openid connect|iam)\b",
    ),
    "ai-ml": (
        r"\b(?:pytorch|tensorflow|jupyter|transformers|hugging face|huggingface|mlflow|ollama|vllm|langchain|machine learning|model serving|llm framework|keras)\b",
    ),
}
_TOPIC_RULES: dict[str, tuple[str, ...]] = {
    "Supply chain": (
        r"\b(?:supply[- ]chain|dependency confusion|malicious package|poisoned (?:image|package)|tamper(?:ed|ing)? (?:with )?(?:container )?images?|signing[- ]key|software artifact signing|package substitution)\b",
    ),
    "Remote code execution": (
        r"\b(?:remote code execution|arbitrary code execution|execute arbitrary code|\brce\b|command injection|code injection)\b",
    ),
    "Privilege escalation": (
        r"\b(?:privilege escalation|elevation of privilege|elevate privileges|gain elevated privileges)\b",
    ),
    "Authentication & authorization": (
        r"\b(?:authentication bypass|authorization bypass|improper authorization|access control|credential theft|credentials? disclosure|unauthenticated access|token forgery|account takeover)\b",
    ),
    "Data exposure": (
        r"\b(?:information disclosure|data exposure|sensitive data|data leakage|leak sensitive|expose private|exfiltrat|data breach)\b",
    ),
    "Denial of service": (
        r"\b(?:denial of service|\bdos\b|resource exhaustion|service disruption)\b",
    ),
}


def _find_rules(text: str, rules: dict[str, tuple[str, ...]]) -> list[str]:
    return [label for label, patterns in rules.items()
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)]


def categorize(advisory: dict) -> list[str]:
    # Prefer specifically named products/ecosystems; source title and summary
    # are supporting evidence. False positives are possible and documented.
    parts = [advisory.get("title", ""), advisory.get("summary", "")]
    parts += advisory.get("affected", []) or []
    parts += advisory.get("ecosystems", []) or []
    return _find_rules(" ".join(str(p) for p in parts), _CATEGORY_RULES) or ["unclassified"]


def topic_tags(advisory: dict) -> list[str]:
    text = " ".join(str(advisory.get(key, "")) for key in ("title", "summary"))
    return _find_rules(text, _TOPIC_RULES)


def explanation(advisory: dict) -> str:
    summary = advisory.get("summary", "")
    return summary if summary else "The source did not provide a description. Consult the original advisory."


def next_step(advisory: dict) -> str:
    """Choose a fixed template, not generated text or an assumed mitigation."""
    tags = set(advisory.get("security_topics") or topic_tags(advisory))
    categories = set(advisory.get("categories") or categorize(advisory))
    if advisory.get("exploited"):
        return ("Review the vendor advisory promptly. Check relevant installed product "
                "versions and follow the vendor's mitigation guidance.")
    if "Supply chain" in tags:
        return ("Review the original advisory and affected build or distribution "
                "components. Verify upstream status before changing dependencies.")
    if "Containers & registries" in (CATEGORY_LABELS.get(x) for x in categories):
        return ("Check affected registry or container software versions against "
                "the vendor advisory and its recommended mitigations.")
    if "dependencies" in categories:
        return ("Check whether affected package versions are present in your "
                "dependencies and review the maintainer's fix guidance.")
    if "cloud-identity" in categories:
        return ("Identify any relevant service or identity-product versions "
                "and consult the vendor's remediation instructions.")
    return ("Check whether the named product and affected versions are in use; "
            "follow the original vendor's remediation guidance.")
