"""Bounded HTTP JSON requests and GitHub cursor pagination helpers.

Remote content is untrusted data. Responses and pagination links are validated.
"""
from __future__ import annotations

import json
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class SourceError(RuntimeError):
    """An upstream collector failed without publishing a partial result."""


class SourceSchemaError(SourceError):
    """Upstream JSON parsed, but no longer meets the adapter's expected schema."""


class SourcePaginationError(SourceError):
    """Pagination could not be completed safely."""


def _request_json(url: str, *, api: str = "", timeout: int = 25) -> tuple[dict | list, str]:
    headers = {
        "User-Agent": "SecurityRadar/0.3 (+https://github.com/gu-ma/security-radar)",
        "Accept": "application/json",
    }
    if api == "github":
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        token = os.environ.get("GH_TOKEN", "")
        if token:
            headers["Authorization"] = "Bearer " + token
    if api == "nvd":
        token = os.environ.get("NVD_API_KEY", "")
        if token:
            headers["apiKey"] = token
    last_error = None
    for attempt in range(3):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=timeout) as response:
                raw = response.read(12 * 1024 * 1024 + 1)
                if len(raw) > 12 * 1024 * 1024:
                    raise SourceError("Source response exceeded 12 MiB")
                return json.loads(raw), response.headers.get("Link", "")
        except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
            last_error = exc
            retryable = not isinstance(exc, HTTPError) or exc.code in (429, 500, 502, 503, 504)
            if not retryable or attempt == 2:
                break
            time.sleep(2 ** attempt)
    raise SourceError(
        f"Unable to read {api or 'JSON'} source ({type(last_error).__name__}: {last_error})"
    )


def get_json(url: str, *, api: str = "", timeout: int = 25) -> dict | list:
    return _request_json(url, api=api, timeout=timeout)[0]


def _github_next_link(header: str, original_url: str) -> str | None:
    """Accept only GitHub's HTTPS Link rel=next for the same API endpoint."""
    if not header:
        return None
    origin = urlsplit(original_url)
    for fragment in header.split(","):
        match = re.search(r'<([^>]+)>\s*;\s*rel=["\']?next["\']?', fragment, re.I)
        if not match:
            continue
        candidate = match.group(1)
        parsed = urlsplit(candidate)
        if (parsed.scheme != "https" or parsed.hostname != "api.github.com" or
                parsed.netloc != "api.github.com" or
                parsed.path != origin.path or not parsed.query):
            raise SourcePaginationError("GitHub returned an unexpected pagination destination")
        return candidate
    return None


def get_github_page(url: str, *, timeout: int = 25) -> tuple[list, str | None]:
    """Read one page and the next cursor URL supplied by the GitHub API."""
    result, link_header = _request_json(url, api="github", timeout=timeout)
    if not isinstance(result, list):
        raise SourceSchemaError("GitHub global advisories returned a non-list response")
    return result, _github_next_link(link_header, url)
