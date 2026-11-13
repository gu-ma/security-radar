"""Bounded HTTP JSON requests. Remote content is data, never executed."""
from __future__ import annotations

import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class SourceError(RuntimeError):
    pass


def get_json(url: str, *, api: str = "", timeout: int = 25) -> dict | list:
    headers = {
        "User-Agent": "SecurityRadar/0.1 (+https://github.com/gu-ma/security-radar)",
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
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
            last_error = exc
            retryable = not isinstance(exc, HTTPError) or exc.code in (429, 500, 502, 503, 504)
            if not retryable or attempt == 2:
                break
            time.sleep(2 ** attempt)
    raise SourceError(f"Unable to read {api or 'JSON'} source ({type(last_error).__name__}: {last_error})")
