"""OSV.dev API lookup, for ecosystems that have no local bulk index.

    POST https://api.osv.dev/v1/querybatch   {"queries": [{"package": {"name", "ecosystem"}}, ...]}
    POST https://api.osv.dev/v1/query        {"package": {...}, "page_token": ...}   (paging)
    GET  https://api.osv.dev/v1/vulns/<id>   (full record)

The bulk snapshot (scripts/fetch_data.py) stays the default for PyPI, npm and Go because it runs fully
offline. The API is the extension point: any ecosystem OSV knows can be looked up with the same query
format, as long as depscan/ecosystems.py knows how to order its versions.

Safe offline: everything is cached on disk (names -> ids for 7 days, records by id and `modified`),
the timeout is short, and one network failure marks the API down for the run. If the API could not
be reached and nothing is cached, `failed` is set so the report can say "NOT checked" instead of
silently showing no findings.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .data.osv import compact_advisory
from .ecosystems import normalize_name

API = "https://api.osv.dev/v1"
USER_AGENT = "depscan-hackathon/0.1 (read-only advisory lookup)"
TTL_SECONDS = 7 * 24 * 3600
BATCH = 500  # querybatch accepts up to 1000 queries; stay well below

# (method, url, json body or None, timeout) -> parsed JSON
Transport = Callable[[str, str, dict | None, float], dict]


def default_transport(method: str, url: str, body: dict | None, timeout: float) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": USER_AGENT, **({"Content-Type": "application/json"} if data else {})}
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=timeout) as r:
        return json.loads(r.read())


class OsvApiIndex:
    """Looks like the dict the matcher expects: `.get(name, default)` -> compact advisories."""

    def __init__(self, ecosystem: str, cache_dir: Path, *, transport: Transport | None = None,
                 timeout: float = 10.0, offline: bool = False):
        self.ecosystem = ecosystem
        self.dir = cache_dir / "osv_api"
        self.transport = transport or default_transport
        self.timeout = timeout
        self.down = offline
        self.failed: list[str] = []            # package names we could not check at all
        self._ids: dict[str, list[dict]] = {}  # name -> [{"id","modified"}]
        self.network_calls = 0

    # ---- disk cache
    def _names_path(self) -> Path:
        return self.dir / f"{self.ecosystem}.names.json"

    def _load_names(self) -> dict:
        try:
            return json.loads(self._names_path().read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def _vuln_path(self, vid: str) -> Path:
        return self.dir / "vulns" / f"{vid.replace('/', '_')}.json"

    # ---- network
    def _call(self, method: str, path: str, body: dict | None = None) -> dict | None:
        if self.down:
            return None
        try:
            self.network_calls += 1
            return self.transport(method, f"{API}{path}", body, self.timeout)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError):
            self.down = True  # circuit breaker
            return None

    def prefetch(self, names: list[str]) -> None:
        """Resolve advisory ids for all names with as few requests as possible (querybatch)."""
        cache = self._load_names()
        now = time.time()
        todo = []
        for n in dict.fromkeys(names):
            hit = cache.get(n)
            if hit and now - hit["fetched_at"] < TTL_SECONDS:
                self._ids[n] = hit["vulns"]
            else:
                todo.append(n)
        for i in range(0, len(todo), BATCH):
            chunk = todo[i:i + BATCH]
            resp = self._call("POST", "/querybatch", {"queries": [
                {"package": {"name": n, "ecosystem": self.ecosystem}} for n in chunk]})
            if resp is None:
                for n in chunk:  # a stale cache entry beats nothing
                    if n in cache:
                        self._ids[n] = cache[n]["vulns"]
                    else:
                        self.failed.append(n)
                continue
            for n, result in zip(chunk, resp.get("results", [])):
                vulns = list(result.get("vulns", []))
                token = result.get("next_page_token")
                while token:  # querybatch pages large results: follow with /query
                    page = self._call("POST", "/query", {"package": {"name": n, "ecosystem": self.ecosystem}, "page_token": token})
                    if page is None:
                        break
                    vulns += page.get("vulns", [])
                    token = page.get("next_page_token")
                self._ids[n] = [{"id": v["id"], "modified": v.get("modified")} for v in vulns]
                cache[n] = {"fetched_at": now, "vulns": self._ids[n]}
        if todo:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._names_path().write_text(json.dumps(cache), "utf-8")

    def _record(self, vid: str, modified: str | None) -> dict | None:
        p = self._vuln_path(vid)
        try:
            cached = json.loads(p.read_text("utf-8"))
            if modified is None or cached.get("modified") == modified or self.down:
                return cached
        except (OSError, ValueError):
            cached = None
        raw = self._call("GET", f"/vulns/{vid}")
        if raw is None:
            return cached  # stale or missing
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(raw), "utf-8")
        return raw

    # ---- the interface the matcher uses
    def get(self, name: str, default=None):
        if name not in self._ids:
            self.prefetch([name])
        out = []
        for v in self._ids.get(name, []):
            raw = self._record(v["id"], v.get("modified"))
            if raw:
                out.append(compact_advisory(raw, self.ecosystem, normalize_name(self.ecosystem, name)))
        return out if out or name in self._ids else (default if default is not None else [])
