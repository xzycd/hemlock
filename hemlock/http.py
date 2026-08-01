"""A cached HTTP client, and nothing more.

Shared by the registry and OSV clients. Caching matters here beyond speed:
a scan you re-run while triaging should not re-hit a public endpoint, and
the maintainers of those endpoints are doing us a favour by serving them.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "hemlock (+https://github.com/xzycd/hemlock)"
DEFAULT_TTL = 6 * 3600


class _Absent:
    """What a 404 returns when the caller asked for one.

    Falsy, so every `if not doc` reading it as "nothing usable came back"
    still holds. Identity is what separates it from `None`: "the registry has
    no such package" and "we could not ask the registry" are different
    answers, and a tool that reports the second as the first tells you a
    package does not exist every time a DNS lookup times out.
    """

    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "ABSENT"


ABSENT = _Absent()


def default_cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "hemlock")


class Http:
    def __init__(self, cache_dir: str | None = None, timeout: int = 20, ttl: int = DEFAULT_TTL):
        self.cache_dir = cache_dir or default_cache_dir()
        self.timeout = timeout
        self.ttl = ttl
        self.failures: list[str] = []
        self.calls = 0
        self.hits = 0
        os.makedirs(self.cache_dir, exist_ok=True)

    # -- cache ------------------------------------------------------------

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha256(key.encode()).hexdigest()[:32] + ".json.gz")

    def _read(self, key: str):
        path = self._path(key)
        try:
            if time.time() - os.path.getmtime(path) < self.ttl:
                with open(path, "rb") as fh:
                    self.hits += 1
                    return json.loads(gzip.decompress(fh.read()))
        except (OSError, ValueError):
            pass
        return None

    def _write(self, key: str, doc) -> None:
        try:
            with open(self._path(key), "wb") as fh:
                fh.write(gzip.compress(json.dumps(doc).encode()))
        except (OSError, TypeError):
            pass

    # -- requests ---------------------------------------------------------

    def get(self, url: str, allow_404: bool = False):
        """Returns the decoded body, ABSENT for a 404 the caller allowed, or
        None when the request did not complete. A 404 is a fact, not a
        failure, when the caller says so: 'this package has no provenance' is
        an answer, and caching it stops us asking again every run."""
        if (hit := self._read(url)) is not None:
            return ABSENT if hit == {"__absent__": True} else hit

        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"})
        try:
            self.calls += 1
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                doc = json.loads(_body(resp))
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_404:
                self._write(url, {"__absent__": True})
                return ABSENT
            self.failures.append(f"{_short(url)}: HTTP {exc.code}")
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            self.failures.append(f"{_short(url)}: {exc}")
            return None

        self._write(url, doc)
        return doc

    def post(self, url: str, payload: dict, cache_key: str | None = None):
        key = cache_key or (url + "#" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest())
        if (hit := self._read(key)) is not None:
            return hit

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept-Encoding": "gzip"},
        )
        try:
            self.calls += 1
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                doc = json.loads(_body(resp))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            self.failures.append(f"{_short(url)}: {exc}")
            return None

        self._write(key, doc)
        return doc


def _body(resp) -> bytes:
    raw = resp.read()
    return gzip.decompress(raw) if resp.headers.get("Content-Encoding") == "gzip" else raw


def _short(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc + parsed.path[:60]
