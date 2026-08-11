"""A cached HTTP client, and nothing more.

Shared by the registry and OSV clients. Caching matters here beyond speed:
a scan you re-run while triaging should not re-hit a public endpoint, and
the maintainers of those endpoints are doing us a favour by serving them.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "hemlock (+https://github.com/xzycd/hemlock)"
DEFAULT_TTL = 6 * 3600
# Registry documents can be large, especially npm packuments, but none of the
# endpoints used here should need an unbounded read. The same ceiling applies
# after gzip expansion so a small compressed response cannot exhaust memory.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


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
        os.makedirs(self.cache_dir, mode=0o700, exist_ok=True)

    # -- cache ------------------------------------------------------------

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, hashlib.sha256(key.encode()).hexdigest()[:32] + ".json.gz")

    def _read(self, key: str):
        path = self._path(key)
        try:
            if time.time() - os.path.getmtime(path) < self.ttl:
                with open(path, "rb") as fh:
                    self.hits += 1
                    return json.loads(_gunzip(fh.read(MAX_RESPONSE_BYTES + 1)))
        except (OSError, ValueError):
            pass
        return None

    def _write(self, key: str, doc) -> None:
        temporary = ""
        try:
            payload = gzip.compress(json.dumps(doc).encode())
            fd, temporary = tempfile.mkstemp(prefix=".hemlock-", dir=self.cache_dir)
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
            # A complete cache entry appears in one operation. This also
            # replaces a destination symlink instead of following it.
            os.replace(temporary, self._path(key))
            temporary = ""
        except (OSError, TypeError):
            pass
        finally:
            if temporary:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    # -- requests ---------------------------------------------------------

    def get(self, url: str, allow_404: bool = False):
        """Returns the decoded body, ABSENT for a 404 the caller allowed, or
        None when the request did not complete. A 404 is a fact, not a
        failure, when the caller says so: 'this package has no provenance' is
        an answer, and caching it stops us asking again every run."""
        if not _safe_url(url):
            self.failures.append(f"{_short(url)}: refused non-HTTPS URL")
            return None
        if (hit := self._read(url)) is not None:
            return ABSENT if hit == {"__absent__": True} else hit

        req = urllib.request.Request(  # noqa: S310 - _safe_url restricts the scheme and authority
            url, headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
        )
        try:
            self.calls += 1
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
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
        if not _safe_url(url):
            self.failures.append(f"{_short(url)}: refused non-HTTPS URL")
            return None
        key = cache_key or (url + "#" + hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest())
        if (hit := self._read(key)) is not None:
            return hit

        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 - _safe_url restricts the scheme and authority
            url, data=data,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept-Encoding": "gzip"},
        )
        try:
            self.calls += 1
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                doc = json.loads(_body(resp))
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            self.failures.append(f"{_short(url)}: {exc}")
            return None

        self._write(key, doc)
        return doc


def _body(resp) -> bytes:
    raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response exceeds {MAX_RESPONSE_BYTES} bytes")
    return _gunzip(raw) if resp.headers.get("Content-Encoding") == "gzip" else raw


def _gunzip(raw: bytes) -> bytes:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"compressed response exceeds {MAX_RESPONSE_BYTES} bytes")
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
        body = fh.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"expanded response exceeds {MAX_RESPONSE_BYTES} bytes")
    return body


def _short(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        # hostname excludes embedded credentials, unlike netloc.
        return (parsed.hostname or "unknown host") + parsed.path[:60]
    except ValueError:
        return "invalid URL"


def _safe_url(url: str) -> bool:
    """Only public HTTPS endpoints belong in this client.

    Reject embedded credentials as well. They are unnecessary for the public
    APIs Hemlock uses and can leak through error messages or proxy logs.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        return bool(
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False
