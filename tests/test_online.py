"""The --online layer, exercised against a stub instead of the network.

Nothing here touches a registry. The point is the logic that sits on top of
the responses: which records get believed, how a repository URL is compared,
and what happens when a lookup fails.
"""

import os
import urllib.request

import pytest

from hemlock.intel import Osv
from hemlock.model import Package
from hemlock.provenance import describe, npm_provenance, repo_slug
from hemlock.registry import Registry


class FakeHttp:
    """Serves canned documents and records what was asked for."""

    def __init__(self, docs=None):
        self.docs = docs or {}
        self.failures = []
        self.calls = 0
        self.hits = 0
        self.asked = []

    def get(self, url, allow_404=False):
        self.asked.append(url)
        self.calls += 1
        return self.docs.get(url)

    def post(self, url, payload, cache_key=None):
        self.asked.append(url)
        self.calls += 1
        handler = self.docs.get(url)
        return handler(payload) if callable(handler) else handler


# -- OSV -------------------------------------------------------------------

BATCH = "https://api.osv.dev/v1/querybatch"
VULN = "https://api.osv.dev/v1/vulns/"


def osv_with(results, details=None):
    docs = {BATCH: lambda payload: {"results": results}}
    docs.update({VULN + k: v for k, v in (details or {}).items()})
    return Osv(FakeHttp(docs))


def test_separates_malware_from_advisories():
    osv = osv_with(
        [{"vulns": [{"id": "MAL-2025-46969"}, {"id": "GHSA-aaaa-bbbb-cccc"}]}],
        {"MAL-2025-46969": {"summary": "Malicious code in chalk (npm)", "aliases": ["GHSA-2v46-p5h4-248w"]}},
    )
    pkg = Package("npm", "chalk", version="5.6.1")
    osv.enrich([pkg])

    assert pkg.meta["malware"][0]["id"] == "MAL-2025-46969"
    assert pkg.meta["malware"][0]["summary"] == "Malicious code in chalk (npm)"
    assert pkg.meta["advisories"] == ["GHSA-aaaa-bbbb-cccc"]


def test_withdrawn_malware_reports_are_ignored():
    """OSV pulled 157 false-positive malware reports in May 2026. A tool that
    keeps failing builds on a retracted record is worse than no tool."""
    osv = osv_with(
        [{"vulns": [{"id": "MAL-2026-00001"}]}],
        {"MAL-2026-00001": {"summary": "Malicious code in innocent", "withdrawn": "2026-05-20T00:00:00Z"}},
    )
    pkg = Package("npm", "innocent", version="1.0.0")
    osv.enrich([pkg])
    assert "malware" not in pkg.meta


def test_clean_packages_get_no_metadata():
    pkg = Package("npm", "express", version="4.18.2")
    osv_with([{}]).enrich([pkg])
    assert "malware" not in pkg.meta and "advisories" not in pkg.meta


def test_pypi_names_are_normalised_and_ecosystem_cased():
    osv = osv_with([{}])
    osv.enrich([Package("pypi", "Python_DateUtil", version="2.8.2")])
    query = osv.http.docs  # the payload is built inside post(); re-run it
    sent = {}

    def capture(payload):
        sent.update(payload)
        return {"results": [{}]}

    osv.http.docs = {**query, BATCH: capture}
    osv.enrich([Package("pypi", "Python_DateUtil", version="2.8.2")])
    assert sent["queries"][0]["package"] == {"ecosystem": "PyPI", "name": "python-dateutil"}


def test_packages_without_a_version_are_skipped():
    osv = osv_with([{}])
    osv.enrich([Package("npm", "chalk", spec="^5.0.0")])
    assert osv.http.calls == 0


def test_the_same_coordinate_is_asked_about_once():
    sent = []
    osv = Osv(FakeHttp({BATCH: lambda p: (sent.append(p), {"results": [{}]})[1]}))
    a = Package("npm", "chalk", version="5.6.0", origin="a/package-lock.json")
    b = Package("npm", "chalk", version="5.6.0", origin="b/package-lock.json")
    osv.enrich([a, b])
    assert len(sent[0]["queries"]) == 1


# -- provenance ------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("git+ssh://git@github.com/sindresorhus/chalk.git", "sindresorhus/chalk"),
        ("git+https://github.com/psf/requests.git", "psf/requests"),
        ("https://github.com/PSF/Requests", "psf/requests"),
        ("github:expressjs/express", "expressjs/express"),
        ("git@github.com:sigstore/sigstore-js.git", "sigstore/sigstore-js"),
        ({"type": "git", "url": "git+https://github.com/npm/cli.git"}, "npm/cli"),
        ("expressjs/express", "expressjs/express"),
        ("", None),
        ("not-a-repo", None),
        (None, None),
    ],
)
def test_repo_slug_normalises_every_spelling(value, expected):
    assert repo_slug(value) == expected


def _bundle(payload_b64):
    return {"attestations": [{"bundle": {"dsseEnvelope": {"payload": payload_b64}}}]}


def test_npm_provenance_extracts_repo_workflow_and_commit():
    import base64
    import json

    statement = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {
                        "repository": "https://github.com/sigstore/sigstore-js",
                        "path": ".github/workflows/release.yml",
                        "ref": "refs/heads/main",
                    }
                },
                "resolvedDependencies": [{"digest": {"gitCommit": "3a57a741bfb9f7c3bca69b63e170fc28e9432e69"}}],
            }
        },
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    url = "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0"
    http = FakeHttp({url: _bundle(payload)})

    prov = npm_provenance("sigstore", "3.0.0", http)
    assert prov["repository"] == "sigstore/sigstore-js"
    assert prov["workflow"] == "release.yml"
    assert prov["commit"].startswith("3a57a74")
    assert describe(prov) == "sigstore/sigstore-js@3a57a74 via release.yml"


def test_npm_provenance_absent_is_not_an_error():
    assert npm_provenance("left-pad", "1.3.0", FakeHttp({})) is None


def test_malformed_attestation_payload_is_survivable():
    url = "https://registry.npmjs.org/-/npm/v1/attestations/x@1.0.0"
    assert npm_provenance("x", "1.0.0", FakeHttp({url: _bundle("not base64 !!!")})) is None


# -- registry --------------------------------------------------------------


def npm_packument(versions, times, repo="https://github.com/acme/widget"):
    return {
        "versions": versions,
        "time": times,
        "repository": {"url": repo},
        "dist-tags": {"latest": max(versions)},
    }


def test_prior_publishers_only_counts_earlier_releases():
    """A pinned old version predates the newest releases, so those publishers
    are not 'prior' to it and must not make it look like a takeover."""
    packument = npm_packument(
        versions={
            "1.0.0": {"_npmUser": {"name": "alice"}, "dist": {}},
            "2.0.0": {"_npmUser": {"name": "alice"}, "dist": {}},
            "3.0.0": {"_npmUser": {"name": "newteam"}, "dist": {}},
        },
        times={
            "1.0.0": "2020-01-01T00:00:00Z",
            "2.0.0": "2021-01-01T00:00:00Z",
            "3.0.0": "2026-01-01T00:00:00Z",
        },
    )
    http = FakeHttp({"https://registry.npmjs.org/widget": packument})
    meta = Registry(http)._npm("widget", "2.0.0")

    assert meta["publisher"] == "alice"
    assert meta["prior_publishers"] == ["alice"]  # not "newteam", who came later


def test_a_genuinely_new_publisher_is_visible():
    packument = npm_packument(
        versions={
            "1.0.0": {"_npmUser": {"name": "alice"}, "dist": {}},
            "1.0.1": {"_npmUser": {"name": "stranger"}, "dist": {}},
        },
        times={"1.0.0": "2025-01-01T00:00:00Z", "1.0.1": "2026-06-01T00:00:00Z"},
    )
    http = FakeHttp({"https://registry.npmjs.org/widget": packument})
    meta = Registry(http)._npm("widget", "1.0.1")
    assert meta["publisher"] == "stranger" and meta["prior_publishers"] == ["alice"]


def test_an_offline_scan_opens_no_connection(monkeypatch):
    """`hemlock scan` without --online is documented as making no network
    calls at all. That promise is worth a test, not just a paragraph."""
    from hemlock import cli

    def forbidden(*args, **kwargs):
        raise AssertionError("an offline scan tried to reach the network")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    fixture = os.path.join(os.path.dirname(__file__), "..", "examples", "compromised-app")
    assert cli.main(["scan", fixture, "--format", "json", "--fail-on", "never"]) == 0


def test_declared_repo_is_normalised_for_comparison():
    packument = npm_packument(
        versions={"1.0.0": {"dist": {}}},
        times={"1.0.0": "2026-01-01T00:00:00Z"},
        repo="git+ssh://git@github.com/Acme/Widget.git",
    )
    http = FakeHttp({"https://registry.npmjs.org/widget": packument})
    assert Registry(http)._npm("widget", "1.0.0")["declared_repo"] == "acme/widget"
