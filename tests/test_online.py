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


def _pypi_docs(name="hemlock-scan", version="0.5.0", attested=True):
    """A versionless PyPI lookup, the shape `hemlock check <name>` produces."""
    wheel = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    docs = {
        f"https://pypi.org/pypi/{name}/json": {
            "info": {"version": version, "home_page": f"https://github.com/acme/{name}"},
            "urls": [{
                "filename": wheel,
                "packagetype": "bdist_wheel",
                "size": 88634,
                "upload_time_iso_8601": "2026-07-31T17:40:00Z",
            }],
        },
    }
    if attested:
        docs[f"https://pypi.org/integrity/{name}/{version}/{wheel}/provenance"] = {
            "attestation_bundles": [{
                "publisher": {
                    "kind": "GitHub",
                    "repository": f"acme/{name}",
                    "workflow": "release.yml",
                    "environment": "pypi",
                },
                "attestations": [],
            }],
        }
    return docs


def test_a_bare_pypi_name_still_gets_its_provenance_checked():
    """PEP 740 attestations attach to a file, so finding one needs a version.
    The npm branch resolved `latest` and this one did not, so `hemlock check
    <name>` reported every signed package as unsigned. hemlock's own 0.5.0
    release was the first thing it accused."""
    http = FakeHttp(_pypi_docs())
    meta = Registry(http)._pypi("hemlock-scan", None)

    assert meta["resolved_version"] == "0.5.0"
    assert meta["provenance"], "a signed release was reported as having no attestation"
    assert meta["provenance"]["repository"] == "acme/hemlock-scan"
    assert meta["provenance"]["workflow"] == "release.yml"


def test_an_unsigned_release_is_still_reported_as_unsigned():
    """The fix above must not turn HEM601 off. A 404 from the integrity
    endpoint is the genuine no-provenance answer and has to survive."""
    http = FakeHttp(_pypi_docs(attested=False))
    meta = Registry(http)._pypi("hemlock-scan", None)
    assert meta["resolved_version"] == "0.5.0"
    assert meta["provenance"] is None


def test_an_explicit_version_is_not_overwritten_by_the_latest_one():
    docs = _pypi_docs()
    docs["https://pypi.org/pypi/hemlock-scan/0.4.1/json"] = {
        "info": {"version": "0.5.0"},   # PyPI reports `info.version` as latest
        "urls": [{"filename": "hemlock_scan-0.4.1-py3-none-any.whl",
                  "packagetype": "bdist_wheel", "size": 1}],
    }
    meta = Registry(FakeHttp(docs))._pypi("hemlock-scan", "0.4.1")
    assert meta["resolved_version"] == "0.4.1"


def test_a_fresh_release_names_the_version_it_actually_found():
    """This read `None published 0 hours ago` for a name with no version on
    it. `pkg.version` stays whatever the manifest pinned, because
    `floating_version` reads it to mean exactly that."""
    from datetime import UTC, datetime

    from hemlock.model import Context, Package
    from hemlock.rules import fresh_release

    pkg = Package("pypi", "hemlock-scan")
    pkg.meta["published_at"] = datetime.now(UTC)
    pkg.meta["resolved_version"] = "0.5.0"

    evidence = list(fresh_release(pkg, Context(root=".")))
    assert evidence and evidence[0].startswith("0.5.0 published")
    assert "None" not in evidence[0]
    assert pkg.version is None, "the manifest pinned nothing and that must stay true"


def test_declared_repo_is_normalised_for_comparison():
    packument = npm_packument(
        versions={"1.0.0": {"dist": {}}},
        times={"1.0.0": "2026-01-01T00:00:00Z"},
        repo="git+ssh://git@github.com/Acme/Widget.git",
    )
    http = FakeHttp({"https://registry.npmjs.org/widget": packument})
    assert Registry(http)._npm("widget", "1.0.0")["declared_repo"] == "acme/widget"


# -- check, wired to the same enrichment as scan ---------------------------


def test_check_asks_osv_about_a_package_named_on_the_command_line(monkeypatch):
    """The reason `check` exists: the answer to "should I install this" is
    mostly a question for osv.dev, and it costs one request."""
    from hemlock import http as http_mod
    from hemlock import scan
    from hemlock.policy import Policy

    docs = {
        BATCH: lambda payload: {"results": [{"vulns": [{"id": "MAL-2025-46969"}]}]},
        VULN + "MAL-2025-46969": {"summary": "Malicious code in chalk (npm)"},
    }
    monkeypatch.setattr(http_mod, "Http", lambda *a, **k: FakeHttp(docs))

    report = scan.check([scan.parse_spec("npm:chalk@5.6.1")], Policy(), online=True)
    assert [v.package.coord for v in report.malware] == ["chalk@5.6.1"]
    assert report.worst() == "critical"


# -- hemlock update --------------------------------------------------------
#
# Nothing here installs anything, and neither does hemlock without a yes.

import pytest  # noqa: E402

from hemlock import cli, update  # noqa: E402


def test_the_command_is_printed_before_it_runs():
    """The child inherits stdout and writes immediately; our own prints are
    buffered whenever stdout is a pipe. Redirected to a file or read back from
    a CI log, that put all of pip's output above the line saying what was
    about to run. `capture_output` here is the pipe that provokes it."""
    import subprocess
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = (
        "from hemlock.update import run;"
        "print('ANNOUNCE');"
        "run([__import__('sys').executable, '-c', \"print('CHILD')\"])"
    )
    out = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, cwd=root, check=False,
    )
    assert "ANNOUNCE" in out.stdout and "CHILD" in out.stdout, out.stderr
    assert out.stdout.index("ANNOUNCE") < out.stdout.index("CHILD"), (
        f"the command ran before it was announced:\n{out.stdout}"
    )


@pytest.mark.parametrize("text, expected", [
    ("0.5.0", (0, 5, 0)),
    ("v0.5.0", (0, 5, 0)),
    ("1.2", (1, 2, 0)),
    ("10.0.3", (10, 0, 3)),
    ("0.5.0rc1", None),      # a prerelease is not what `update` should offer
    ("nightly", None),
    ("", None),
])
def test_version_parsing(text, expected):
    assert update.parse_version(text) == expected


def test_the_newest_release_wins_and_prereleases_are_skipped():
    assert update.newest(["0.9.0", "0.10.0", "0.4.1"]) == "0.10.0"
    assert update.newest(["v1.0.0", "v0.5.0"]) == "v1.0.0"
    assert update.newest(["1.0.0rc1", "0.9.0"]) == "0.9.0"
    assert update.newest(["nope", "nightly"]) is None


def test_pypi_is_preferred_and_github_is_the_fallback():
    on_pypi = FakeHttp({update.PYPI: {"releases": {"0.4.1": [], "0.6.0": []}}})
    assert update.latest(on_pypi) == ("0.6.0", "pypi")

    only_tags = FakeHttp({update.TAGS: [{"name": "v0.5.0"}, {"name": "v0.4.1"}]})
    assert update.latest(only_tags) == ("v0.5.0", "github")

    assert update.latest(FakeHttp({})) is None


def test_an_untagged_repository_reads_as_nothing_published_not_as_a_failure():
    """PyPI 404s and the repo has no tags. Reporting that as a failed check
    sends people looking at their network for a problem they do not have."""
    http = FakeHttp({update.TAGS: []})
    assert update.latest(http) is None
    assert http.failures == []


def test_how_it_was_installed(tmp_path):
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "hemlock").mkdir()
    assert update.installation(package_dir=str(checkout / "hemlock")) == "git"

    plain = tmp_path / "site" / "hemlock"
    plain.mkdir(parents=True)
    assert update.installation("/usr", str(plain)) == "pip"
    assert update.installation("/home/x/.local/pipx/venvs/hemlock-scan", str(plain)) == "pipx"


def test_the_upgrade_command_follows_where_the_release_actually_is():
    """`hemlock-scan` is not on PyPI yet, so the upgrade path is the
    repository. The day a release lands, PyPI answers and this switches over
    with nothing to edit."""
    assert update.upgrade_command("pipx", on_pypi=True) == ["pipx", "upgrade", "hemlock-scan"]
    assert update.upgrade_command("pipx", on_pypi=False)[:3] == ["pipx", "install", "--force"]
    assert update.SOURCE in update.upgrade_command("pip", on_pypi=False)
    assert "hemlock-scan" in update.upgrade_command("pip", on_pypi=True)
    assert update.upgrade_command("git", on_pypi=True, root="/r")[:3] == ["git", "-C", "/r"]


def _offer(monkeypatch, version, ran):
    monkeypatch.setattr("hemlock.http.Http", lambda *a, **k: FakeHttp(
        {update.TAGS: [{"name": version}]}))
    monkeypatch.setattr("hemlock.update.run", lambda cmd: ran.append(cmd) or 0)


def test_update_says_nothing_to_do_when_it_is_current(monkeypatch, capsys):
    ran = []
    _offer(monkeypatch, "v0.0.1", ran)
    assert cli.main(["update", "--color", "never"]) == 0
    assert "up to date" in capsys.readouterr().out
    assert ran == []


def test_update_shows_the_command_and_installs_nothing_under_check(monkeypatch, capsys):
    ran = []
    _offer(monkeypatch, "v99.0.0", ran)
    assert cli.main(["update", "--check", "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "update available" in out and "v99.0.0" in out
    assert ran == [], "--check must never install"


def test_update_does_not_install_unattended(monkeypatch, capsys):
    """A scanner whose whole argument is that running somebody else's install
    step is the risk does not get to make an exception for its own. Without a
    terminal to say yes at, it prints the command and stops."""
    ran = []
    _offer(monkeypatch, "v99.0.0", ran)
    monkeypatch.setattr("sys.stdin", type("NoTty", (), {"isatty": lambda self: False})())
    assert cli.main(["update", "--color", "never"]) == 0
    assert ran == [], "installed without consent"
    assert "--yes" in capsys.readouterr().out


def test_update_installs_when_told_to(monkeypatch, capsys):
    ran = []
    _offer(monkeypatch, "v99.0.0", ran)
    assert cli.main(["update", "--yes", "--color", "never"]) == 0
    assert len(ran) == 1


def test_the_update_flag_is_the_same_as_the_subcommand(monkeypatch, capsys):
    ran = []
    _offer(monkeypatch, "v0.0.1", ran)
    assert cli.main(["--update"]) == 0
    assert "up to date" in capsys.readouterr().out
