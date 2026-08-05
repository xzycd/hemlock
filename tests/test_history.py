"""`hemlock history`: what a project used to have installed.

Nothing here touches the network. The osv.dev half runs against the same
`FakeHttp` stub the rest of the online tests use, and the git half runs
against a repository built in a temporary directory, which is the only way to
test history without pinning the tests to this repository's own.
"""

import json
import os
import subprocess
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

from hemlock import cli, history
from hemlock import report as fmt
from hemlock.history import Commit, Snapshot, windows
from tests.test_online import BATCH, VULN, FakeHttp

# -- windows ---------------------------------------------------------------

CHALK_BAD = ("npm", "chalk", "5.6.1")
CHALK_OK = ("npm", "chalk", "5.3.0")


def at(day: int, sha: str = "", subject: str = "") -> Commit:
    return Commit(sha or f"{day:040d}", datetime(2026, 1, day, tzinfo=UTC), subject or f"commit {day}")


def shots(*rows) -> list[Snapshot]:
    return [Snapshot(at(day), set(coords)) for day, coords in rows]


def test_a_version_that_arrives_and_leaves_is_one_window():
    found = windows(shots(
        (1, [CHALK_OK]),
        (2, [CHALK_BAD]),
        (3, [CHALK_OK]),
    ))
    bad = [w for w in found if w.version == "5.6.1"]
    assert len(bad) == 1
    assert bad[0].entered.when.day == 2 and bad[0].left.when.day == 3
    assert bad[0].bounded, "it arrived inside the history we read, so the date is exact"
    assert not bad[0].open


def test_a_version_that_comes_back_is_two_windows():
    """Two exposures are two things to answer for. Collapsing them into one
    span would report a gap in the middle as time spent exposed."""
    found = [w for w in windows(shots(
        (1, [CHALK_BAD]),
        (2, [CHALK_OK]),
        (3, [CHALK_BAD]),
        (4, [CHALK_BAD]),
    )) if w.version == "5.6.1"]

    assert len(found) == 2
    assert [w.entered.when.day for w in found] == [1, 3]
    assert found[1].open, "the second one is still there at HEAD"
    assert found[1].commits == 2


def test_the_oldest_commit_read_can_only_say_at_or_before():
    """Something already present in the first commit we looked at entered
    somewhere we did not look. Reporting that date as the arrival is a lie
    that gets shorter the more history you skip."""
    found = windows(shots((1, [CHALK_OK]), (2, [CHALK_OK])))
    assert found[0].bounded is False


def test_an_empty_history_has_no_windows():
    assert windows([]) == []


# -- git -------------------------------------------------------------------


def lockfile(version: str) -> str:
    return json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/chalk": {
                "version": version,
                "resolved": f"https://registry.npmjs.org/chalk/-/chalk-{version}.tgz",
                "integrity": "sha512-x",
            },
        },
    })


@pytest.fixture
def repo(tmp_path):
    """A project whose lockfile took a bad version and then dropped it."""
    def git(*args, when=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        if when:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                       capture_output=True, env=env)

    git("init", "-q")
    for version, when, message in (
        ("5.3.0", "2025-01-04T10:00:00+00:00", "add chalk"),
        ("5.6.1", "2025-09-08T09:00:00+00:00", "bump dependencies"),
        ("5.3.0", "2025-09-14T16:00:00+00:00", "pin chalk back"),
    ):
        (tmp_path / "package-lock.json").write_text(lockfile(version))
        git("add", "-A")
        git("commit", "-qm", message, when=when)
    return tmp_path


def test_commits_come_back_oldest_first_with_their_subjects(repo):
    found, truncated = history.commits_touching(str(repo), ["package-lock.json"])
    assert [c.subject for c in found] == ["add chalk", "bump dependencies", "pin chalk back"]
    assert not truncated
    assert found[0].when < found[-1].when


def test_the_limit_truncates_and_says_it_did(repo):
    found, truncated = history.commits_touching(str(repo), ["package-lock.json"], limit=2)
    assert truncated
    assert [c.subject for c in found] == ["bump dependencies", "pin chalk back"], "newest kept"


def test_blobs_reads_every_version_in_one_git_process(repo):
    found, _ = history.commits_touching(str(repo), ["package-lock.json"])
    specs = [f"{c.sha}:package-lock.json" for c in found]
    specs.append(f"{found[0].sha}:never-existed.json")

    blobs = history.blobs(str(repo), specs)
    assert len(blobs) == 3, "the missing path is skipped, the rest still line up"
    assert b'"5.6.1"' in blobs[specs[1]]
    assert b'"5.3.0"' in blobs[specs[2]], "a missing object must not shift the ones after it"


def test_blobs_of_nothing_asks_git_nothing(repo):
    assert history.blobs(str(repo), []) == {}


# -- the command -----------------------------------------------------------


def osv_stub(monkeypatch, malicious=("chalk", "5.6.1")):
    def answers(payload):
        return {"results": [
            {"vulns": [{"id": "MAL-2025-46969"}]}
            if (q["package"]["name"], q["version"]) == malicious else {}
            for q in payload["queries"]
        ]}

    docs = {BATCH: answers, VULN + "MAL-2025-46969": {"summary": "Malicious code in chalk (npm)"}}
    stub = FakeHttp(docs)
    monkeypatch.setattr("hemlock.http.Http", lambda *a, **k: stub)
    return stub


def test_a_clean_working_tree_can_still_have_a_dirty_history(repo, monkeypatch):
    """The whole point of the command. `scan` reads HEAD, where chalk is 5.3.0
    and nothing is wrong. The build that installed 5.6.1 still happened."""
    osv_stub(monkeypatch)
    report = history.run(str(repo), online=True)

    assert [w.coord for w in report.exposed] == ["chalk@5.6.1"]
    window = report.exposed[0]
    assert window.entered.subject == "bump dependencies"
    assert window.left.subject == "pin chalk back"
    assert 5.9 < window.days < 6.5, "six days between the two commits"
    assert not window.open, "it is not in the lockfile now, which is why a scan says clean"


def test_the_report_names_the_commits_that_opened_and_closed_it(repo, monkeypatch):
    osv_stub(monkeypatch)
    text = fmt.terminal_history(history.run(str(repo), online=True), fmt.Ink(False))

    assert "EXPOSED" in text and "chalk 5.6.1" in text
    assert "6 days" in text
    assert "bump dependencies" in text and "pin chalk back" in text
    assert "MAL-2025-46969" in text
    assert "Rotate every credential" in text
    assert "\033[" not in text


def test_nothing_found_says_what_was_actually_checked(repo, monkeypatch):
    osv_stub(monkeypatch, malicious=("nothing", "0"))
    report = history.run(str(repo), online=True)
    text = fmt.terminal_history(report, fmt.Ink(False))

    assert not report.exposed
    assert "never exposed" in text
    assert str(report.coords) in text and report.coords == 2, "5.3.0 and 5.6.1"


def test_following_one_package_needs_no_network(repo, monkeypatch):
    """The offline half. It answers when a dependency arrived and what it
    replaced, which is a question people have outside an incident."""
    def forbidden(*args, **kwargs):
        raise AssertionError("history --package tried to reach the network")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    report = history.run(str(repo), package="chalk")

    assert [(w.version, w.open) for w in report.windows] == [
        ("5.3.0", False), ("5.6.1", False), ("5.3.0", True),
    ]
    text = fmt.terminal_history(report, fmt.Ink(False))
    assert "3 spans" in text and "2 versions of chalk" in text


def test_following_a_package_online_still_shows_the_record_behind_a_red_row(repo, monkeypatch):
    osv_stub(monkeypatch)
    text = fmt.terminal_history(history.run(str(repo), package="chalk", online=True), fmt.Ink(False))

    assert "5.4.0" not in text and "5.6.1" in text, "the timeline is still the timeline"
    assert "MAL-2025-46969" in text, "a red row with no record behind it is not an answer"
    assert "Rotate every credential" in text


def test_a_shallow_clone_is_called_out_rather_than_reported_as_a_short_history(repo, tmp_path):
    """CI checkouts are shallow by default, and a shallow clone looks exactly
    like a project that has barely changed. Saying "never exposed" about fifty
    commits somebody fetched by accident is the one thing this cannot do."""
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
                   check=True, capture_output=True)
    report = history.run(str(shallow))
    assert any("shallow" in w for w in report.warnings)
    assert "shallow clone" in fmt.terminal_history(report, fmt.Ink(False))


def test_a_full_clone_says_nothing_about_shallowness(repo):
    assert history.run(str(repo)).warnings == []


def test_a_name_nobody_ever_pinned_says_so(repo):
    report = history.run(str(repo), package="left-pad")
    assert report.windows == []
    assert "nothing matching" in fmt.terminal_history(report, fmt.Ink(False))


def test_the_axis_runs_to_today_so_a_current_version_is_not_a_sliver(repo):
    report = history.run(str(repo), package="chalk")
    first, last = report.axis
    assert last >= datetime.now(UTC) - timedelta(seconds=5)
    assert report.span[1] < last, "the newest commit is older than today"


def tag(repo, name, sha="HEAD"):
    subprocess.run(["git", "-C", str(repo), "tag", name, sha], check=True, capture_output=True)


def test_releases_cut_while_it_was_in_the_tree_are_named(repo, monkeypatch):
    """"Exposed for six days" is a fact about a lockfile. "You shipped v1.4.0
    during those six days" is the version somebody has to act on."""
    osv_stub(monkeypatch)
    found, _ = history.commits_touching(str(repo), ["package-lock.json"])
    tag(repo, "v1.3.0", found[0].sha)   # before it arrived
    tag(repo, "v1.4.0", found[1].sha)   # cut with it in the tree
    tag(repo, "v1.4.1", found[2].sha)   # cut from the commit that removed it

    window = history.run(str(repo), online=True).exposed[0]
    assert window.tags == ["v1.4.0"]

    text = fmt.terminal_history(history.run(str(repo), online=True), fmt.Ink(False))
    assert "shipped v1.4.0" in text and "1 tag cut while it was in the tree" in text


def test_a_window_still_open_counts_every_release_since(repo, monkeypatch):
    osv_stub(monkeypatch, malicious=("chalk", "5.3.0"))
    found, _ = history.commits_touching(str(repo), ["package-lock.json"])
    tag(repo, "v2.0.0", found[2].sha)

    still_open = [w for w in history.run(str(repo), online=True).exposed if w.open]
    assert still_open and still_open[0].tags == ["v2.0.0"]


def test_tags_are_only_looked_up_where_they_change_what_you_do(repo, monkeypatch):
    """An advisory on a version you dropped is not a recall, so the release
    list would be noise. Malware is the case that needs it."""
    osv_stub(monkeypatch, malicious=("nothing", "0"))
    tag(repo, "v1.0.0")
    report = history.run(str(repo), package="chalk")
    assert all(not w.tags for w in report.windows)


def test_json_carries_the_window_and_the_commits(repo, monkeypatch):
    osv_stub(monkeypatch)
    payload = json.loads(fmt.as_json_history(history.run(str(repo), online=True)))

    assert payload["mode"] == "history"
    assert payload["summary"]["exposed"] == 1
    window = next(w for w in payload["windows"] if w["version"] == "5.6.1")
    assert window["malware"] == ["MAL-2025-46969"]
    assert window["entered"]["subject"] == "bump dependencies"
    assert window["left"]["sha"] and window["still_present"] is False


# -- the cli ---------------------------------------------------------------


def test_exposure_fails_the_build_and_can_be_told_not_to(repo, monkeypatch, capsys):
    osv_stub(monkeypatch)
    assert cli.main(["history", str(repo), "--online", "--format", "json"]) == 1
    assert cli.main(["history", str(repo), "--online", "--format", "json", "--fail-on", "never"]) == 0


def test_a_history_with_nothing_in_it_passes(repo, monkeypatch):
    osv_stub(monkeypatch, malicious=("nothing", "0"))
    assert cli.main(["history", str(repo), "--online", "--format", "json"]) == 0


def test_history_outside_a_repository_says_so(tmp_path, capsys):
    (tmp_path / "package-lock.json").write_text(lockfile("5.3.0"))
    assert cli.main(["history", str(tmp_path), "--color", "never"]) == 2
    assert "not inside a git repository" in capsys.readouterr().err


def test_a_repository_with_no_manifests_is_not_an_error(tmp_path, capsys):
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True, capture_output=True)
    assert cli.main(["history", str(tmp_path), "--color", "never"]) == 0
    assert "no npm or Python manifests" in capsys.readouterr().out
