"""hemlock diff: what a change lets in."""

import json
import os
import subprocess

import pytest

from hemlock import cli, diff
from hemlock import report as fmt
from hemlock.model import Package
from hemlock.policy import Policy


def pkg(name, version, ecosystem="npm"):
    return Package(ecosystem, name, version=version)


# -- comparison ------------------------------------------------------------


def test_added_updated_removed_and_unchanged():
    base = [pkg("a", "1.0.0"), pkg("b", "1.0.0"), pkg("gone", "1.0.0")]
    head = [pkg("a", "1.0.0"), pkg("b", "2.0.0"), pkg("new", "1.0.0")]
    changes, removed, unchanged = diff.compare(base, head)

    by_name = {c.package.name: c for c in changes}
    assert by_name["new"].kind == "added" and by_name["new"].was is None
    assert by_name["b"].kind == "updated" and by_name["b"].was == "1.0.0"
    assert [p.name for p in removed] == ["gone"]
    assert unchanged == 1
    assert "a" not in by_name


def test_the_same_name_in_two_ecosystems_is_two_packages():
    base = [pkg("redis", "1.0.0", "npm")]
    head = [pkg("redis", "1.0.0", "npm"), pkg("redis", "5.0.0", "pypi")]
    changes, removed, unchanged = diff.compare(base, head)
    assert [(c.package.ecosystem, c.kind) for c in changes] == [("pypi", "added")]
    assert unchanged == 1 and removed == []


def test_manifest_entries_are_not_treated_as_dependencies():
    base = []
    head = [Package("pypi", "requirements.txt", kind="manifest"), pkg("flask", "3.0.0", "pypi")]
    changes, _, _ = diff.compare(base, head)
    assert [c.package.name for c in changes] == ["flask"]


def test_a_spec_change_without_a_version_still_counts():
    base = [Package("npm", "react", spec="^18.0.0")]
    head = [Package("npm", "react", spec="^19.0.0")]
    changes, _, _ = diff.compare(base, head)
    assert changes[0].kind == "updated" and changes[0].was == "^18.0.0"


# -- scoring the change ----------------------------------------------------


def test_only_the_change_gets_scored():
    base = [pkg("colorz", "1.0.4"), pkg("express", "4.18.2")]
    head = [pkg("colorz", "1.0.4"), pkg("requsts", "2.28.0", "pypi")]
    report = diff.run(base, head, Policy(), root=".")

    scanned = {v.package.name for v in report.verdicts}
    assert scanned == {"requsts"}  # colorz was already there and is not this PR's problem
    assert report.unchanged == 1
    assert any(f.rule.id == "HEM101" for v in report.flagged for f in v.findings)


def test_nothing_new_means_nothing_to_report():
    same = [pkg("express", "4.18.2")]
    report = diff.run(same, list(same), Policy(), root=".")
    assert report.changes == [] and report.flagged == []
    assert "no dependencies were added or moved" in fmt.terminal_diff(report, fmt.Ink(False))


# -- rendering -------------------------------------------------------------


def test_terminal_diff_marks_each_kind_of_change():
    base = [pkg("express", "4.18.2"), pkg("gone", "1.0.0")]
    head = [pkg("express", "4.18.2"), pkg("colorz", "1.0.4"), pkg("chalk", "5.6.1")]
    report = diff.run(base, head, Policy(), root=".", labels=("HEAD~1", "working tree"))
    text = fmt.terminal_diff(report, fmt.Ink(False))

    assert "HEAD~1" in text and "working tree" in text
    assert "+  npm   colorz" in text
    assert "-  npm   gone" in text
    assert "removed" in text


def test_updated_rows_show_the_previous_version():
    base = [pkg("chalk", "5.6.0")]
    head = [pkg("chalk", "5.6.1")]
    report = diff.run(base, head, Policy(), root=".")
    assert "(was 5.6.0)" in fmt.terminal_diff(report, fmt.Ink(False))


def test_diff_json_carries_the_change_kind():
    base = [pkg("express", "4.18.2")]
    head = [pkg("express", "4.18.2"), pkg("colorz", "1.0.4")]
    doc = json.loads(fmt.as_json_diff(diff.run(base, head, Policy(), root=".")))

    assert doc["mode"] == "diff"
    assert doc["summary"]["changed"] == 1 and doc["summary"]["unchanged"] == 1
    assert doc["results"][0]["change"] == "added"


# -- git and file plumbing -------------------------------------------------


def test_parser_is_chosen_by_filename():
    from hemlock import npm as npm_mod
    from hemlock import pypi as pypi_mod

    assert diff.parser_for("/x/package-lock.json") is npm_mod
    assert diff.parser_for("/x/yarn.lock") is npm_mod
    assert diff.parser_for("/x/poetry.lock") is pypi_mod
    assert diff.parser_for("/x/requirements-dev.txt") is pypi_mod
    assert diff.parser_for("/x/README.md") is None


@pytest.fixture
def repo(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True,
                       capture_output=True, env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"})

    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"express": "4.18.2"}},
                     "node_modules/express": {"version": "4.18.2", "integrity": "sha512-x"}},
    }))
    git("init", "-q")
    git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
    return tmp_path


def test_reads_a_manifest_from_a_git_ref(repo):
    base = diff.from_git("HEAD", str(repo / "package-lock.json"), str(repo))
    assert [p.name for p in base] == ["express"]


def test_a_file_that_did_not_exist_at_that_ref_is_all_new(repo):
    assert diff.from_git("HEAD", str(repo / "never-existed.json"), str(repo)) == []


def test_git_root_is_found_and_absent_outside_a_repo(repo, tmp_path):
    assert diff.git_root(str(repo)) == str(repo.resolve())


def test_since_requires_a_git_repository(tmp_path, capsys):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
    assert cli.main(["diff", "--since", "HEAD", "--path", str(tmp_path)]) == 2
    assert "not inside a git repository" in capsys.readouterr().err


def test_diff_end_to_end_through_the_cli(repo, capsys):
    lock = repo / "package-lock.json"
    lock.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"colorz": "1.0.4"}},
                     "node_modules/colorz": {"version": "1.0.4"}},
    }))
    code = cli.main(["diff", "--since", "HEAD", "--path", str(repo), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)

    assert code == 1  # colorz is a near-miss of colors, which is high
    assert doc["results"][0]["name"] == "colorz"
    assert doc["results"][0]["change"] == "added"
    assert doc["removed"] == [{"ecosystem": "npm", "name": "express"}]


def test_two_manifests_or_since_but_not_both(capsys):
    assert cli.main(["diff", "a.json", "--since", "HEAD"]) == 2
    assert "not both" in capsys.readouterr().err


def test_a_single_manifest_is_not_a_diff(capsys):
    assert cli.main(["diff", "only-one.json"]) == 2
    assert "two manifests" in capsys.readouterr().err


def test_non_manifest_files_are_rejected(tmp_path, capsys):
    a, b = tmp_path / "a.md", tmp_path / "b.md"
    a.write_text("x")
    b.write_text("y")
    assert cli.main(["diff", str(a), str(b)]) == 2
    assert "not a manifest" in capsys.readouterr().err
