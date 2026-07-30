"""Baselines, the wordmark, and the commands built on top of them."""

import json
import os
import shutil

import pytest

from hemlock import baseline as baseline_mod
from hemlock import brand, cli, scan
from hemlock import report as fmt
from hemlock.model import RULES, Finding, Package
from hemlock.policy import Policy
from hemlock.score import score_package

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "compromised-app")


@pytest.fixture
def project(tmp_path):
    dest = tmp_path / "app"
    shutil.copytree(os.path.abspath(FIXTURE), dest)
    return str(dest)


# -- baseline --------------------------------------------------------------


def test_a_baseline_hides_what_it_accepted(project):
    before = scan.run(project, Policy())
    assert before.flagged

    _, count = baseline_mod.write(before, project)
    assert count > 0

    after = scan.run(project, Policy())
    baseline_mod.apply(after, baseline_mod.load(project))
    assert after.flagged == []
    assert after.baselined == count


def test_a_new_finding_still_gets_through(project):
    baseline_mod.write(scan.run(project, Policy()), project)

    lock = os.path.join(project, "package-lock.json")
    doc = json.load(open(lock))
    doc["packages"]["node_modules/reqeusts"] = {"version": "1.0.0"}
    json.dump(doc, open(lock, "w"))

    after = scan.run(project, Policy())
    baseline_mod.apply(after, baseline_mod.load(project))
    assert [v.package.name for v in after.flagged] == ["reqeusts"]


def test_a_version_bump_re_raises_everything_about_a_package(project):
    """Accepting a finding accepts it for the version we saw. The release that
    lands tomorrow has not been reviewed by anyone."""
    baseline_mod.write(scan.run(project, Policy()), project)

    lock = os.path.join(project, "package-lock.json")
    doc = json.load(open(lock))
    doc["packages"]["node_modules/colorz"]["version"] = "1.0.5"
    json.dump(doc, open(lock, "w"))

    after = scan.run(project, Policy())
    baseline_mod.apply(after, baseline_mod.load(project))
    assert "colorz" in {v.package.name for v in after.flagged}


def test_a_package_is_rescored_on_what_is_left(project):
    """One new finding beside four accepted ones should read as one finding,
    not keep a score built from all five."""
    report = scan.run(project, Policy())
    colorz = next(v for v in report.verdicts if v.package.name == "colorz")
    assert len(colorz.findings) > 1
    full_score = colorz.score

    accepted = {baseline_mod.fingerprint(colorz, f) for f in colorz.findings[1:]}
    baseline_mod.apply(report, baseline_mod.Baseline(accepted=accepted))

    rescored = next(v for v in report.verdicts if v.package.name == "colorz")
    assert len(rescored.findings) == 1
    assert rescored.score < full_score


def test_fingerprints_separate_rule_package_and_version():
    pkg = Package("npm", "colorz", version="1.0.4")
    finding = Finding(RULES["HEM101"], pkg, ["evidence"])
    verdict = score_package(pkg, [finding])
    assert baseline_mod.fingerprint(verdict, finding) == "npm:colorz@1.0.4:HEM101"


def test_an_absent_or_unreadable_baseline_is_just_no_baseline(tmp_path):
    assert baseline_mod.load(str(tmp_path)) is None
    (tmp_path / ".hemlock-baseline.json").write_text("{ not json")
    assert baseline_mod.load(str(tmp_path)) is None


def test_a_baseline_from_a_future_format_is_ignored(tmp_path):
    (tmp_path / ".hemlock-baseline.json").write_text(json.dumps({"format": 99, "accepted": ["x"]}))
    assert baseline_mod.load(str(tmp_path)) is None


def test_the_baseline_file_explains_itself(project):
    path, _ = baseline_mod.write(scan.run(project, Policy()), project)
    doc = json.load(open(path))
    assert doc["format"] == 1 and doc["created"] and "note" in doc
    assert doc["accepted"] == sorted(doc["accepted"])  # stable diffs


def test_scan_applies_a_committed_baseline_without_a_flag(project, capsys):
    cli.main(["baseline", project])
    capsys.readouterr()

    assert cli.main(["scan", project, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["critical"] == 0


def test_ignore_baseline_shows_everything_again(project, capsys):
    cli.main(["baseline", project])
    capsys.readouterr()

    assert cli.main(["scan", project, "--format", "json", "--ignore-baseline", "--fail-on", "never"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["critical"] > 0


# -- why -------------------------------------------------------------------


@pytest.fixture
def nested(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"app-kit": "1.0.0"}},
            "node_modules/app-kit": {"version": "1.0.0", "integrity": "sha512-x",
                                     "dependencies": {"build-tools": "^2.0.0"}},
            "node_modules/build-tools": {"version": "2.1.0", "integrity": "sha512-x",
                                         "dependencies": {"colorz": "^1.0.0"}},
            "node_modules/colorz": {"version": "1.0.4", "integrity": "sha512-x"},
        },
    }))
    return str(tmp_path)


def test_why_shows_the_route_and_the_finding(nested, capsys):
    assert cli.main(["why", "colorz", "--path", nested, "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "app-kit" in out and "build-tools" in out and "colorz" in out
    assert "HEM101" in out and "fix" in out


def test_why_says_when_a_package_was_asked_for_directly(nested, capsys):
    cli.main(["why", "app-kit", "--path", nested, "--color", "never"])
    assert "asked for directly" in capsys.readouterr().out


def test_the_scan_view_shows_the_route_for_transitive_findings(nested):
    report = scan.run(nested, Policy())
    text = fmt.terminal(report, fmt.Ink(False))
    assert "via" in text and "build-tools" in text


def test_why_on_an_unknown_package_is_an_error(nested, capsys):
    assert cli.main(["why", "nonexistent", "--path", nested]) == 2
    assert "no package matching" in capsys.readouterr().err


def test_why_matches_on_a_fragment(nested, capsys):
    assert cli.main(["why", "color", "--path", nested, "--color", "never"]) == 0
    assert "colorz" in capsys.readouterr().out


# -- init ------------------------------------------------------------------


def test_init_writes_a_config_and_a_workflow(tmp_path, capsys):
    assert cli.main(["init", str(tmp_path), "--color", "never"]) == 0
    assert (tmp_path / ".hemlock.toml").is_file()
    assert (tmp_path / ".github" / "workflows" / "hemlock.yml").is_file()
    assert "created" in capsys.readouterr().out


def test_init_never_overwrites(tmp_path, capsys):
    (tmp_path / ".hemlock.toml").write_text("fail_on = 'critical'\n")
    cli.main(["init", str(tmp_path), "--color", "never"])
    assert (tmp_path / ".hemlock.toml").read_text() == "fail_on = 'critical'\n"
    assert "already there" in capsys.readouterr().out


def test_the_generated_config_parses(tmp_path):
    from hemlock.policy import load

    cli.main(["init", str(tmp_path), "--color", "never"])
    assert load(str(tmp_path)).fail_on == "high"


def test_the_generated_workflow_scans_prs_as_diffs(tmp_path):
    cli.main(["init", str(tmp_path), "--color", "never"])
    workflow = (tmp_path / ".github" / "workflows" / "hemlock.yml").read_text()
    assert "hemlock diff --since" in workflow and "hemlock scan ." in workflow


# -- wordmark --------------------------------------------------------------


def test_the_wordmark_spells_hemlock():
    rows = brand.render()
    assert len(rows) == 5
    assert len({len(r) for r in rows}) == 1  # every row the same width
    assert set("".join(rows)) <= {"█", " "}


def test_the_alphabet_covers_the_word_and_nothing_else():
    assert set(brand.GLYPHS) == set("hemlock")


def test_the_logo_renders_without_colour():
    plain = brand.logo(color=False, animate=False)
    assert "\033[" not in plain
    assert brand.TAGLINE in plain


def test_the_logo_carries_a_version_when_given_one():
    assert "v0.3.0" in brand.logo(color=False, animate=False, version="0.3.0")


class NotATty:
    def isatty(self):
        return False

    def write(self, *_):
        pass

    def flush(self):
        pass


def test_animation_stays_off_when_output_is_not_a_terminal():
    assert not brand.wants_animation(color=True, stream=NotATty())


def test_animation_stays_off_under_ci(monkeypatch):
    class Tty(NotATty):
        def isatty(self):
            return True

    monkeypatch.setenv("CI", "true")
    assert not brand.wants_animation(color=True, stream=Tty())


def test_animation_stays_off_without_colour():
    assert not brand.wants_animation(color=False, stream=NotATty())


def test_duration_reads_in_the_right_unit():
    assert fmt.duration(0.005) == "5ms"
    assert fmt.duration(2.5) == "2.5s"
