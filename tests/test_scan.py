"""End-to-end: scoring, policy, and the shipped fixture.

The fixture under examples/compromised-app is inert but is shaped like a real
compromise, so it doubles as the regression test for detection.
"""

import json
import os

import pytest

from hemlock import cli, scan
from hemlock import report as fmt
from hemlock.model import RULES, Finding, Package
from hemlock.policy import Policy, PolicyError, load
from hemlock.score import score_package

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "compromised-app")


@pytest.fixture(scope="module")
def result():
    return scan.run(os.path.abspath(FIXTURE), Policy())


def rules_for(result, name):
    for v in result.verdicts:
        if v.package.name == name:
            return {f.rule.id for f in v.findings}
    raise AssertionError(f"{name} was not scanned")


# -- detection -------------------------------------------------------------


def test_finds_every_planted_package(result):
    flagged = {v.package.name for v in result.flagged}
    assert {"colorz", "analytics-helper", "types-node", "express-js", "сhalk"} <= flagged


def test_credential_stealing_postinstall(result):
    assert {"HEM201", "HEM202", "HEM204", "HEM101"} <= rules_for(result, "colorz")


def test_obfuscated_package(result):
    assert {"HEM203", "HEM301", "HEM302", "HEM404"} <= rules_for(result, "analytics-helper")


def test_homoglyph_package(result):
    assert "HEM103" in rules_for(result, "сhalk")


def test_plain_http_resolution(result):
    assert {"HEM403", "HEM104"} <= rules_for(result, "types-node")


def test_extra_index_is_reported_against_the_file(result):
    files = [v for v in result.flagged if v.package.kind == "manifest"]
    assert [f.rule.id for v in files for f in v.findings] == ["HEM405"]


def test_a_clean_package_stays_clean(result):
    assert rules_for(result, "express") == set()
    assert rules_for(result, "requests") == set()


def test_severity_ordering_is_sane(result):
    by_name = {v.package.name: v for v in result.verdicts}
    assert by_name["colorz"].severity == "critical"
    assert by_name["colorz"].score > by_name["types-node"].score
    assert by_name["types-node"].score > by_name["express-js"].score
    assert result.verdicts == sorted(result.verdicts, key=lambda v: (-v.score, v.package.name))


def test_online_rules_do_not_run_offline(result):
    assert not any(f.rule.online for v in result.verdicts for f in v.findings)


# -- scoring ---------------------------------------------------------------


def make_findings(*rule_ids):
    pkg = Package("npm", "x", version="1.0.0")
    return pkg, [Finding(RULES[r], pkg, ["evidence"]) for r in rule_ids]


def test_no_findings_scores_zero():
    pkg, _ = make_findings()
    assert score_package(pkg, []).score == 0
    assert score_package(pkg, []).severity == "clean"


def test_repeat_findings_in_one_category_have_diminishing_value():
    pkg, one = make_findings("HEM202")  # 45
    pkg, two = make_findings("HEM202", "HEM201")  # 45 + 0.4*18
    assert score_package(pkg, one).score == 45
    assert score_package(pkg, two).score == 52


def test_agreement_across_categories_is_worth_more():
    pkg, same = make_findings("HEM202", "HEM201")
    pkg, mixed = make_findings("HEM202", "HEM101")
    # 45 + 30 = 75, x1.25 for two categories
    assert score_package(pkg, mixed).score == 94
    assert score_package(pkg, mixed).score > score_package(pkg, same).score


def test_score_is_capped_at_100():
    pkg, many = make_findings("HEM204", "HEM202", "HEM101", "HEM301", "HEM403")
    v = score_package(pkg, many)
    assert v.score == 100
    assert v.base > 100
    assert "capped" in __import__("hemlock.score", fromlist=["arithmetic"]).arithmetic(v)


def test_arithmetic_names_every_category():
    pkg, mixed = make_findings("HEM202", "HEM101")
    from hemlock.score import arithmetic

    line = arithmetic(score_package(pkg, mixed))
    assert "install 45" in line and "naming 30" in line
    assert line.endswith("94")


def test_arithmetic_has_an_ascii_form():
    pkg, mixed = make_findings("HEM202", "HEM101")
    from hemlock.score import arithmetic

    line = arithmetic(score_package(pkg, mixed), unicode=False)
    assert "×" not in line and "→" not in line
    assert "x1.25" in line and "->" in line


# -- the terminal view -----------------------------------------------------


def test_headline_names_the_worst_finding(result):
    assert fmt.headline(result) == "1 package reads credentials from an install script."


def test_headline_agrees_with_its_count():
    pkg = Package("npm", "one", version="1.0")
    empty = scan.Report(root=".", packages=[pkg], verdicts=[score_package(pkg, [])])
    assert fmt.headline(empty) is None

    _, findings = make_findings("HEM101")
    one = scan.Report(root=".", packages=[pkg], verdicts=[score_package(pkg, findings)])
    assert fmt.headline(one).startswith("1 package is a keystroke")


def test_ascii_terminal_output_has_no_box_drawing(result, monkeypatch):
    """Asserted against the glyph table rather than a hand-written string, so
    a new box-drawing character joins the check the moment it is added."""
    monkeypatch.setattr("hemlock.ui.glyphs", lambda: fmt.ASCII)
    text = fmt.terminal(result, fmt.Ink(False))
    assert not set(text) & set("".join(fmt.UNICODE.values()))
    assert "colorz" in text and "HEM204" in text


def test_summary_bar_never_exceeds_its_span(result):
    bar = fmt._summary(result, fmt.Ink(False), fmt.UNICODE, span=18)
    blocks = sum(bar.count(c) for c in (fmt.UNICODE["on"], fmt.UNICODE["off"]))
    assert blocks == 18


# -- policy ----------------------------------------------------------------


def test_suppression_by_rule_and_package(tmp_path):
    (tmp_path / ".hemlock.toml").write_text(
        '[[ignore]]\nrule = "HEM201"\npackage = "colorz"\nreason = "reviewed"\n'
    )
    pol = load(str(tmp_path))
    assert pol.suppresses("HEM201", "colorz")
    assert not pol.suppresses("HEM201", "other")
    assert not pol.suppresses("HEM202", "colorz")


def test_glob_suppression(tmp_path):
    (tmp_path / ".hemlock.toml").write_text('[[ignore]]\nrule = "HEM4*"\nreason = "internal mirror"\n')
    pol = load(str(tmp_path))
    assert pol.suppresses("HEM402", "anything")
    assert not pol.suppresses("HEM101", "anything")


def test_expired_suppression_stops_working(tmp_path):
    (tmp_path / ".hemlock.toml").write_text(
        '[[ignore]]\nrule = "HEM201"\nreason = "temporary"\nexpires = "2020-01-01"\n'
    )
    pol = load(str(tmp_path))
    assert not pol.suppresses("HEM201", "colorz")
    assert len(pol.expired) == 1


def test_disable_removes_a_rule_entirely():
    pol = Policy(disable={"HEM201", "HEM202", "HEM204"})
    result = scan.run(os.path.abspath(FIXTURE), pol)
    assert not (rules_for(result, "colorz") & {"HEM201", "HEM202", "HEM204"})


def test_suppressed_findings_are_counted(tmp_path):
    (tmp_path / ".hemlock.toml").write_text('[[ignore]]\nrule = "HEM201"\nreason = "known"\n')
    pol = load(str(tmp_path))
    result = scan.run(os.path.abspath(FIXTURE), pol)
    assert result.suppressed >= 2
    assert "HEM201" not in rules_for(result, "colorz")


def test_missing_config_is_fine(tmp_path):
    assert load(str(tmp_path)).fail_on == "high"


@pytest.mark.parametrize("text", [
    "fail_on = 'urgent'\n",
    "fresh_days = -1\n",
    "disable = 'HEM201'\n",
    "[[ignore]]\nexpires = 'tomorrow'\n",
    "not valid toml =\n",
])
def test_invalid_policy_is_rejected_with_a_clear_error(tmp_path, text):
    (tmp_path / ".hemlock.toml").write_text(text)
    with pytest.raises(PolicyError):
        load(str(tmp_path))


def test_cli_reports_a_bad_policy_without_a_traceback(tmp_path, capsys):
    (tmp_path / ".hemlock.toml").write_text("fail_on = 'urgent'\n")
    assert cli.main(["scan", str(tmp_path), "--color", "never"]) == 2
    assert "fail_on must be one of" in capsys.readouterr().err


# -- output and exit codes -------------------------------------------------


def test_json_round_trips(result):
    doc = json.loads(fmt.as_json(result))
    assert doc["summary"]["critical"] >= 1
    assert doc["results"][0]["scoring"]["categories"]


def test_sarif_is_well_formed(result):
    doc = json.loads(fmt.as_sarif(result))
    run = doc["runs"][0]
    assert doc["version"] == "2.1.0"
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert declared and all(r["ruleId"] in declared for r in run["results"])
    assert all(r["level"] in {"error", "warning", "note"} for r in run["results"])


def test_terminal_output_shows_evidence_and_arithmetic(result):
    text = fmt.terminal(result, fmt.Ink(False))
    assert "colorz" in text and "HEM204" in text
    assert "categories agree" in text
    assert "\033[" not in text  # colour off means no escapes


@pytest.mark.parametrize(
    "args,expected",
    [
        (["scan", FIXTURE, "--format", "json"], 1),
        (["scan", FIXTURE, "--format", "json", "--fail-on", "never"], 0),
        (["scan", FIXTURE, "--format", "json", "--fail-on", "critical"], 1),
        (["explain", "HEM502"], 0),
        (["explain", "NOPE"], 2),
        (["rules"], 0),
    ],
)
def test_exit_codes(args, expected, capsys):
    assert cli.main(args) == expected


def test_scan_of_an_empty_tree_is_clean(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path), "--format", "json"]) == 0


def test_every_rule_has_an_explanation():
    for rule in RULES.values():
        assert len(rule.explain) > 200, rule.id
        assert rule.explain.strip() == rule.explain


def test_rule_counts_match_the_readme():
    """The README quotes these numbers. Adding a rule should force an edit."""
    readme = open(os.path.join(os.path.dirname(__file__), "..", "README.md")).read()
    offline = [r for r in RULES.values() if not r.online]
    assert (len(RULES), len(offline)) == (26, 15)
    assert "The 26 rules" in readme and "Fifteen rules run offline" in readme


def test_only_reported_facts_are_certain():
    """`certain` skips the scoring entirely, so it stays reserved for rules
    that repeat someone else's published analysis rather than infer."""
    assert {r.id for r in RULES.values() if r.certain} == {"HEM701"}


def test_a_certain_finding_settles_the_verdict_alone():
    pkg, findings = make_findings("HEM701")
    v = score_package(pkg, findings)
    assert v.score == 100 and v.certain and v.severity == "critical"

    # It also overrides arithmetic that would otherwise total far less.
    pkg, mixed = make_findings("HEM701", "HEM401")
    assert score_package(pkg, mixed).score == 100


def test_certain_findings_sort_first():
    pkg, mixed = make_findings("HEM401", "HEM701")
    assert score_package(pkg, mixed).findings[0].rule.id == "HEM701"


# -- hemlock check ---------------------------------------------------------


@pytest.mark.parametrize("text, ecosystem, name, version", [
    ("chalk@5.6.1", "npm", "chalk", "5.6.1"),
    ("chalk", "npm", "chalk", None),
    ("@types/node@20.1.0", "npm", "@types/node", "20.1.0"),
    ("@types/node", "npm", "@types/node", None),
    ("pypi:requests==2.32.3", "pypi", "requests", "2.32.3"),
    ("pypi:django@5.0", "pypi", "django", "5.0"),
    ("npm:lodash", "npm", "lodash", None),
])
def test_a_package_spec_parses(text, ecosystem, name, version):
    """The scoped-name case is the one that bites: `@types/node` opens with
    the same character that separates a version, so only a later one counts."""
    pkg = scan.parse_spec(text)
    assert (pkg.ecosystem, pkg.name, pkg.version) == (ecosystem, name, version)


def test_an_unprefixed_name_follows_the_ecosystem_flag():
    assert scan.parse_spec("requests", default="pypi").ecosystem == "pypi"
    assert scan.parse_spec("npm:chalk", default="pypi").ecosystem == "npm"


def test_check_judges_a_name_with_no_project_around_it():
    report = scan.check([scan.parse_spec("colorz")], Policy())
    assert [f.rule.id for v in report.flagged for f in v.findings] == ["HEM101"]


def test_check_says_what_it_could_not_look_at():
    """Offline, a bare name only reaches the naming rules. A report that does
    not say so is claiming more than it found."""
    report = scan.check([scan.parse_spec("colorz")], Policy())
    assert "no install scripts" in report.scope
    assert "--online" in report.scope


def test_check_lists_the_packages_it_was_asked_about_even_when_clean(capsys):
    assert cli.main(["check", "lodash", "colorz", "--color", "never", "--no-logo"]) == 0
    out = capsys.readouterr().out
    assert "lodash" in out and "clean" in out
    assert "colorz" in out


def test_check_reports_no_manifests_rather_than_zero_of_them(capsys):
    """`0 manifests` in the header of a report about one package name reads
    as a failure to find it."""
    cli.main(["check", "lodash", "--color", "never", "--no-logo"])
    assert "manifest" not in capsys.readouterr().out


def test_check_exits_non_zero_at_the_threshold(capsys):
    assert cli.main(["check", "colorz", "--fail-on", "medium", "--color", "never", "--no-logo"]) == 1
    assert cli.main(["check", "colorz", "--fail-on", "high", "--color", "never", "--no-logo"]) == 0


def test_check_rejects_an_empty_name(capsys):
    assert cli.main(["check", "npm:", "--color", "never", "--no-logo"]) == 2


def test_check_makes_no_network_call_without_online(monkeypatch):
    """Same guarantee as `scan`. Naming a package is not consent to phone
    a registry about it."""
    import urllib.request

    def forbidden(*a, **k):
        raise AssertionError("check reached the network offline")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    scan.check([scan.parse_spec("colorz"), scan.parse_spec("pypi:requsts")], Policy())
