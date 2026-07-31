"""The view layer: colour depth, gauges, links, panels, and the Markdown report.

Most of these are alignment tests wearing different hats. Terminal output is
built out of padded columns, so anything that changes a string's width without
changing what it looks like on screen is a bug that only shows up in the shape
of the page.
"""

import os
import shutil

import pytest

from hemlock import cli, scan, ui
from hemlock import report as fmt
from hemlock.model import RULES, Finding, Package
from hemlock.policy import Policy
from hemlock.score import score_package

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "examples", "compromised-app")
BOX = set("".join(ui.UNICODE.values()))


@pytest.fixture(scope="module")
def result():
    return scan.run(os.path.abspath(FIXTURE), Policy())


@pytest.fixture
def project(tmp_path):
    dest = tmp_path / "app"
    shutil.copytree(os.path.abspath(FIXTURE), dest)
    return str(dest)


def verdict(rule_id, name="colorz", version="1.0.4", ecosystem="npm", evidence="evidence"):
    pkg = Package(ecosystem, name, version=version, origin="package-lock.json")
    return score_package(pkg, [Finding(RULES[rule_id], pkg, [evidence])])


def report_with(*verdicts, online=False):
    packages = [v.package for v in verdicts]
    return scan.Report(root=".", manifests=["package-lock.json"], packages=packages,
                       verdicts=list(verdicts), online=online)


class Tty:
    def __init__(self, tty=True, encoding="utf-8"):
        self._tty, self.encoding = tty, encoding

    def isatty(self):
        return self._tty


# -- colour depth ----------------------------------------------------------


def test_direct_colour_when_the_terminal_advertises_it(monkeypatch):
    monkeypatch.setenv("COLORTERM", "truecolor")
    assert ui.color_depth("always") == 24


def test_falls_back_to_the_256_palette(monkeypatch):
    monkeypatch.delenv("COLORTERM", raising=False)
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert ui.color_depth("always") == 8


def test_no_colour_when_asked_for_none():
    assert ui.color_depth("never") == 0
    assert not ui.want_color("never")


def test_no_colour_when_output_is_not_a_terminal():
    assert ui.color_depth("auto", Tty(tty=False)) == 0


def test_no_color_env_is_honoured(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.color_depth("auto", Tty()) == 0


def test_an_explicit_flag_beats_the_environment(monkeypatch):
    """--color always is a more specific instruction than an env var someone
    exported months ago."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui.color_depth("always") > 0


def test_a_dumb_terminal_gets_nothing(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    monkeypatch.delenv("COLORTERM", raising=False)
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    assert ui.color_depth("always") == 0


def test_ink_emits_the_right_escape_for_its_depth():
    assert "38;2;" in ui.Ink(24)("x", "accent")
    assert "38;5;" in ui.Ink(8)("x", "accent")
    assert ui.Ink(0)("x", "accent") == "x"


def test_ink_still_takes_a_plain_boolean():
    assert ui.Ink(True).on and not ui.Ink(False).on


def test_an_unknown_style_name_does_not_crash():
    assert ui.Ink(24)("x", "nonsense") == "x\033[0m"


# -- gauges ----------------------------------------------------------------


def test_a_gauge_fills_in_proportion():
    ink = ui.Ink(False)
    assert ui.gauge(100, "critical", ink) == "█" * 10
    assert ui.gauge(50, "medium", ink) == "█" * 5 + "░" * 5
    assert ui.gauge(0, "clean", ink) == "░" * 10


def test_any_finding_at_all_lights_one_cell():
    """A score of 1 that draws an empty bar reads as nothing found."""
    assert ui.gauge(1, "low", ui.Ink(False)).startswith("█")


def test_a_reported_malware_gauge_is_full_regardless_of_score():
    assert ui.gauge(0, "critical", ui.Ink(False), full=True) == "█" * 10


def test_a_gauge_is_always_its_full_span():
    for score in range(0, 101, 7):
        assert len(ui.gauge(score, "high", ui.Ink(False))) == 10


def test_weights_are_drawn_next_to_their_numbers():
    text = fmt.rule_table(ui.Ink(False))
    assert "HEM201" in text and "HEM701" in text
    assert "█" in text


# -- width arithmetic ------------------------------------------------------


def test_colour_codes_do_not_count_towards_width():
    ink = ui.Ink(24)
    assert ui.visible(ink("hello", "accent", "bold")) == 5


def test_hyperlinks_do_not_count_towards_width():
    ink = ui.Ink(24, links=True)
    assert ui.visible(ui.link("chalk", "https://example.invalid", ink)) == 5


def test_result_rows_line_up_whether_or_not_they_carry_links(result):
    """The right-hand severity label is placed by subtracting visible width.
    Get that wrong and every linked row drifts."""
    plain = fmt.terminal(result, ui.Ink(24))
    linked = fmt.terminal(result, ui.Ink(24, links=True))
    assert [ui.visible(x) for x in plain.splitlines()] == \
           [ui.visible(x) for x in linked.splitlines()]


def test_a_badge_takes_the_same_room_with_and_without_colour():
    assert ui.visible(ui.badge("MAL", ui.Ink(0))) == ui.visible(ui.badge("MAL", ui.Ink(24)))


def test_no_line_carries_trailing_whitespace(result):
    text = fmt.terminal(result, ui.Ink(24))
    assert not [line for line in text.splitlines() if line != line.rstrip()]


# -- links -----------------------------------------------------------------


def test_links_are_off_unless_asked_for():
    ink = ui.Ink(24)
    assert ui.link("chalk", "https://example.invalid", ink) == "chalk"


def test_registry_urls_point_at_the_right_index():
    assert ui.registry_url("npm", "chalk", "5.6.1").endswith("/package/chalk/v/5.6.1")
    assert ui.registry_url("npm", "@types/node") .endswith("/package/@types/node")
    assert ui.registry_url("pypi", "requests", "2.32.3").endswith("/project/requests/2.32.3/")
    assert ui.registry_url("cargo", "serde") == ""


def test_advisory_ids_inside_evidence_become_clickable():
    ink = ui.Ink(24, links=True)
    out = ui.linkify("2 advisories: GHSA-qw6h-vgh9-j6wx, MAL-2025-46969", ink)
    assert "osv.dev/vulnerability/GHSA-qw6h-vgh9-j6wx" in out
    assert "osv.dev/vulnerability/MAL-2025-46969" in out


def test_linkify_leaves_ordinary_words_alone():
    ink = ui.Ink(24, links=True)
    assert ui.linkify("no ids here at all", ink) == "no ids here at all"


def test_hyperlinks_stay_out_of_a_redirect():
    assert not ui.wants_links(Tty(tty=False))


# -- panel and rails -------------------------------------------------------


def test_a_panel_is_rectangular():
    lines = ui.panel("MALWARE", [ui.Ink(0)("short"), ui.Ink(0)("a much longer line")],
                     ui.Ink(0), "critical", 60)
    assert len({ui.visible(x) for x in lines}) == 1


def test_the_malware_box_appears_only_for_reported_malware(result):
    assert "MALWARE" not in fmt.terminal(result, ui.Ink(False))
    reported = report_with(verdict("HEM701", name="chalk", version="5.6.1"))
    assert "MALWARE" in fmt.terminal(reported, ui.Ink(False))


# -- the ASCII fallback ----------------------------------------------------


def test_every_view_falls_back_to_ascii(result, monkeypatch, nested):
    monkeypatch.setattr("hemlock.ui.glyphs", lambda: ui.ASCII)
    ink = ui.Ink(False)
    pages = [
        fmt.terminal(result, ink),
        fmt.rule_table(ink),
        fmt.explain(RULES["HEM701"], ink),
        fmt.why(scan.run(nested, Policy()), [(None, Package("npm", "colorz"))], ink),
        fmt.terminal(report_with(verdict("HEM701")), ink),
    ]
    for page in pages:
        assert not set(page) & BOX


def test_the_rail_and_the_branch_stay_apart_in_ascii():
    assert ui.ASCII["rail"] != ui.ASCII["tee"]


# -- the all clear ---------------------------------------------------------


def test_a_clean_offline_scan_says_what_it_did_not_check():
    text = fmt.terminal(report_with(online=False), ui.Ink(False))
    assert "nothing flagged" in text and "--online" in text


def test_a_clean_online_scan_does_not_promise_safety():
    text = fmt.terminal(report_with(online=True), ui.Ink(False))
    assert "nothing flagged" in text
    assert "--online" not in text
    assert "Nothing here matched" in text


def test_counts_of_one_are_not_pluralised():
    text = fmt.terminal(report_with(verdict("HEM101")), ui.Ink(False))
    assert "1 package · 1 manifest ·" in text


# -- routes ----------------------------------------------------------------


@pytest.fixture
def nested(tmp_path):
    import json

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


def test_a_route_is_drawn_as_a_staircase(nested, capsys):
    cli.main(["why", "colorz", "--path", nested, "--color", "never"])
    lines = [x for x in capsys.readouterr().out.splitlines() if x.strip()]
    trail = [x for x in lines if any(n in x for n in ("app-kit", "build-tools", "colorz"))]
    indents = [len(x) - len(x.lstrip()) for x in trail]
    assert indents == sorted(indents)  # each step further in than the last
    assert indents[0] < indents[-1]


# -- crowds ----------------------------------------------------------------


def crowd(rule_id, n, prefix="pkg"):
    return report_with(*[verdict(rule_id, name=f"{prefix}{i}") for i in range(n)])


def test_one_rule_flagging_a_crowd_collapses_into_one_block():
    """Forty unpinned versions is one observation about a project, not forty.
    Printing it forty times is how the finding that failed the build ends up
    in the middle of a scroll."""
    text = fmt.terminal(crowd("HEM401", 20), ui.Ink(False), fail_on="high")
    assert text.count("Version is not pinned") == 1
    assert "20 packages" in text


def test_a_collapsed_group_still_names_every_package():
    text = fmt.terminal(crowd("HEM401", 20), ui.Ink(False), fail_on="high")
    for i in range(20):
        assert f"pkg{i}" in text


def test_a_small_group_is_left_alone():
    small = fmt.CROWD_MIN - 1
    text = fmt.terminal(crowd("HEM401", small), ui.Ink(False), fail_on="high")
    assert text.count("Version is not pinned") == small


def test_nothing_at_the_failing_threshold_is_ever_collapsed():
    """Whatever broke the build gets its own block, however many there are."""
    packages = crowd("HEM101", 7)  # HEM101 scores 30, which is medium
    folded = fmt.terminal(packages, ui.Ink(False), fail_on="high")
    expanded = fmt.terminal(packages, ui.Ink(False), fail_on="medium")
    assert folded.count("near-miss") == 1
    assert expanded.count("near-miss") == 7


def test_critical_is_never_collapsed():
    """A worm hits every package in a lockfile at once, and every one of them
    is a single HEM701. That is the case this guard exists for."""
    packages = crowd("HEM701", 8)
    text = fmt.terminal(packages, ui.Ink(False), fail_on="critical")
    assert text.count("reported as malware") == 8


def test_a_package_with_more_than_one_finding_keeps_its_own_block():
    pkg = Package("npm", "colorz", version="1.0.4", origin="package-lock.json")
    pair = score_package(pkg, [Finding(RULES["HEM401"], pkg, ["e"]),
                               Finding(RULES["HEM402"], pkg, ["e"])])
    text = fmt.terminal(report_with(pair, *crowd("HEM401", 6).verdicts),
                        ui.Ink(False), fail_on="high")
    assert "colorz" in text and "HEM402" in text


# -- the exit line ---------------------------------------------------------


def test_the_exit_line_names_what_failed_the_build():
    text = fmt.terminal(report_with(verdict("HEM701", name="chalk")), ui.Ink(False), fail_on="high")
    assert "exit 1" in text and "chalk" in text and "at high or above" in text


def test_the_exit_line_is_not_drowned_by_findings_that_did_not_cause_it():
    """The whole point: one critical finding among thirty low ones stays
    findable, and the thirty do not each get five lines."""
    quiet = crowd("HEM401", 30).verdicts
    text = fmt.terminal(report_with(verdict("HEM701", name="chalk"), *quiet),
                        ui.Ink(False), fail_on="high")
    assert "exit 1" in text and "chalk" in text
    assert text.count("Version is not pinned") == 1


def test_no_exit_line_when_nothing_reaches_the_threshold():
    text = fmt.terminal(crowd("HEM401", 6), ui.Ink(False), fail_on="high")
    assert "exit 1" not in text


def test_no_exit_line_when_failing_is_switched_off():
    text = fmt.terminal(report_with(verdict("HEM701")), ui.Ink(False), fail_on="never")
    assert "exit 1" not in text


def test_the_exit_line_agrees_with_the_actual_exit_code(project, capsys):
    from hemlock import cli as cli_mod

    code = cli_mod.main(["scan", project, "--color", "never", "--fail-on", "high"])
    out = capsys.readouterr().out
    assert code == 1
    assert ("exit 1" in out) == (code == 1)


# -- markdown --------------------------------------------------------------


def test_markdown_carries_a_marker_so_a_bot_can_find_its_own_comment(result):
    assert fmt.as_markdown(result).startswith(fmt.MARKER)


def test_markdown_lists_a_row_per_flagged_package(result):
    text = fmt.as_markdown(result)
    for v in result.flagged:
        assert v.package.name in text


def test_markdown_raises_a_caution_for_reported_malware():
    text = fmt.as_markdown(report_with(verdict("HEM701", name="chalk", version="5.6.1")))
    assert "[!CAUTION]" in text and "chalk@5.6.1" in text


def test_markdown_warns_but_does_not_shout_for_an_ordinary_finding():
    text = fmt.as_markdown(report_with(verdict("HEM101")))
    assert "[!CAUTION]" not in text
    assert "[!WARNING]" in text or "[!NOTE]" in text


def test_markdown_on_a_clean_scan_still_reports(result):
    text = fmt.as_markdown(report_with())
    assert "[!NOTE]" in text and "Nothing flagged" in text


def test_markdown_links_a_package_to_its_registry_page():
    text = fmt.as_markdown(report_with(verdict("HEM101", name="colorz", version="1.0.4")))
    assert "https://www.npmjs.com/package/colorz/v/1.0.4" in text


def test_markdown_evidence_cannot_break_out_of_its_code_span():
    text = fmt.as_markdown(report_with(verdict("HEM101", evidence="a ` backtick")))
    assert "a ' backtick" in text


def test_a_long_markdown_report_is_capped_and_says_so():
    many = [verdict("HEM101", name=f"pkg{i}") for i in range(fmt.MD_ROWS + 5)]
    text = fmt.as_markdown(report_with(*many))
    assert text.count("| 🟡 |") == fmt.MD_ROWS
    assert "5 more" in text


def test_markdown_diff_shows_what_changed(project, capsys):
    import json

    lock = os.path.join(project, "package-lock.json")
    doc = json.load(open(lock))
    doc["packages"]["node_modules/reqeusts"] = {"version": "1.0.0"}
    json.dump(doc, open(lock, "w"))

    base = os.path.join(project, "base")
    os.makedirs(base, exist_ok=True)
    before = os.path.join(base, "package-lock.json")
    json.dump({"lockfileVersion": 3, "packages": {"": {}}}, open(before, "w"))

    assert cli.main(["diff", before, lock, "--format", "markdown", "--fail-on", "never"]) == 0
    out = capsys.readouterr().out
    assert out.startswith(fmt.MARKER) and "reqeusts" in out and "`+`" in out


def test_markdown_is_a_scan_format(project, capsys):
    assert cli.main(["scan", project, "--format", "markdown", "--fail-on", "never"]) == 0
    assert fmt.MARKER in capsys.readouterr().out


def test_the_generated_workflow_posts_its_report(tmp_path):
    cli.main(["init", str(tmp_path), "--color", "never"])
    workflow = (tmp_path / ".github" / "workflows" / "hemlock.yml").read_text()
    assert "--format markdown" in workflow
    assert "gh pr comment" in workflow and "--edit-last" in workflow
    assert "pull-requests: write" in workflow


def test_no_workflow_carries_a_publish_credential():
    """The release workflow publishes over OIDC. A stored token appearing in
    here later would be the exact failure this project is about."""
    root = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows")
    for name in os.listdir(root):
        text = open(os.path.join(root, name)).read().lower()
        assert "pypi_api_token" not in text, name
        assert "password:" not in text, name
        assert "twine upload" not in text, name


def test_the_release_workflow_asks_for_attestations():
    path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "release.yml")
    text = open(path).read()
    assert "attestations: true" in text
    assert "id-token: write" in text


def test_ci_steps_that_capture_a_report_do_not_gate_on_it():
    """`hemlock scan fixture --format sarif > file` failed the build for three
    weeks. The fixture is known-bad, so scanning it exits 1 by design, and a
    step that only wants the file was reading that as its own failure.

    Scoped to our own ci.yml. The workflow `hemlock init` generates redirects
    without `--fail-on never` on purpose: that step is `continue-on-error` and
    its outcome is what gates the build.
    """
    path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "ci.yml")
    for line in open(path):
        if ">" in line and ("hemlock scan" in line or "hemlock diff" in line):
            assert "--fail-on never" in line, f"captures a report but gates on it: {line.strip()}"


def test_ci_runs_on_pushes_to_the_default_branch():
    """The trigger said `main` while the repository's default branch is
    `master`, so no push to it ever ran the suite."""
    path = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "ci.yml")
    assert "branches: [main, master]" in open(path).read()


def test_the_generated_workflow_installs_from_somewhere_that_exists(tmp_path):
    """`pip install hemlock-scan` shipped in this file for three releases and
    fails, because nothing of that name is on PyPI. Anyone running
    `hemlock init` got a workflow that could not run."""
    cli.main(["init", str(tmp_path), "--color", "never"])
    workflow = (tmp_path / ".github" / "workflows" / "hemlock.yml").read_text()
    install = [x for x in workflow.splitlines() if "pip install" in x or "pipx install" in x]
    assert install, "the workflow never installs hemlock"
    assert all("github.com/xzycd/hemlock" in x for x in install)
