from __future__ import annotations

import argparse
import os
import sys

from . import __version__, brand, motion, scan
from . import baseline as baseline_mod
from . import history as history_mod
from . import policy as policy_mod
from . import report as fmt
from . import update as update_mod
from .model import RULES

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

BANNER = "hemlock: supply-chain scanner for npm and PyPI. Poison hemlock looks like parsley."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hemlock", description=BANNER)
    p.add_argument("--version", action="version", version=f"hemlock {__version__}")
    # People reach for `--update` before they think to look for a subcommand,
    # and being right about the spelling is not the point of the exercise.
    p.add_argument("--update", action="store_true", help="same as `hemlock update`")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project for suspicious dependencies")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    _shared(s)
    s.add_argument("--all", action="store_true", help="list clean packages too")

    c = sub.add_parser("check", help="judge packages by name, before you install them")
    c.add_argument("specs", nargs="+", metavar="PACKAGE",
                   help="name[@version], optionally prefixed npm: or pypi:")
    c.add_argument("--ecosystem", choices=scan.ECOSYSTEMS, default="npm",
                   help="which registry an unprefixed name belongs to (default: npm)")
    _shared(c)

    d = sub.add_parser("diff", help="score only what a change adds or moves")
    d.add_argument("manifests", nargs="*", metavar="MANIFEST",
                   help="two manifest files to compare, or none with --since")
    d.add_argument("--since", metavar="REF",
                   help="compare the working tree against a git ref, e.g. HEAD~1 or origin/main")
    d.add_argument("--path", default=".", help="project directory when using --since (default: .)")
    _shared(d)

    h = sub.add_parser("history", help="what this project used to have installed, and whether it was safe")
    h.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    h.add_argument("--package", metavar="NAME",
                   help="follow one package through the history instead of hunting for exposure")
    h.add_argument("--limit", type=int, default=history_mod.DEFAULT_LIMIT, metavar="N",
                   help=f"manifest commits to read, newest first (default: {history_mod.DEFAULT_LIMIT})")
    h.add_argument("--since", metavar="REF", help="only history after this git ref")
    h.add_argument("--online", action="store_true", help="check every version ever pinned against osv.dev")
    h.add_argument("--fail-on", choices=SEVERITY_ORDER + ["never"], help="exit non-zero at this severity")
    h.add_argument("--format", choices=["terminal", "json"], default="terminal")
    h.add_argument("--config", metavar="FILE", help="path to .hemlock.toml")
    h.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    h.add_argument("--no-logo", action="store_true", help="skip the wordmark")

    w = sub.add_parser("why", help="show where a package came from and what is wrong with it")
    w.add_argument("package", help="package name, or a fragment of one")
    w.add_argument("--path", default=".", help="project directory (default: .)")
    w.add_argument("--online", action="store_true", help="add registry, provenance and OSV checks")
    w.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    b = sub.add_parser("baseline", help="accept every current finding so CI only fails on new ones")
    b.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    b.add_argument("--online", action="store_true", help="include the online rules in the baseline")
    b.add_argument("--config", metavar="FILE", help="path to .hemlock.toml")
    b.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    i = sub.add_parser("init", help="write a config file and a CI workflow")
    i.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    i.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    e = sub.add_parser("explain", help="why a rule exists and what to do about it")
    e.add_argument("rule", help="a rule id, e.g. HEM701")
    e.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    r = sub.add_parser("rules", help="list every check")
    r.add_argument("--online", action="store_true", help="only the checks that need the network")
    r.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    u = sub.add_parser("update", help="check for a newer hemlock and offer to install it")
    u.add_argument("--check", action="store_true", help="report only, never install")
    u.add_argument("--yes", action="store_true", help="install without asking")
    u.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    return p


def _shared(sp) -> None:
    sp.add_argument("--online", action="store_true", help="add registry, provenance and OSV checks")
    sp.add_argument("--fresh-days", type=int, metavar="N", help="how new a release counts as fresh (default 14)")
    sp.add_argument("--fail-on", choices=SEVERITY_ORDER + ["never"], help="exit non-zero at this severity")
    sp.add_argument("--format", choices=["terminal", "markdown", "json", "sarif"], default="terminal")
    sp.add_argument("--config", metavar="FILE", help="path to .hemlock.toml")
    sp.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    sp.add_argument("--ignore-baseline", action="store_true",
                    help="report accepted findings too, instead of only new ones")
    sp.add_argument("--no-logo", action="store_true", help="skip the wordmark")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        if args.update:
            return _update(parser.parse_args(["update"]), fmt.Ink(fmt.color_depth("auto")))
        depth = fmt.color_depth("auto")
        print(brand.logo(color=depth, animate=brand.wants_animation(depth), version=__version__))
        parser.print_help()
        return 0

    ink = fmt.Ink(fmt.color_depth(args.color), links=fmt.wants_links())

    if args.command == "explain":
        rule = RULES.get(args.rule.upper())
        if not rule:
            near = [r for r in RULES if args.rule.upper() in r]
            hint = f" Did you mean {near[0]}?" if near else " Try `hemlock rules`."
            print(f"No rule {args.rule!r}.{hint}", file=sys.stderr)
            return 2
        print(fmt.explain(rule, ink))
        return 0

    if args.command == "rules":
        print(fmt.rule_table(ink, online_only=args.online))
        return 0

    return {
        "scan": _scan,
        "check": _check,
        "update": _update,
        "diff": _diff,
        "history": _history,
        "why": _why,
        "baseline": _baseline,
        "init": _init,
    }[args.command](args, ink)


# --------------------------------------------------------------------------


def _ticker_for(args):
    """The live line, or nothing at all when there is nobody to watch it."""
    if args.format != "terminal" or not sys.stderr.isatty():
        return None
    if os.environ.get("CI") or os.environ.get("HEMLOCK_NO_ANIMATION"):
        return None
    return motion.Ticker(fmt.Ink(fmt.color_depth(args.color, sys.stderr)))


def _launch(args) -> None:
    """The wordmark, at the top of an interactive scan.

    Gated on stdout being a terminal rather than stderr, because this one is
    part of the report: redirect the report and you asked for the report, not
    for five rows of block letters at the top of the file.
    """
    if args.format != "terminal" or args.no_logo or not sys.stdout.isatty():
        return
    if os.environ.get("HEMLOCK_NO_LOGO"):
        return
    depth = fmt.color_depth(args.color)
    print(brand.logo(color=depth, animate=brand.wants_animation(depth), version=__version__))


def _policy(args, root: str):
    pol = policy_mod.load(root, args.config)
    # Not every command has a freshness window to override. `history` reads the
    # config for its failing threshold and nothing else.
    if getattr(args, "fresh_days", None) is not None:
        pol.fresh_days = args.fresh_days
    return pol, (args.fail_on or pol.fail_on)


def _distinguish(a: str, b: str) -> tuple[str, str]:
    """Shortest tail of each path that still tells the two apart.

    Comparing two lockfiles usually means two copies of `package-lock.json`,
    and a header reading 'package-lock.json -> package-lock.json' says nothing.
    """
    pa, pb = a.split(os.sep), b.split(os.sep)
    depth = 1
    while depth < max(len(pa), len(pb)) and pa[-depth:] == pb[-depth:]:
        depth += 1
    return os.sep.join(pa[-depth:]), os.sep.join(pb[-depth:])


def _exit_code(report, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.index(fail_on)
    for v in report.flagged:
        if v.severity in SEVERITY_ORDER and SEVERITY_ORDER.index(v.severity) >= threshold:
            return 1
    return 0


def _scan(args, ink: fmt.Ink) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2

    _launch(args)
    pol, fail_on = _policy(args, root)
    ticker = _ticker_for(args)
    try:
        if ticker:
            ticker.start()
        report = scan.run(root, pol, online=args.online,
                          progress=ticker.update if ticker else None)
    finally:
        if ticker:
            ticker.stop()

    # A baseline present in the project is applied by default. That is the
    # whole point of committing one: CI should stop failing on the backlog
    # without anyone having to remember a flag.
    if not args.ignore_baseline and (known := baseline_mod.load(root)):
        baseline_mod.apply(report, known)

    if args.format == "json":
        print(fmt.as_json(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
    elif args.format == "markdown":
        print(fmt.as_markdown(report))
    else:
        if not report.manifests:
            print(f"\n  no npm or Python manifests under {args.path}\n", file=sys.stderr)
            return 0
        print(fmt.terminal(report, ink, show_all=args.all, fail_on=fail_on))

    return _exit_code(report, fail_on)


def _update(args, ink: fmt.Ink) -> int:
    """Check for a newer release, then offer the exact command.

    Nothing is installed without a yes. hemlock's whole argument is that
    running somebody else's install step is the risk, so it does not get to
    make an exception for its own.
    """
    from .http import Http
    from .update import installation, latest, run, upgrade_command

    http = Http(ttl=900)
    found = latest(http)
    if not found:
        # An answer of "nothing published" is not a failure to get an answer,
        # and reporting it as one sends people looking at their network.
        if http.failures:
            print(f"\n  {ink('could not check', 'medium')}  {http.failures[0]}")
            print(f"  you have {ink('v' + __version__, 'accent')}\n")
            return 1
        print(f"\n  {ink('nothing published yet', 'dim')}  "
              f"no release on PyPI and no tag on the repository")
        print(f"  you are running {ink('v' + __version__, 'accent')} "
              f"{ink('from source', 'dim')}\n")
        return 0

    newest, source = found
    mine, theirs = update_mod.parse_version(__version__), update_mod.parse_version(newest)
    if not theirs or (mine and mine >= theirs):
        print(f"\n  {ink('up to date', 'clean')}  hemlock {ink('v' + __version__, 'accent')} "
              f"{ink('is the newest release', 'dim')}\n")
        return 0

    method = installation()
    command = upgrade_command(method, on_pypi=(source == "pypi"))
    printable = " ".join(command)

    print(f"\n  {ink('update available', 'medium', 'bold')}  "
          f"{ink('v' + __version__, 'dim')} {ink('to', 'dim')} {ink('v' + newest, 'accent', 'bold')}")
    print(f"  {ink(f'installed with {method}', 'dim')}\n")
    print(f"    {ink(printable, 'accent')}\n")

    if args.check:
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            print(f"  {ink('run that to upgrade, or pass --yes', 'dim')}\n")
            return 0
        try:
            reply = input("  run it? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 130
        if reply not in ("y", "yes"):
            print(f"  {ink('left alone', 'dim')}\n")
            return 0

    print("")
    return run(command)


def _check(args, ink: fmt.Ink) -> int:
    specs = [scan.parse_spec(s, args.ecosystem) for s in args.specs]
    if any(not p.name for p in specs):
        print("hemlock: give a package name, e.g. hemlock check chalk@5.6.1", file=sys.stderr)
        return 2

    _launch(args)
    # No project root, so config discovery starts where the user is standing.
    # Running `check` inside a repository should respect that repository's
    # disabled rules and suppressions.
    pol, fail_on = _policy(args, os.getcwd())
    ticker = _ticker_for(args)
    try:
        if ticker:
            ticker.start()
        report = scan.check(specs, pol, online=args.online,
                            progress=ticker.update if ticker else None)
    finally:
        if ticker:
            ticker.stop()

    if args.format == "json":
        print(fmt.as_json(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
    elif args.format == "markdown":
        print(fmt.as_markdown(report))
    else:
        # Always list every package asked about, clean ones included. Naming a
        # package is the question; "nothing flagged" without saying which of
        # the three you meant is not an answer to it.
        print(fmt.terminal(report, ink, show_all=True, fail_on=fail_on))

    return _exit_code(report, fail_on)


def _diff(args, ink: fmt.Ink) -> int:
    from . import diff as diff_mod

    _launch(args)
    root = os.path.abspath(args.path)
    pol, fail_on = _policy(args, root)
    ticker = _ticker_for(args)

    if args.since:
        if args.manifests:
            print("hemlock: pass manifests or --since, not both", file=sys.stderr)
            return 2
        repo = diff_mod.git_root(root)
        if not repo:
            print(f"hemlock: {args.path} is not inside a git repository", file=sys.stderr)
            return 2
        _, head = scan.collect(root)
        if not head:
            print(f"\n  no npm or Python manifests under {args.path}\n", file=sys.stderr)
            return 0
        base = []
        for rel in sorted({p.origin for p in head}):
            base.extend(diff_mod.from_git(args.since, os.path.join(root, rel), repo))
        labels = (args.since, "working tree")

    elif len(args.manifests) == 2:
        before, after = (os.path.abspath(m) for m in args.manifests)
        for path in (before, after):
            if not os.path.isfile(path):
                print(f"hemlock: {path} is not a file", file=sys.stderr)
                return 2
            if diff_mod.parser_for(path) is None:
                print(f"hemlock: {os.path.basename(path)} is not a manifest hemlock reads", file=sys.stderr)
                return 2
        base = diff_mod.read_manifest(before, os.path.dirname(before))
        head = diff_mod.read_manifest(after, os.path.dirname(after))
        labels = _distinguish(before, after)

    else:
        print("hemlock: give two manifests, or --since <ref>", file=sys.stderr)
        return 2

    try:
        if ticker:
            ticker.start()
        report = diff_mod.run(base, head, pol, root, online=args.online,
                              progress=ticker.update if ticker else None, labels=labels)
    finally:
        if ticker:
            ticker.stop()

    if args.format == "json":
        print(fmt.as_json_diff(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
    elif args.format == "markdown":
        print(fmt.as_markdown_diff(report))
    else:
        print(fmt.terminal_diff(report, ink))

    return _exit_code(report, fail_on)


def run() -> None:
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)


WORKFLOW = """\
name: hemlock

on:
  pull_request:
  push:
    branches: [main, master]
  schedule:
    # A malware record is usually published after the package was already
    # installed, so a scan that passed on Monday can be wrong about Monday by
    # Friday. The weekly run re-asks about every version this project ever
    # pinned, including the ones it has since upgraded past.
    - cron: "23 5 * * 1"

permissions:
  contents: read
  pull-requests: write

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install hemlock-scan

      # On a pull request, judge what the branch adds rather than the whole
      # tree. Everything already in the lockfile was somebody else's decision.
      # The comment goes up either way, so a passing scan still leaves a record
      # of what was checked.
      - name: scan the change
        id: scan
        if: github.event_name == 'pull_request'
        continue-on-error: true
        run: |
          hemlock diff --since origin/${{ github.base_ref }} --online \\
            --format markdown --fail-on high > hemlock.md

      # A pull request from a fork gets a read-only token, so the comment
      # cannot be posted. That is not a reason to fail the scan.
      - name: comment on the pull request
        if: github.event_name == 'pull_request'
        continue-on-error: true
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh pr comment ${{ github.event.number }} --body-file hemlock.md \\
            --edit-last --create-if-none

      - name: fail if the change introduced something
        if: steps.scan.outcome == 'failure'
        run: exit 1

      - name: scan everything
        if: github.event_name != 'pull_request'
        run: hemlock scan . --online --fail-on high

  # What the tree used to be. A version you have already upgraded past was
  # still installed at the time, and the record naming it often lands later.
  # Nothing else in CI asks this question, because everything else reads HEAD.
  history:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install hemlock-scan
      - run: hemlock history . --online --fail-on critical
"""


def _history(args, ink: fmt.Ink) -> int:
    """What this project used to have installed.

    Every other command reads the working tree, which answers a question about
    now. This one answers the question people ask when a compromise is
    announced, which is whether they were ever on it.
    """
    from .diff import git_root

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2
    repo = git_root(root)
    if not repo:
        print(f"hemlock: {args.path} is not inside a git repository, so there is no "
              f"history to read", file=sys.stderr)
        return 2
    # An unresolvable ref would quietly read as a project with no history, and
    # "nothing was ever pinned here" is not a thing to say by accident.
    if args.since and not history_mod.resolves(repo, args.since):
        print(f"hemlock: git does not know the ref {args.since!r}", file=sys.stderr)
        return 2

    _launch(args)
    pol, fail_on = _policy(args, root)
    ticker = _ticker_for(args)
    try:
        if ticker:
            ticker.start()
        report = history_mod.run(root, online=args.online, package=args.package or "",
                                 limit=args.limit, since=args.since or "",
                                 progress=ticker.update if ticker else None)
    finally:
        if ticker:
            ticker.stop()

    if args.format == "json":
        print(fmt.as_json_history(report))
    else:
        print(fmt.terminal_history(report, ink))

    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.index(fail_on)
    worst = [w for w in report.windows
             if w.severity in SEVERITY_ORDER and SEVERITY_ORDER.index(w.severity) >= threshold]
    return 1 if worst else 0


def _why(args, ink: fmt.Ink) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2

    pol = policy_mod.load(root, None)
    report = scan.run(root, pol, online=args.online, progress=None)

    needle = args.package.lower()
    exact = [(v, v.package) for v in report.verdicts if v.package.name.lower() == needle]
    matches = exact or [
        (v, v.package) for v in report.verdicts
        if needle in v.package.name.lower() and v.package.kind == "package"
    ]

    if not matches:
        print(f"\n  no package matching {args.package!r} in {args.path}\n", file=sys.stderr)
        return 2
    if len(matches) > 6:
        names = sorted({p.name for _, p in matches})
        print(f"\n  {args.package!r} matches {len(names)} packages: "
              f"{', '.join(names[:8])}...\n", file=sys.stderr)
        return 2

    print(fmt.why(report, matches, ink))
    return 0


def _baseline(args, ink: fmt.Ink) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2

    pol = policy_mod.load(root, args.config)
    report = scan.run(root, pol, online=args.online, progress=None)
    path, count = baseline_mod.write(report, root)

    scope = "including the online rules" if args.online else "offline rules only"
    print(f"\n  accepted {count} findings across {len(report.flagged)} packages, {scope}")
    print(f"  written to {os.path.relpath(path, root)}")
    print(f"  {ink('commit it', 'accent')}, and future scans will only fail on findings that are new\n")
    return 0


def _init(args, ink: fmt.Ink) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2

    written, skipped = [], []
    config = os.path.join(root, ".hemlock.toml")
    if os.path.exists(config):
        skipped.append(".hemlock.toml")
    else:
        with open(config, "w", encoding="utf-8") as fh:
            fh.write(DEFAULT_CONFIG)
        written.append(".hemlock.toml")

    workflow = os.path.join(root, ".github", "workflows", "hemlock.yml")
    if os.path.exists(workflow):
        skipped.append(".github/workflows/hemlock.yml")
    else:
        os.makedirs(os.path.dirname(workflow), exist_ok=True)
        with open(workflow, "w", encoding="utf-8") as fh:
            fh.write(WORKFLOW)
        written.append(".github/workflows/hemlock.yml")

    print("")
    for name in written:
        print(f"  {ink('created', 'clean')}  {name}")
    for name in skipped:
        print(f"  {ink('kept', 'dim')}     {name} {ink('(already there)', 'dim')}")
    if written:
        print(f"\n  next: {ink('hemlock scan .', 'accent')}, then "
              f"{ink('hemlock baseline .', 'accent')} if there is more than you want to fix today\n")
    else:
        print("")
    return 0


DEFAULT_CONFIG = """\
# hemlock configuration. Everything here is optional.

# Exit non-zero when anything reaches this severity.
# One of: low, medium, high, critical, never
fail_on = "high"

# How new a release has to be before HEM501 calls it fresh.
fresh_days = 14

# Turn rules off entirely. Prefer an [[ignore]] block with a reason.
disable = []

# Suppressions. A reason is expected and an expiry is strongly encouraged:
# an ignore with no end date outlives whoever added it, and that is how a
# scanner quietly stops finding anything. Expired entries get reported.
#
# [[ignore]]
# rule = "HEM201"          # rule id, or a glob such as "HEM4*"
# package = "esbuild"      # package name, or a glob. Defaults to everything.
# reason = "compiles a native binary at install time; reviewed today"
# expires = "2027-01-01"
"""
