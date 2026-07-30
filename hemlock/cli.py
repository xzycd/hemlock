from __future__ import annotations

import argparse
import os
import sys

from . import __version__, brand, scan
from . import baseline as baseline_mod
from . import policy as policy_mod
from . import report as fmt
from .model import RULES

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

BANNER = "hemlock: supply-chain scanner for npm and PyPI. Poison hemlock looks like parsley."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hemlock", description=BANNER)
    p.add_argument("--version", action="version", version=f"hemlock {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan a project for suspicious dependencies")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    _shared(s)
    s.add_argument("--all", action="store_true", help="list clean packages too")

    d = sub.add_parser("diff", help="score only what a change adds or moves")
    d.add_argument("manifests", nargs="*", metavar="MANIFEST",
                   help="two manifest files to compare, or none with --since")
    d.add_argument("--since", metavar="REF",
                   help="compare the working tree against a git ref, e.g. HEAD~1 or origin/main")
    d.add_argument("--path", default=".", help="project directory when using --since (default: .)")
    _shared(d)

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
    return p


def _shared(sp) -> None:
    sp.add_argument("--online", action="store_true", help="add registry, provenance and OSV checks")
    sp.add_argument("--fresh-days", type=int, metavar="N", help="how new a release counts as fresh (default 14)")
    sp.add_argument("--fail-on", choices=SEVERITY_ORDER + ["never"], help="exit non-zero at this severity")
    sp.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    sp.add_argument("--config", metavar="FILE", help="path to .hemlock.toml")
    sp.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    sp.add_argument("--ignore-baseline", action="store_true",
                    help="report accepted findings too, instead of only new ones")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        print(brand.logo(color=fmt.want_color("auto"),
                         animate=brand.wants_animation(fmt.want_color("auto")),
                         version=__version__))
        parser.print_help()
        return 0

    ink = fmt.Ink(fmt.want_color(args.color))

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
        "diff": _diff,
        "why": _why,
        "baseline": _baseline,
        "init": _init,
    }[args.command](args, ink)


# --------------------------------------------------------------------------


def _progress_for(args):
    if args.format != "terminal" or not args.online or not sys.stderr.isatty():
        return None
    ink = fmt.Ink(args.color != "never")

    def report(label: str, done: int, total: int) -> None:
        print("\r\033[K" + fmt.progress_line(label, done, total, ink), end="", file=sys.stderr, flush=True)

    return report


def _clear(progress) -> None:
    if progress:
        print("\r\033[K", end="", file=sys.stderr, flush=True)


def _policy(args, root: str):
    pol = policy_mod.load(root, args.config)
    if args.fresh_days is not None:
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

    pol, fail_on = _policy(args, root)
    progress = _progress_for(args)
    report = scan.run(root, pol, online=args.online, progress=progress)
    _clear(progress)

    # A baseline present in the project is applied by default. That is the
    # whole point of committing one: CI should stop failing on the backlog
    # without anyone having to remember a flag.
    if not args.ignore_baseline and (known := baseline_mod.load(root)):
        baseline_mod.apply(report, known)

    if args.format == "json":
        print(fmt.as_json(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
    else:
        if not report.manifests:
            print(f"\n  no npm or Python manifests under {args.path}\n", file=sys.stderr)
            return 0
        print(fmt.terminal(report, ink, show_all=args.all))

    return _exit_code(report, fail_on)


def _diff(args, ink: fmt.Ink) -> int:
    from . import diff as diff_mod

    root = os.path.abspath(args.path)
    pol, fail_on = _policy(args, root)
    progress = _progress_for(args)

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

    report = diff_mod.run(base, head, pol, root, online=args.online, progress=progress, labels=labels)
    _clear(progress)

    if args.format == "json":
        print(fmt.as_json_diff(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
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
      - name: scan the change
        if: github.event_name == 'pull_request'
        run: hemlock diff --since origin/${{ github.base_ref }} --online --fail-on high

      - name: scan everything
        if: github.event_name != 'pull_request'
        run: hemlock scan . --online --fail-on high
"""


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
