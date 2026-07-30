from __future__ import annotations

import argparse
import os
import sys

from . import __version__, scan
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
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

    return _scan(args, ink) if args.command == "scan" else _diff(args, ink)


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
