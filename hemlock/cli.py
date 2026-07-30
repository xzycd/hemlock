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
    s.add_argument("--online", action="store_true", help="add registry trust checks (network)")
    s.add_argument("--fresh-days", type=int, metavar="N", help="how new a release counts as fresh (default 14)")
    s.add_argument("--fail-on", choices=SEVERITY_ORDER + ["never"], help="exit non-zero at this severity")
    s.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    s.add_argument("--all", action="store_true", help="list clean packages too")
    s.add_argument("--config", metavar="FILE", help="path to .hemlock.toml")
    s.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    e = sub.add_parser("explain", help="why a rule exists and what to do about it")
    e.add_argument("rule", help="a rule id, e.g. HEM502")
    e.add_argument("--color", choices=["auto", "always", "never"], default="auto")

    r = sub.add_parser("rules", help="list every check")
    r.add_argument("--online", action="store_true", help="only the checks that need the network")
    r.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.command:
        build_parser().print_help()
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

    return _scan(args, ink)


def _scan(args, ink: fmt.Ink) -> int:
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"hemlock: {args.path} is not a directory", file=sys.stderr)
        return 2

    pol = policy_mod.load(root, args.config)
    if args.fresh_days is not None:
        pol.fresh_days = args.fresh_days
    fail_on = args.fail_on or pol.fail_on

    progress = None
    if args.format == "terminal" and args.online and sys.stderr.isatty():
        err_ink = fmt.Ink(args.color != "never")

        def progress(done: int, total: int) -> None:
            print("\r\033[K" + fmt.progress_line(done, total, err_ink), end="", file=sys.stderr, flush=True)

    report = scan.run(root, pol, online=args.online, progress=progress)
    if progress:
        print("\r\033[K", end="", file=sys.stderr, flush=True)

    if args.format == "json":
        print(fmt.as_json(report))
    elif args.format == "sarif":
        print(fmt.as_sarif(report))
    else:
        if not report.manifests:
            print(f"\n  no npm or Python manifests under {args.path}\n", file=sys.stderr)
            return 0
        print(fmt.terminal(report, ink, show_all=args.all))

    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER.index(fail_on)
    for v in report.flagged:
        if v.severity in SEVERITY_ORDER and SEVERITY_ORDER.index(v.severity) >= threshold:
            return 1
    return 0


def run() -> None:
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
