"""Accepting what is already there.

Point a new scanner at an established codebase and it returns four hundred
findings. Nobody triages four hundred findings. The tool gets switched off, or
wired into CI with the threshold set so high it never fires, which is the same
thing with extra steps.

A baseline records what was true on the day you adopted the tool. After that
CI only fails on findings that are new, so the tool starts being about the
change in front of you rather than the decade behind you. The existing
findings do not disappear; they are still in the report, marked as known.

The fingerprint includes the version. A dependency that moves re-raises
everything about itself, because "we accepted this in March" says nothing
about the release that landed last night.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime

BASELINE_NAME = ".hemlock-baseline.json"
FORMAT = 1


def fingerprint(verdict, finding) -> str:
    pkg = verdict.package
    return f"{pkg.ecosystem}:{pkg.name}@{pkg.version or pkg.spec or '*'}:{finding.rule.id}"


@dataclass
class Baseline:
    accepted: set[str] = field(default_factory=set)
    created: str | None = None
    path: str | None = None

    def knows(self, verdict, finding) -> bool:
        return fingerprint(verdict, finding) in self.accepted

    def __len__(self) -> int:
        return len(self.accepted)


def path_for(root: str, explicit: str | None = None) -> str:
    return explicit or os.path.join(root, BASELINE_NAME)


def load(root: str, explicit: str | None = None) -> Baseline | None:
    path = path_for(root, explicit)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if doc.get("format") != FORMAT:
        return None
    return Baseline(accepted=set(doc.get("accepted") or []), created=doc.get("created"), path=path)


def write(report, root: str, explicit: str | None = None, now: datetime | None = None) -> tuple[str, int]:
    """Record every current finding as accepted. Returns the path and count."""
    accepted = sorted(
        fingerprint(v, f) for v in report.verdicts for f in v.findings
    )
    doc = {
        "format": FORMAT,
        "created": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": "Findings accepted when hemlock was adopted. Delete an entry to start "
                "failing on it again, or delete the file to start over.",
        "accepted": accepted,
    }
    path = path_for(root, explicit)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return path, len(accepted)


def apply(report, baseline: Baseline) -> None:
    """Mark known findings, and re-score each package on what is left.

    Rescoring matters. A package with one new finding beside four accepted
    ones should read as one new finding, not keep a score built from all five.
    """
    from .score import score_package

    rescored, known = [], 0
    for verdict in report.verdicts:
        fresh = []
        for finding in verdict.findings:
            if baseline.knows(verdict, finding):
                known += 1
            else:
                fresh.append(finding)
        if len(fresh) == len(verdict.findings):
            rescored.append(verdict)
        else:
            rescored.append(score_package(verdict.package, fresh))

    rescored.sort(key=lambda v: (-v.score, v.package.name))
    report.verdicts = rescored
    report.baselined = known
