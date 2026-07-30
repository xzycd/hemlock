"""Project configuration: .hemlock.toml

Suppressions carry a reason and can carry an expiry. An ignore with no reason
is a note to nobody, and an ignore with no expiry outlives the person who
added it. Both are how a scanner quietly stops finding anything.
"""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field
from datetime import date

CONFIG_NAMES = [".hemlock.toml", "hemlock.toml"]


@dataclass
class Ignore:
    rule: str = "*"
    package: str = "*"
    reason: str = ""
    expires: date | None = None

    def matches(self, rule_id: str, package: str) -> bool:
        return fnmatch.fnmatch(rule_id, self.rule) and fnmatch.fnmatch(package, self.package)

    @property
    def expired(self) -> bool:
        return self.expires is not None and self.expires < date.today()


@dataclass
class Policy:
    fail_on: str = "high"
    fresh_days: int = 14
    disable: set[str] = field(default_factory=set)
    ignores: list[Ignore] = field(default_factory=list)
    path: str | None = None
    expired: list[Ignore] = field(default_factory=list)

    def suppresses(self, rule_id: str, package: str) -> Ignore | None:
        for ig in self.ignores:
            if not ig.expired and ig.matches(rule_id, package):
                return ig
        return None


def load(root: str, explicit: str | None = None) -> Policy:
    path = explicit
    if not path:
        for name in CONFIG_NAMES:
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate):
                path = candidate
                break
    if not path or not os.path.isfile(path):
        return Policy()

    with open(path, "rb") as fh:
        doc = tomllib.load(fh)

    policy = Policy(
        fail_on=str(doc.get("fail_on", "high")).lower(),
        fresh_days=int(doc.get("fresh_days", 14)),
        disable={str(r).upper() for r in doc.get("disable", [])},
        path=path,
    )

    for raw in doc.get("ignore", []):
        expires = raw.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        ig = Ignore(
            rule=str(raw.get("rule", "*")).upper(),
            package=str(raw.get("package", "*")),
            reason=str(raw.get("reason", "")),
            expires=expires,
        )
        (policy.expired if ig.expired else policy.ignores).append(ig)

    return policy
