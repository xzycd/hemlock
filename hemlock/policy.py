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
FAIL_LEVELS = {"low", "medium", "high", "critical", "never"}


class PolicyError(ValueError):
    pass


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
    if explicit and not os.path.isfile(explicit):
        raise PolicyError(f"config file does not exist: {explicit}")
    if not path or not os.path.isfile(path):
        return Policy()

    try:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc

    fail_on = str(doc.get("fail_on", "high")).lower()
    if fail_on not in FAIL_LEVELS:
        raise PolicyError(f"{path}: fail_on must be one of {', '.join(sorted(FAIL_LEVELS))}")
    try:
        fresh_days = int(doc.get("fresh_days", 14))
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{path}: fresh_days must be a non-negative integer") from exc
    if fresh_days < 0:
        raise PolicyError(f"{path}: fresh_days must be a non-negative integer")

    disabled = doc.get("disable", [])
    if not isinstance(disabled, list) or not all(isinstance(rule, str) for rule in disabled):
        raise PolicyError(f"{path}: disable must be a list of rule ids")

    policy = Policy(
        fail_on=fail_on,
        fresh_days=fresh_days,
        disable={rule.upper() for rule in disabled},
        path=path,
    )

    ignores = doc.get("ignore", [])
    if not isinstance(ignores, list) or not all(isinstance(raw, dict) for raw in ignores):
        raise PolicyError(f"{path}: ignore must be an array of tables")
    for raw in ignores:
        expires = raw.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError as exc:
                raise PolicyError(f"{path}: invalid ignore expiry {expires!r}") from exc
        elif expires is not None and not isinstance(expires, date):
            raise PolicyError(f"{path}: ignore expiry must be an ISO date")
        ig = Ignore(
            rule=str(raw.get("rule", "*")).upper(),
            package=str(raw.get("package", "*")),
            reason=str(raw.get("reason", "")),
            expires=expires,
        )
        (policy.expired if ig.expired else policy.ignores).append(ig)

    return policy
