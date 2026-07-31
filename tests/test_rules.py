import pytest

from hemlock import rules as rules_mod
from hemlock.data import POPULAR
from hemlock.model import Context, Package
from hemlock.rules import (
    affix_impersonation,
    edit_distance,
    entropy,
    homoglyph_name,
    near_miss,
    nearest,
    scope_drop,
    wearing_affix,
)

CTX = Context(root=".")


def npm(name, **kw):
    return Package("npm", name, **kw)


def pypi(name, **kw):
    return Package("pypi", name, **kw)


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("requests", "requests", 0),
        ("requsts", "requests", 1),
        ("reqeusts", "requests", 1),  # transposition counts as one edit
        ("lodash", "lodahs", 1),
        ("chalk", "chalks", 1),
        ("express", "flask", 6),
        ("requests", "urllib3", 8),
    ],
)
def test_edit_distance(a, b, expected):
    assert edit_distance(a, b, cutoff=20) == expected


def test_edit_distance_bails_out_early():
    assert edit_distance("a" * 40, "b" * 2, cutoff=2) > 2


def fires(rule, pkg):
    return list(rule(pkg, CTX))


class TestNearMiss:
    def test_catches_a_dropped_letter(self):
        assert "requests" in fires(near_miss, pypi("requsts"))[0]

    def test_catches_a_transposition(self):
        assert fires(near_miss, npm("lodahs"))

    def test_ignores_the_real_package(self):
        assert not fires(near_miss, npm("lodash"))
        assert not fires(near_miss, pypi("requests"))

    def test_ignores_normalised_pypi_spelling(self):
        # PEP 503 says these are the same name, so it is not a near-miss.
        assert not fires(near_miss, pypi("Python_DateUtil"))

    def test_ignores_very_short_names(self):
        assert not fires(near_miss, npm("ms"))

    def test_ignores_unrelated_names(self):
        for name in ("my-internal-thing", "acme-widgets", "supercalifragilistic"):
            assert not fires(near_miss, npm(name)), name


class TestAffix:
    def test_suffix(self):
        assert "express" in fires(affix_impersonation, npm("express-js"))[0]

    def test_prefix(self):
        assert "numpy" in fires(affix_impersonation, pypi("python-numpy"))[0]

    def test_leaves_real_packages_alone(self):
        assert not fires(affix_impersonation, npm("socket.io"))
        assert not fires(affix_impersonation, pypi("boto3"))


class TestHomoglyph:
    def test_cyrillic_es_reads_as_c(self):
        hits = fires(homoglyph_name, npm("сhalk"))
        assert hits and "CYRILLIC" in hits[0]

    def test_ascii_names_are_clean(self):
        assert not fires(homoglyph_name, npm("@babel/core"))
        assert not fires(homoglyph_name, pypi("charset-normalizer"))


class TestScopeDrop:
    def test_unscoped_types_package(self):
        assert "@types/node" in fires(scope_drop, npm("types-node"))[0]

    def test_scoped_packages_are_fine(self):
        assert not fires(scope_drop, npm("@types/node"))

    def test_ordinary_hyphenated_names_are_fine(self):
        assert not fires(scope_drop, npm("cross-spawn"))


def test_entropy_separates_text_from_random():
    assert entropy("aaaaaaaaaaaa") < 1.0
    assert entropy("the quick brown fox") < 4.5
    assert entropy("aB3xQ9zL7pW2mK5vN8rT4yU6iO1sD0fG") > 4.5


# -- the naming prefilters -------------------------------------------------
#
# Comparing every package name against the whole corpus was 93% of the runtime
# on a fifty thousand package lockfile. Two prefilters cut that, and both have
# to be sound rather than merely fast, so they are pinned against the sweep
# they replaced.


def _brute_force_nearest(name, ecosystem):
    """What the rule did before: score the whole corpus, keep the best."""
    hits = []
    for target in POPULAR.get(ecosystem, frozenset()):
        d = edit_distance(name, target, cutoff=2)
        if d and d <= 2 and abs(len(name) - len(target)) <= 2:
            hits.append((d, target))
    return min(hits) if hits else None


def _mutations(word):
    """The four ways a name gets typoed, which is what the rule is for."""
    for i in range(len(word)):
        yield word[:i] + word[i + 1:]                      # deletion
        yield word[:i] + "x" + word[i + 1:]                # substitution
        yield word[:i] + "q" + word[i:]                    # insertion
        if i + 1 < len(word):
            yield word[:i] + word[i + 1] + word[i] + word[i + 2:]   # transposition


@pytest.mark.parametrize("ecosystem", ["npm", "pypi"])
def test_the_prefilters_never_change_a_verdict(ecosystem):
    for target in sorted(POPULAR[ecosystem]):
        for name in _mutations(target):
            assert nearest(name, ecosystem) == _brute_force_nearest(name, ecosystem), name


def test_an_unrelated_name_is_rejected_without_the_dynamic_programming():
    """The length and character prefilters are what make a monorepo scan
    finish. A name sharing nothing with the corpus should not reach the DP."""
    calls = []
    real = rules_mod.edit_distance

    def counted(a, b, cutoff=3):
        calls.append((a, b))
        return real(a, b, cutoff)

    rules_mod.edit_distance = counted
    try:
        rules_mod.nearest.cache_clear()
        rules_mod.nearest("zzqqwwxxjjkk", "npm")
    finally:
        rules_mod.edit_distance = real
        rules_mod.nearest.cache_clear()
    assert calls == [], f"reached the DP {len(calls)} times for a name sharing nothing"


def test_the_nearest_match_is_the_closest_one_and_is_stable():
    """The old sweep returned whichever match set iteration reached first, so
    two runs could name different neighbours for the same package."""
    assert nearest("requsts", "pypi") == (1, "requests")
    assert nearest("colorz", "npm") == (1, "colors")
    assert nearest("requsts", "pypi") == nearest("requsts", "pypi")


def test_affix_stripping_survived_being_precompiled():
    """`python3-dateutil` is not in here on purpose: it is one edit from
    `python-dateutil`, so HEM101 catches it and HEM102 never sees it."""
    assert wearing_affix("colors-js", "npm") == ("colors", "js")
    assert wearing_affix("requests-python", "pypi") == ("requests", "python")
    assert wearing_affix("urllib3-sdk", "pypi") == ("urllib3", "sdk")
    assert wearing_affix("wholly-unrelated-name", "npm") is None
