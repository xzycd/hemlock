import pytest

from hemlock.model import Context, Package
from hemlock.rules import affix_impersonation, edit_distance, entropy, homoglyph_name, near_miss, scope_drop

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
