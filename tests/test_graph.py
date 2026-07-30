"""Dependency routes: who asked for this package."""

import json

from hemlock.graph import Graph, build
from hemlock.model import Package


def project(tmp_path, lockfile, name="package-lock.json"):
    (tmp_path / name).write_text(json.dumps(lockfile))
    return str(tmp_path)


def pkgs(*names, direct=(), origin="package-lock.json"):
    return [Package("npm", n, version="1.0.0", origin=origin, direct=n in direct) for n in names]


# -- npm lockfile v2/v3 ----------------------------------------------------


NESTED = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"app-kit": "1.0.0"}},
        "node_modules/app-kit": {"version": "1.0.0", "dependencies": {"build-tools": "^2.0.0"}},
        "node_modules/build-tools": {"version": "2.1.0", "dependencies": {"colorz": "^1.0.0", "shared": "^1.0.0"}},
        "node_modules/build-tools/node_modules/shared": {"version": "1.5.0"},
        "node_modules/shared": {"version": "2.0.0"},
        "node_modules/colorz": {"version": "1.0.4"},
    },
}


def test_follows_a_transitive_chain(tmp_path):
    root = project(tmp_path, NESTED)
    g = build(root, pkgs("app-kit", "build-tools", "colorz", "shared", direct=("app-kit",)))
    assert g.paths_to("npm", "colorz") == [["app-kit", "build-tools", "colorz"]]


def test_a_direct_dependency_is_its_own_route(tmp_path):
    root = project(tmp_path, NESTED)
    g = build(root, pkgs("app-kit", direct=("app-kit",)))
    assert g.is_direct("npm", "app-kit")
    assert g.paths_to("npm", "app-kit") == [["app-kit"]]


def test_a_nested_copy_resolves_before_the_hoisted_one(tmp_path):
    """build-tools depends on shared, and there is a copy beside it. Node
    resolves the nearer one, so the edge must come from that lookup rather
    than from whatever sits at the root."""
    root = project(tmp_path, NESTED)
    g = build(root, pkgs("app-kit", "build-tools", "shared", direct=("app-kit",)))
    assert g.children("npm", "build-tools") == {"colorz", "shared"}


def test_the_project_itself_produces_roots_not_edges(tmp_path):
    root = project(tmp_path, NESTED)
    g = build(root, pkgs("app-kit", direct=("app-kit",)))
    assert ("npm", "app-kit") in g.roots
    assert ("npm", "") not in {(e, n) for e, n in g.edges}


def test_a_dependency_the_lockfile_never_resolves_is_skipped(tmp_path):
    root = project(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "1.0.0"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"ghost": "^1.0.0"}},
        },
    })
    g = build(root, pkgs("a", direct=("a",)))
    assert g.children("npm", "a") == set()


def test_unreachable_packages_have_no_route(tmp_path):
    root = project(tmp_path, {
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {}}, "node_modules/orphan": {"version": "1.0.0"}},
    })
    g = build(root, pkgs("orphan"))
    assert g.paths_to("npm", "orphan") == []


# -- npm lockfile v1 -------------------------------------------------------


def test_v1_nested_tree(tmp_path):
    root = project(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {
            "outer": {"version": "1.0.0", "dependencies": {"inner": {"version": "2.0.0"}}},
        },
    })
    g = build(root, pkgs("outer", "inner", direct=("outer",)))
    assert g.paths_to("npm", "inner") == [["outer", "inner"]]


# -- poetry ----------------------------------------------------------------


def test_poetry_lock(tmp_path):
    (tmp_path / "poetry.lock").write_text('''
[[package]]
name = "flask"
version = "3.0.0"
[package.dependencies]
werkzeug = ">=3.0"

[[package]]
name = "werkzeug"
version = "3.0.1"
[package.dependencies]
markupsafe = ">=2.1"

[[package]]
name = "markupsafe"
version = "2.1.3"
''')
    packages = [Package("pypi", n, version="1", origin="poetry.lock")
                for n in ("flask", "werkzeug", "markupsafe")]
    g = build(str(tmp_path), packages)
    assert g.paths_to("pypi", "markupsafe") == [["flask", "werkzeug", "markupsafe"]]
    assert g.is_direct("pypi", "flask")  # nothing depends on it, so the project asked for it


# -- traversal behaviour ---------------------------------------------------


def test_a_cycle_does_not_hang():
    g = Graph()
    g.roots.add(("npm", "a"))
    g.add("npm", "a", "b")
    g.add("npm", "b", "a")
    g.add("npm", "b", "target")
    assert g.paths_to("npm", "target") == [["a", "b", "target"]]


def test_the_shortest_route_comes_first():
    g = Graph()
    g.roots.update({("npm", "short"), ("npm", "long")})
    g.add("npm", "short", "target")
    g.add("npm", "long", "middle")
    g.add("npm", "middle", "target")
    assert g.paths_to("npm", "target", limit=2)[0] == ["short", "target"]


def test_routes_are_capped():
    g = Graph()
    for i in range(10):
        g.roots.add(("npm", f"root{i}"))
        g.add("npm", f"root{i}", "target")
    assert len(g.paths_to("npm", "target", limit=3)) == 3


def test_a_missing_lockfile_is_not_fatal(tmp_path):
    g = build(str(tmp_path), pkgs("a", direct=("a",)))
    assert g.roots == {("npm", "a")} and g.edges == {}


def test_a_corrupt_lockfile_is_not_fatal(tmp_path):
    (tmp_path / "package-lock.json").write_text("{ not json")
    assert build(str(tmp_path), pkgs("a", direct=("a",))).edges == {}
