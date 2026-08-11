import json

from hemlock import npm, pypi


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def by_name(packages):
    return {p.name: p for p in packages}


def test_lockfile_v3(tmp_path):
    path = write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"express": "4.18.2"}},
            "node_modules/express": {"version": "4.18.2", "integrity": "sha512-x",
                                     "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"},
            "node_modules/nan": {"version": "2.17.0", "hasInstallScript": True, "dev": True},
        },
    }))
    pkgs = by_name(npm.parse(path, str(tmp_path)))
    assert pkgs["express"].version == "4.18.2"
    assert pkgs["express"].direct is True
    assert pkgs["nan"].direct is False
    assert pkgs["nan"].dev is True
    assert pkgs["nan"].meta["hasInstallScript"] is True


def test_lockfile_v1_walks_the_nested_tree(tmp_path):
    path = write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "integrity": "sha1-x",
                  "dependencies": {"b": {"version": "2.0.0"}}},
        },
    }))
    pkgs = by_name(npm.parse(path, str(tmp_path)))
    assert pkgs["a"].direct is True
    assert pkgs["b"].version == "2.0.0"
    assert pkgs["b"].direct is False


def test_yarn_lock(tmp_path):
    path = write(tmp_path, "yarn.lock", '''
# yarn lockfile v1

"@babel/core@^7.0.0":
  version "7.22.5"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.5.tgz"
  integrity sha512-abc

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
''')
    pkgs = by_name(npm.parse(path, str(tmp_path)))
    assert pkgs["@babel/core"].version == "7.22.5"
    assert pkgs["@babel/core"].integrity == "sha512-abc"
    assert pkgs["lodash"].version == "4.17.21"


def test_package_json_marks_floating_ranges(tmp_path):
    path = write(tmp_path, "package.json", json.dumps({
        "dependencies": {"react": "^18.0.0", "pinned": "1.2.3"},
        "devDependencies": {"jest": "*"},
    }))
    pkgs = by_name(npm.parse(path, str(tmp_path)))
    assert pkgs["react"].version is None and pkgs["react"].spec == "^18.0.0"
    assert pkgs["pinned"].version == "1.2.3"
    assert pkgs["jest"].dev is True


def test_requirements(tmp_path):
    path = write(tmp_path, "requirements.txt", '''
# a comment
--extra-index-url https://internal.example.invalid/simple
requests==2.31.0
flask>=2.0
django[argon2]==4.2.1
urllib3
git+https://github.com/example/thing.git#egg=thing
''')
    parsed = pypi.parse(path, str(tmp_path))
    pkgs = by_name(parsed)
    assert pkgs["requests"].version == "2.31.0"
    assert pkgs["flask"].version is None and pkgs["flask"].spec == ">=2.0"
    assert pkgs["django"].version == "4.2.1"
    assert pkgs["urllib3"].spec is None
    assert pkgs["thing"].meta["vcs"] is True
    # the extra index is reported against the file, not against each package
    manifest = [p for p in parsed if p.kind == "manifest"]
    assert len(manifest) == 1
    assert manifest[0].meta["extra_indexes"] == ["https://internal.example.invalid/simple"]
    assert all(p.kind == "package" for p in parsed if p.name != "requirements.txt")


def test_requirements_accept_equals_options_and_keep_vcs_names(tmp_path):
    path = write(tmp_path, "requirements.txt", """
--extra-index-url=https://internal.example.invalid/simple
git+https://github.com/example/my-package.git@v1.2.3
""")
    parsed = pypi.parse(path, str(tmp_path))
    package = next(pkg for pkg in parsed if pkg.kind == "package")
    manifest = next(pkg for pkg in parsed if pkg.kind == "manifest")
    assert package.name == "my-package"
    assert manifest.meta["extra_indexes"] == ["https://internal.example.invalid/simple"]


def test_requirements_hashes_count_as_integrity(tmp_path):
    path = write(tmp_path, "requirements.txt",
                 "requests==2.31.0 --hash=sha256:aaaa\nflask==3.0.0\n")
    pkgs = by_name(pypi.parse(path, str(tmp_path)))
    assert pkgs["requests"].integrity == "sha256"
    assert pkgs["flask"].integrity is None


def test_poetry_lock(tmp_path):
    path = write(tmp_path, "poetry.lock", '''
[[package]]
name = "requests"
version = "2.31.0"
category = "main"
files = [{file = "requests-2.31.0.tar.gz", hash = "sha256:aaa"}]

[[package]]
name = "pytest"
version = "7.4.0"
category = "dev"
files = []
''')
    pkgs = by_name(pypi.parse(path, str(tmp_path)))
    assert pkgs["requests"].version == "2.31.0"
    assert pkgs["requests"].integrity == "sha256"
    assert pkgs["pytest"].dev is True
    assert pkgs["pytest"].integrity is None


def test_pep503_normalisation():
    assert pypi.normalize("Python_Date.Util") == "python-date-util"
    assert pypi.normalize("ZOPE--interface") == "zope-interface"


def test_unreadable_manifest_is_skipped_not_fatal(tmp_path):
    path = write(tmp_path, "package-lock.json", "{ not json")
    assert npm.parse(path, str(tmp_path)) == []
