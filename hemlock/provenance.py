"""Build provenance for npm and PyPI.

Both registries can now tell you which repository, workflow and commit a
release was built from, signed through Sigstore and verified on upload:

  npm   SLSA provenance, published automatically by trusted publishing
  PyPI  PEP 740 attestations, carrying the publisher identity directly

The two formats are different shapes and get normalised to one here, so the
rules never have to care which registry a package came from.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse

from .http import Http

NPM_ATTESTATIONS = "https://registry.npmjs.org/-/npm/v1/attestations/"
PYPI_INTEGRITY = "https://pypi.org/integrity/"
SLSA_V1 = "https://slsa.dev/provenance/v1"


def repo_slug(value) -> str | None:
    """Reduce any way a repository gets written down to 'owner/name'.

    package.json alone yields git+ssh://, git+https://, plain https://,
    'github:owner/name', and a bare 'owner/name'. They all mean one thing.
    """
    if isinstance(value, dict):
        value = value.get("url") or value.get("repository") or ""
    if not isinstance(value, str) or not value.strip():
        return None

    text = value.strip()
    text = re.sub(r"^(git\+|git:)", "", text)
    text = re.sub(r"^(github|gitlab|bitbucket):", "", text)

    if "://" in text:
        parsed = urllib.parse.urlparse(text)
        path = parsed.path
    elif text.startswith("git@") or "@" in text.split("/")[0]:
        path = text.split(":", 1)[-1]
    else:
        path = text

    path = re.sub(r"\.git$", "", path.strip("/"))
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    return f"{parts[-2]}/{parts[-1]}".lower()


def npm_provenance(name: str, version: str, http: Http) -> dict | None:
    url = NPM_ATTESTATIONS + urllib.parse.quote(f"{name}@{version}", safe="@")
    doc = http.get(url, allow_404=True)
    if not doc:
        return None

    for attestation in doc.get("attestations") or []:
        statement = _dsse_statement(attestation)
        if not statement or statement.get("predicateType") != SLSA_V1:
            continue
        build = (statement.get("predicate") or {}).get("buildDefinition") or {}
        workflow = (build.get("externalParameters") or {}).get("workflow") or {}
        resolved = (build.get("resolvedDependencies") or [{}])[0]
        return {
            "source": "slsa",
            "repository": repo_slug(workflow.get("repository")),
            "workflow": (workflow.get("path") or "").rsplit("/", 1)[-1] or None,
            "ref": workflow.get("ref"),
            "commit": (resolved.get("digest") or {}).get("gitCommit"),
        }
    return None


def pypi_provenance(name: str, version: str, filename: str, http: Http) -> dict | None:
    url = f"{PYPI_INTEGRITY}{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/{urllib.parse.quote(filename)}/provenance"
    doc = http.get(url, allow_404=True)
    if not doc:
        return None

    for bundle in doc.get("attestation_bundles") or []:
        publisher = bundle.get("publisher") or {}
        if not publisher:
            continue
        return {
            "source": "pep740",
            "kind": publisher.get("kind"),
            "repository": repo_slug(publisher.get("repository")),
            "workflow": publisher.get("workflow"),
            "ref": publisher.get("environment"),
            "commit": None,
        }
    return None


def _dsse_statement(attestation: dict) -> dict | None:
    envelope = (attestation.get("bundle") or {}).get("dsseEnvelope") or {}
    payload = envelope.get("payload")
    if not payload:
        return None
    try:
        return json.loads(base64.b64decode(payload))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def describe(prov: dict) -> str:
    """One human-readable line: where this artifact was actually built."""
    bits = [prov["repository"]] if prov.get("repository") else ["an unnamed repository"]
    if prov.get("commit"):
        bits.append(f"@{prov['commit'][:7]}")
    line = "".join(bits)
    if prov.get("workflow"):
        line += f" via {prov['workflow']}"
    return line
