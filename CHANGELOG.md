# Changelog

## 0.2.0

The theme is signals that only became available recently, plus a way to review
a change instead of a whole repository.

### Added

- **`HEM701`, known malware.** Queries osv.dev, which aggregates the OpenSSF
  malicious-packages feed, and reports when a record names the exact version
  installed. Withdrawn records are skipped: OSV pulled 157 false-positive
  malware reports in May 2026, and a scanner that keeps failing builds on a
  retracted record is worse than no scanner.
- **`HEM702`, published advisories**, from the same batched OSV request.
  Replaces the PyPI-only advisory check and now covers npm as well.
- **`HEM601` and `HEM602`, build provenance.** Reads npm SLSA attestations and
  PyPI PEP 740 attestations. `HEM602` fires when the repository that signed the
  build is not the repository the package points you at.
- **`hemlock diff`.** Scores only what a change added or moved, against two
  manifests or any git ref via `--since`. Exits non-zero on the same thresholds
  as `scan`.
- Rules can be marked `certain`, which settles a verdict without scoring it.
  Only `HEM701` is.
- Terminal output gained a malware banner, change markers in the diff view,
  staged progress with a spinner, and a request/cache line in online mode.

### Changed

- **Rule ids were renumbered.** `503→601`, `504→503`, `505→504`, `506→505`,
  `507→702`, `508→506`. Update `.hemlock.toml` if it names any of those. This
  was a pre-release cleanup and ids are stable from here.
- `HEM601` replaces the old "release is unsigned" check. Registry signatures
  are now universal enough to say nothing; provenance is the signal that
  replaced them.
- All online work goes through one cached HTTP layer, so OSV costs one batched
  request for the whole dependency list rather than one per package.

### Fixed

- **`HEM502` false positive on pinned older versions.** Prior publishers were
  taken from the most recent releases rather than the ones preceding the
  version in question, so `express@4.18.2` looked like an account takeover
  because the 5.x line has different maintainers.

## 0.1.0

First release. Twenty-three rules across naming, install-time execution, code
shape, pinning and registry trust. Terminal, JSON and SARIF output, a
transparent scoring model, and `hemlock explain`.
