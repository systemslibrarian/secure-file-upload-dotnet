# Changelog

All notable changes to `SecureFileUpload.Core` are recorded here. The package
follows semantic versioning. `AssemblyVersion` is held at `3.0.0.0` across the
entire `3.0.x` line so patch releases are drop-in upgrades with no
binding-redirect churn.

## 3.0.3 — 2026-06-01 — Defense-in-depth hardening

Backward-compatible patch. No public API break. Drop-in upgrade from any
`3.0.x`.

### Added

- **`SECURITY.md`** — explicit crypto classification (classical AES-256-GCM,
  no PQ asymmetric layer), AV failure-mode posture, and the deliberate
  separation from the `PostQuantum.*` family.
- **`VirusScan:FailClosedOnUnavailable`** configuration option
  (default `false`). When `true`, scanner unavailability rejects the upload
  rather than accepting it as `NotScanned`. Detection mode is always
  fail-closed regardless of this flag.
- **Uniform `VIRUS_SCAN_SKIPPED` security event** emitted in both fail-open
  and fail-closed availability modes, so operators alert on a single signal.
- **PDF FlateDecode walker hard caps**:
  - `FileContent:MaxPdfStreamScanMilliseconds` (default `2 000` ms) — per-file
    wall-clock budget for the compressed-stream scan.
  - `FileContent:MaxDecompressionRatio` (default `200`) — per-stream
    expansion-ratio cap; a stream over the cap is rejected as
    `PDF-DecompressionBomb`.
  - `FileContent:MaxPdfStreamRecursionDepth` (default `2`) — bounded walk
    into nested `/ObjStm` compressed object streams.
  - Full `CancellationToken` propagation through `ScanCompressedPdfStreams`
    so a cancelled validation aborts deterministically.
- **`HardeningRegressionTests`** — 25 new test cases covering the filename
  evasion matrix, legitimate accented/CJK/Cyrillic/Greek filename
  acceptance, decompression-bomb rejection within the time budget, nested
  FlateDecode recursion, cancellation propagation, fail-closed AV mode,
  concurrent encrypted uploads, and `PathHelper.IsPathUnderBase`
  encoded-separator resistance.
- **`tests/Fuzz/seeds/`** directory with a corpus convention doc. Fuzz
  harness gains a triage assertion: any `Allowed` verdict on a seed under
  `/seeds/` exits non-zero (a curated bad-input that passes is a finding).

### Changed

- **Filename validation** (`ContainsSuspiciousPatterns`) now NFKC-normalizes
  the input before all checks. This catches:
  - Fullwidth `．．` (U+FF0E ×2) disguising `..` path traversal.
  - Fullwidth letters disguising Windows reserved device names
    (`ＣＯＮ.pdf`).
  - Fullwidth-disguised double-extensions (`evil．exe.pdf`).
- **Trailing dot or space** is now rejected (Windows path resolution strips
  these, so `evil.exe.` would otherwise resolve to `evil.exe` after the
  extension allowlist check).
- **255-character length cap** on the input filename.
- **`README.md`**: production-provenance lead; per-layer plain-English
  table; explicit AV failure-mode section; classical-not-PQ row in the
  Crypto Posture table.
- **`KNOWN-GAPS.md` §Gap 9**: updated to describe the new configurable
  availability mode while noting that the default still matches the prior
  behavior.

### Verified non-changes (the things that did NOT change)

- 8-layer pipeline order.
- v2 envelope encryption format (`ENCGCM\0\x02`) — byte-for-byte
  compatible with `3.0.0` / `3.0.1` / `3.0.2`.
- Argon2id KEK derivation defaults (`m=64 MiB, t=3, p=4`).
- PBKDF2-SHA256 legacy decrypt fallback (`600 000` and `210 000` iter).
- Plaintext / DEK / KDF-input zeroing in `finally` blocks.
- `AssemblyVersion = 3.0.0.0`.

Smoke harness: 18 / 18 pass. xUnit suite: 33 / 33 pass on net8.0, net9.0,
and net10.0.

## 3.0.2 — Multi-targeting restored

Re-published the same source as a multi-targeted package targeting `net8.0`,
`net9.0`, and `net10.0` so any currently-supported .NET runtime can take the
`3.x` hardening. No behavioral, on-disk-format, or crypto-posture changes
from `3.0.1`.

## 3.0.1 — Documentation and code-hygiene patch

- README: new "Deployment notes" section covering multi-instance Data
  Protection key persistence.
- README: token-replay window documented along with the existing
  mitigations.
- Pruned unused `SanitizeForLog` helper from `SecureFileDownloadController`.

## 3.0.0 — Hardened download surface

Breaking changes vs `2.0.0`:

- The reference download endpoint accepts an opaque `fileToken` instead of
  a storage-relative `relativePath` query parameter.
- `AddSecureFileUpload()` registers `IFileAccessTokenService` and the
  reference controller assumes tokenized download links.

Highlights:

- Opaque, signed, time-limited download tokens backed by ASP.NET Core
  Data Protection.
- Release validation includes solution tests + the runtime smoke harness
  before pack / publish.
- Scanner outage logging aligned with actual `NotScanned` fail-open
  pipeline behavior.

The 8-layer upload pipeline, on-disk envelope formats, and
Argon2id / PBKDF2 decryption compatibility are unchanged from `2.0.0`.

## 2.0.0 — Argon2id KEK + .NET 10

Modernized line. Argon2id (memory-hard, RFC 9106) for the master KEK with
PBKDF2 600 000-iter FIPS opt-in and 210 000-iter legacy decrypt fallback.

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31
