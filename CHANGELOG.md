# Changelog

All notable changes to `SecureFileUpload.Core` are recorded here. The package
follows semantic versioning. `AssemblyVersion` is held at `3.0.0.0` across the
entire `3.0.x` line so patch releases are drop-in upgrades with no
binding-redirect churn; `3.1.0` moves `AssemblyVersion` to `3.1.0.0`.

## 3.1.0 — 2026-07-02 — Fail-closed sanitization, user-bound download tokens

No public API break — `FileAccessTokenService` gains one optional constructor
parameter (`IHttpContextAccessor?`), resolved by DI; existing call sites
compile unchanged. One deliberate behavioral change, revertible by config
(see *Changed*).

### Added

- **`FileUpload:RejectOnRecompressFailure`** (default `true`). Governs the
  failure mode of the Gap 1 sanitizing re-encode — see *Changed*.
- **`FileDownload:BindTokensToUser`** (default `false`). When `true`, the
  authenticated user's identity (`ClaimTypes.NameIdentifier`, falling back to
  `Identity.Name`) is folded into the Data Protection purpose chain at token
  creation. A token replayed by a *different* authenticated account fails
  cryptographic verification — not merely a policy check. Issuing a token on
  an unauthenticated request throws; startup fails fast if the flag is on but
  no `IHttpContextAccessor` is available. `AddSecureFileUpload()` now calls
  `AddHttpContextAccessor()` (a no-op if the host already registered it).
- **`.github/dependabot.yml`** — weekly update PRs for `nuget` (ImageSharp is
  fed attacker-controlled bytes by design; its advisories should open PRs
  automatically) and `github-actions` ecosystems.
- **`HardeningV310Tests`** — fail-closed and fallback recompression paths,
  valid-image round-trip (no over-rejection), HTML-neutralized error output,
  and the token-binding matrix (same-user resolve, cross-user replay
  rejection, anonymous issuance refusal, unbound default round-trip).

### Changed

- **Image recompression now fails closed** (Gap 1). Previously, if the
  sanitizing re-encode failed, the pipeline logged a warning and stored the
  *original* validated bytes — but a file whose header parses
  (`Image.Identify`, structural walkers) while its pixel data fails a full
  decode is exactly the shape of a crafted polyglot, so the fallback silently
  defeated the mitigation and kept any appended tail on disk. The upload is
  now rejected with a clear per-file message
  (`SECURITY_EVENT | FILE_SAVE_BLOCKED_SANITIZATION`). Set
  `FileUpload:RejectOnRecompressFailure=false` to restore the old behavior.
- **`SanitizeForLog` neutralizes HTML-active characters** (`<`, `>`, `"`,
  `'` → `?`). Its output is embedded in user-facing `FileUploadResult.Errors`
  strings; a consumer rendering those errors without encoding could
  previously be handed markup from a filename like `<svg onload=…>.jpg`.
- **Windows Defender scan timeout** now clamps with a lower bound of 1 s
  (`Math.Clamp(configured, 1, 120)`, matching ClamAV). A configured `0`
  previously made every scan time out instantly — silently disabling
  scanning under the fail-open availability default.
- **ClamAV `MaxStreamBytes` ≤ 0** now falls back to the 25 MiB default with
  a warning instead of exhausting the budget before the first chunk and
  failing every scan.
- **GitHub Actions pinned to commit SHAs** in both workflows (tag-pinning is
  mutable; Dependabot keeps the pinned SHAs current).
- **`.gitignore`** — local pack-inspection scratch folders (`_extract/`,
  `_verify/`, `_pack_inspect/`) ignored so unpacked binaries can't be
  committed accidentally.

### Unchanged

- The 8-layer pipeline order, on-disk envelope formats (`ENCGCM\0\x01` /
  `\x02`), Argon2id KEK derivation, PBKDF2 legacy decrypt fallback, and the
  plaintext/DEK zeroing discipline.

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
