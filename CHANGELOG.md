# Changelog

All notable changes to `SecureFileUpload.Core` are recorded here. The package
follows semantic versioning. `AssemblyVersion` is held at `3.0.0.0` across the
entire `3.0.x` line so patch releases are drop-in upgrades with no
binding-redirect churn; `3.1.0` moves `AssemblyVersion` to `3.1.0.0`.

## 3.2.0 — 2026-07-26 — Token-aware PDF lexing, real-world false-rejection fixes

No public API break. `FileContentValidatorOptions` gains one property
(`RejectPdfObjectStreams`); three existing defaults change (see *Changed*),
all revertible by config.

This release back-ports the deep content validator rework from the production
intake application this package was lifted from, and merges it with the
compressed-stream scanner that only existed here. Neither side had both.

### Added

- **`FileUpload:ContentValidation:RejectPdfObjectStreams`** (default `false`).
  Object streams (`/ObjStm`) are standard in PDF 1.5+ — Word, Acrobat, browser
  "Print to PDF", and every mainstream phone scanner app emit them — so they
  are accepted and their contents scanned rather than refused. Operators with a
  controlled producer set can flip this to `true`.
- **Compressed-stream contents are now name-scanned.** `ScanCompressedPdfStreams`
  inflates stripped stream payloads and runs the same name-object extraction over
  the decompressed dictionaries, so `/JavaScript` or `/Launch` declared inside an
  object stream is found. Previously the interior was matched by raw substring,
  which both missed hex-escaped spellings and false-positived on `/JSON`.
- **PDF name-object lexer** — `/JS`, `/Launch`, `/OpenAction` and friends are
  matched by extracting real name objects and decoding `#xx` hex escapes.
- **Image metadata-region scoping** — text threat scans on JPEG/PNG/WebP/GIF are
  confined to metadata and comment segments (JPEG `APPn`/`COM`, PNG
  `tEXt`/`iTXt`/`zTXt`, WebP `EXIF`/`XMP`, GIF comment/application) instead of
  running across entropy-coded pixel data.
- **Compressed PNG text chunks are inflated before scanning** (`zTXt`, and
  `iTXt` with the compression flag set), with per-chunk and total output bounds.
- **Atomic upload writes** — files are written to a temporary sibling and moved
  into place, so an interrupted write never leaves a partial file at the
  destination. Success is logged only after the move.
- **Storage-root containment on decrypt** — `GetDecryptedFileStreamAsync`
  normalizes the path, enforces containment under the storage root, and rejects
  reparse points in every path component.

### Changed

- **`RejectPdfObjectStreams` defaults to `false`** (was: object streams rejected
  outright). Their contents are now inflated and scanned, so this is a net
  increase in inspection coverage, not a relaxation.
- **Post-EOI JPEG data is scanned but no longer rejected** for failing to match a
  recognized container. The old allowlist refused MPF second images (Samsung,
  Sony, Fujifilm), Samsung Motion Photo SEF footers, and alignment padding — the
  most common trailers in the wild. Detection now comes from scanning the bytes.
- **Image dimension caps raised** to 30000 px / 300 MP (from 10000 px / 40 MP).
  These guard against decompression pixel bombs only; the previous values
  false-rejected ordinary 48–200 MP smartphone photos.
- **`VirusScanOutcome.NotScanned` split into `Disabled` and `Unavailable`** so
  "no scanner configured" and "configured scanner failed" are distinguishable in
  logs. Both remain fail-open and both count toward `ScanNotScannedCount`.
- **Scan counters are incremented only after storage succeeds**, so a file that
  is scanned and then fails to write is no longer reported as stored.

### Fixed

- **`StripPdfStreamPayloads` treats `stream` as a lexical token.** A plain
  `IndexOf` matched inside comments, literal strings, and names such as
  `/upstream`, which discarded the rest of the document and hid every dangerous
  token that followed. The compressed-stream scanner is now driven by the same
  lexer rather than its own substring search.
- **`FindPdfToken` no longer treats `(` and `%` as string and comment markers
  while searching raw stream data**, where both are ordinary bytes. That
  mis-parse swallowed the real `endstream` and structurally rejected any PDF
  whose producer writes an indirect `/Length` — Ghostscript, MFP firmware, and
  PDF/A converters among them.
- **Threat scans iterate every occurrence of a pattern** instead of stopping at
  the first; a short decoy that failed the printable-run gate used to abandon
  the pattern entirely.
- **Metadata regions are delimited** so a pattern cannot be synthesized across
  the boundary of two unrelated segments.
- **JPEG end-of-image is located by walking segments and the entropy-coded
  scan**, which makes post-EOI data findable and therefore scannable at all.
- **Ambiguous PHP short-open-tag patterns removed**, ending false-positive
  `JPEG-EmbeddedShell` rejections of legitimate phone photos.
- **Cancellation is checked before deep validation** for every file type, not
  only for PDFs that happen to carry a compressed stream.

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
