# Changelog

All notable changes to `SecureFileUpload.Core` are recorded here. The package
follows semantic versioning. `AssemblyVersion` is held at `3.0.0.0` across the
entire `3.0.x` line so patch releases are drop-in upgrades with no
binding-redirect churn; `3.1.0` moves `AssemblyVersion` to `3.1.0.0`, the
whole `3.2.x` line holds at `3.2.0.0` because it changes no IL, and the `3.3.x`
line holds at `3.3.0.0`.

## 3.3.1 — 2026-08-19 — Decode cap raised; 3.3.0 notes corrected

`AssemblyVersion` stays at `3.3.0.0`. Drop-in upgrade from `3.3.0`.

### Changed

- **`FileUpload:MaxNonJpegDecodePixels` default raised from 24 MP to 40 MP.** A 600 dpi
  A4 scan is roughly 35 MP, so the 24 MP default refused a mainstream way of submitting
  a document. 40 MP still bounds a single decode at about 160 MB, and the process-wide
  decode semaphore bounds how many run at once. JPEG keeps the higher 50 MP ceiling
  because it has a reduced-resolution decode path that PNG and WebP do not.

### Note on the 3.3.0 release notes

The `3.3.0` notes below were written before an adversarial review of that release's own
hardening, and understate it. `3.3.0` shipped with the review's findings fixed, but its
notes describe only the first version of the object-stream gate. Recorded here for anyone
auditing what `3.3.0` actually contains:

- **The object-stream gate checks whether contents were read, not what the file declares.**
  The first implementation trusted the stream dictionary and was bypassable by declaring
  `/FlateDecode` over bytes that are not deflate, by parking decoy streams ahead of the
  payload to exhaust the scan budget, by omitting `/Filter` entirely, and by padding the
  dictionary past the lookback window. Every path that skips an object stream now counts it
  as unscanned, and a document declaring `/ObjStm` with any unscanned object stream is
  refused.
- **Hex-escaped names are resolved before matching.** PDF 32000-1 §7.3.5 makes
  `/Type /Obj#53tm` equivalent to `/Type /ObjStm`, and every real reader resolves it. The
  document-level name extractor decoded escapes while the stream-level classifier did not,
  so writing the name escaped left the document counted as declaring an object stream while
  the stream itself classified as ordinary — switching the gate off entirely.
- **An unterminated literal string is now malformed.** *This one predates 3.3.0 and affects
  `3.2.2` and every earlier `3.x`.* An unclosed `(` made the lexer blank everything to
  end-of-file with no malformed flag, so any `/ObjStm`, `/JS` or `/Launch` declared after it
  was invisible to every surface scan and the stream ranges beyond it were never recorded.
  Opening a bracket and never closing it was a complete bypass of PDF content validation.
  **If you are pinned to `3.2.x`, this is the reason to upgrade.**
- **Nested stream scanning uses the correct surface.** Recursion classified inner streams
  against the outer document's text using offsets into the inflated buffer, reading whatever
  happened to sit at those positions.
- **A truncated object stream is not a scanned object stream.** Hitting the byte budget or
  the time budget mid-stream left the remainder unexamined while the file passed. Object
  streams also get their own byte budget, so an image-heavy document cannot exhaust the pool
  and cause a legitimate file to be refused.
- **Animated PNG and WebP are detected by walking chunk tables**, not by searching raw bytes
  for `acTL`/`ANIM`/`ANMF`. The byte search matched inside compressed pixel data often enough
  to refuse roughly 1 in 400 still WebP photographs.

## 3.3.0 — 2026-08-19 — Upload-pipeline hardening

`AssemblyVersion` moves to `3.3.0.0`. Two of these changes close holes that were
reachable on **default configuration** in `3.2.2` and every earlier `3.x`.

### Security

- **PDF object streams whose filter cannot be inspected are now rejected.** Object
  streams are accepted by default (`RejectPdfObjectStreams = false`) on the stated
  grounds that their contents are inflated and scanned. That promise did not hold:
  the scan loop caught any inflation failure and moved on, so an object stream the
  inflater could not read was skipped and the file accepted with its payload
  unexamined. Defeating the compressed-stream scanner required only declaring a
  filter it cannot process — `/Filter /LZWDecode` was enough.

  Two shapes cause this and only one throws, so catching the exception is not
  sufficient on its own: a non-Flate filter fails to inflate, while `FlateDecode`
  with a non-identity `/Predictor` inflates *successfully* and yields
  predictor-encoded bytes that are then scanned as meaningless noise. The gate runs
  before inflation is attempted and covers both.

  Scope is deliberately narrow. Only `/Type /ObjStm` is gated; ordinary content
  streams that fail to inflate are still skipped, since rejecting those would fail
  large numbers of legitimate documents for no security gain. Cross-reference
  streams commonly carry `/Predictor 12` and are untouched for the same reason.
  Controlled by the new `RejectUninspectableObjectStreams` (default `true`).

- **Image decode memory is now bounded.** The sanitizing re-encode decodes every
  accepted image, and its only bound was the deep validator's `MaxImagePixels`
  (300,000,000 by default). That is a structural sanity limit, not a memory limit:
  at roughly 4 bytes per pixel a 300 MP image is a ~1.2 GB bitmap, and a PNG
  declaring those dimensions compresses to a few hundred kilobytes. A single upload
  could cost a gigabyte of RAM, and nothing bounded how many decoded at once.

  Two caps now gate the decode, read from `Image.Identify` so headers alone decide
  and an over-cap file is stopped before any pixels are materialized. What happens
  then follows the existing `FileUpload:RejectOnRecompressFailure`, since an
  over-cap image is the same situation that flag already governs — the image cannot
  be sanitized — so it is refused by default or stored undecoded if you have turned
  that off. No decode happens in either branch, so the memory bound holds
  regardless. Concurrent decodes are bounded by a process-wide semaphore rather than
  a per-instance one, which would give every request its own permit and bound
  nothing.

- **Rejection messages no longer disclose which validation gate fired.**
  `ContentValidationResult.ErrorMessage` carried the validator's internal reason —
  verbatim from `RejectPolicy`, prefixed from `RejectStructural`. Callers are
  expected to surface that field, so every rejection was a labeled oracle: an
  attacker could learn which check blocked a payload ("Missing %%EOF trailer",
  "Embedded ZIP detected at offset 1234") and tune the next attempt around it.
  `RejectMalicious` was already opaque; these two were not.

  `ErrorMessage` now resolves only from the closed `UploadRejectionMessageKey` set,
  whose values are compile-time constants that never echo file-derived bytes. Every
  PDF gate maps to one identical string so which check fired is not observable, with
  password-protected PDFs the sole deliberate exception because it is actionable.
  The reason still reaches the security log and `ThreatDescription`, which is for
  diagnostics and is **not** safe to display.

### Added

- `UploadRejectionMessageKey` and `UploadRejectionMessages` (public) — the closed set
  of user-safe rejection strings and its resolver.
- `FileContentValidatorOptions.RejectUninspectableObjectStreams` (default `true`).
- `FileUpload:MaxReencodeDecodePixels` (default 50,000,000) and
  `FileUpload:MaxNonJpegDecodePixels` (default 24,000,000).
- HEIC/HEIF containers are identified by their ISO-BMFF `ftyp` major brand.

### Changed

- **HEIC uploads are explained instead of being called malware.** HEIC is what
  iPhones and iPads capture by default and the files are routinely renamed to `.jpg`.
  Such an upload previously failed the magic-byte check and returned "File content
  does not match its extension. File may be corrupted or malicious." — wrong on the
  facts, and harmful, because training people to dismiss that warning devalues it for
  the case that matters. The format is still refused; only the explanation changes,
  and the event now logs at Information rather than as a `SECURITY_EVENT`.

### Upgrading — behaviour changes

- PNG and WebP uploads between 24 MP and the validator's `MaxImagePixels` are now
  refused, as are JPEGs above 50 MP. A 600 dpi A4 scan is roughly 35 MP and would be
  affected. Raise `FileUpload:MaxNonJpegDecodePixels` if you need those, understanding
  that the decode cost scales with it. If you already run with
  `FileUpload:RejectOnRecompressFailure = false`, over-cap images are stored
  undecoded instead of refused, so nothing starts failing for you.
- PDFs containing an object stream with a non-Flate filter or a non-identity
  `/Predictor` are now refused. Set `RejectUninspectableObjectStreams` to `false` to
  restore the previous behaviour, understanding that such streams go unscanned.
- `ContentValidationResult.ErrorMessage` no longer contains the specific reason. Code
  that parsed or displayed it for detail should read `ThreatDescription` instead — in
  logs, not in anything shown to the person who uploaded the file.

## 3.2.2 — 2026-08-19 — Dependency maintenance

No code, IL, or on-disk format change — no `.cs` file differs from `3.2.1`.
`AssemblyVersion` stays at `3.2.0.0`, so this is a drop-in upgrade from any
`3.2.x`.

### Changed

- **`SixLabors.ImageSharp` floor raised to `3.1.12`** (pin is now
  `[3.1.12,4.0.0)`). This is the only change visible to consumers of the
  package. The upper bound is unchanged and still deliberate: ImageSharp moved
  to a commercial Six Labors license at v4, and shipping v4 would push that
  obligation onto everyone who installs this package.
- **Build and test tooling only, not shipped:** `Microsoft.SourceLink.GitHub`
  `10.0.301` → `10.0.400` (`PrivateAssets="All"`), `Microsoft.NET.Test.Sdk`
  `18.8.1` → `18.9.0`, `xunit.runner.visualstudio` `3.1.5` → `4.0.0`, and the
  `Microsoft.Extensions.*` smoke-harness pins to `10.0.11`. The full suite
  passes unchanged at 41 tests on `net8.0`, `net9.0`, and `net10.0`.

### Fixed

- **Stale ImageSharp version in the docs.** The README and the csproj header
  comment both still described the pin as `[3.1.11,4.0.0)` after the floor
  moved to `3.1.12`.

### Repository

Not part of the package, recorded for provenance: `.github/dependabot.yml` now
groups the `Microsoft.Extensions.*` packages into a single pull request and
ignores `semver-major` updates to `SixLabors.ImageSharp`. The grouping fixes a
deadlock in which a lone `Microsoft.Extensions.Logging.Console` bump could
never pass CI — it requires `Microsoft.Extensions.Configuration.Binder` at the
same version, which its own single-package branch did not touch, so restore
failed with `NU1605`. The ignore rule stops v4 from being re-proposed on every
release while still admitting the `3.1.x` security patches that matter for a
library fed attacker-controlled bytes.

## 3.2.1 — 2026-07-29 — Documentation patch

No code, IL, or on-disk format change. `AssemblyVersion` stays at `3.2.0.0`, so
this is a drop-in upgrade from `3.2.0`.

### Fixed

- **Corrected config key for the PDF object-stream switch.** The `3.2.0` release
  notes, this changelog, and the `FileContentValidatorOptions` XML doc all
  documented it as `FileUpload:ContentValidation:RejectPdfObjectStreams`. The
  real key is **`FileContent:RejectPdfObjectStreams`** —
  `AddSecureFileUpload()` binds `FileContentValidatorOptions` to the top-level
  `"FileContent"` configuration section, so every property on that class is
  configured under that prefix. Anyone who set the documented key on `3.2.0` had
  it silently ignored and got the default (`false`). That default is the
  recommended value, so nothing was weakened — but an operator deliberately
  opting *in* to rejecting object streams was not getting it.
- **README documentation links are now absolute GitHub URLs.** The packaged
  README used relative markdown paths (`KNOWN-GAPS.md`,
  `SECURITY-ANALYSIS.md`, `SECURITY.md`, `LICENSE`, `docs/*`, `tests/*`) and
  in-page anchors. The NuGet gallery does not resolve those against the source
  repository, so every documentation link on the package page was dead.
- **Stale defaults in the sample `appsettings` block.** The `FileContent`
  section still showed the pre-`3.2.0` image dimension caps (`10000` px /
  `40000000` px²) and omitted `RejectPdfObjectStreams`,
  `MaxDecompressionRatio`, and `MaxPdfStreamScanMilliseconds`. The settings
  table gained rows for the `FileContent:*` options and for
  `VirusScan:FailClosedOnUnavailable`, which was described in prose but absent
  from the table.
- **Stale upgrade guidance.** The install note still claimed `AssemblyVersion`
  was pinned at `3.0.0.0`; it has tracked the package version since `3.1.0`.
  The AV-availability switch was also attributed to `3.0.2` rather than
  `3.0.3`, and the dependency list said "ASP.NET Core 10+" for a package that
  multi-targets `net8.0` / `net9.0` / `net10.0`.

### Changed

- **README leads with what the package does**, followed by the eight pipeline
  layers as an explicit list rather than a bare layer count, and now carries
  the `3.1.0` and `3.2.0` release notes that were missing from the packaged
  copy. Older release sections are condensed with a pointer here.

## 3.2.0 — 2026-07-26 — Token-aware PDF lexing, real-world false-rejection fixes

No public API break. `FileContentValidatorOptions` gains one property
(`RejectPdfObjectStreams`); three existing defaults change (see *Changed*),
all revertible by config.

This release back-ports the deep content validator rework from the production
intake application this package was lifted from, and merges it with the
compressed-stream scanner that only existed here. Neither side had both.

### Added

- **`FileContent:RejectPdfObjectStreams`** (default `false`).
  Object streams (`/ObjStm`) are standard in PDF 1.5+ — Word, Acrobat, browser
  "Print to PDF", and every mainstream phone scanner app emit them — so they
  are accepted and their contents scanned rather than refused. Operators with a
  controlled producer set can flip this to `true`. (`AddSecureFileUpload()` binds
  `FileContentValidatorOptions` to the top-level `"FileContent"` section, so every
  `FileContentValidatorOptions` property is configured under that prefix.)
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
  is scanned and then fails to write is no longer reported as stored. The
  fail-closed rejection path still counts, because `ScanNotScannedCount` is the
  uniform skip signal operators alert on in both availability modes.
- **`SixLabors.ImageSharp` pinned to `[3.1.11,4.0.0)`.** ImageSharp moved to a
  commercial Six Labors license at v4 — the build fails without a paid license
  key, and shipping it would push that obligation onto every consumer of this
  package. The range still admits 3.1.x security patches, which matters because
  ImageSharp is fed attacker-controlled bytes by design.

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
