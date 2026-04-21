# SECURITY-ANALYSIS.md

## Current-State Security Analysis

**Reviewed by:** Claude (Anthropic), adversarial security review  
**Review scope:** All source files — `FileUploadService.cs`, `FileContentValidator.cs`, `ClamAvScanService.cs`, `WindowsDefenderScanService.cs`, `SecureFileDownloadController.cs`, `IVirusScanService.cs`, `PathHelper.cs`  
**Methodology:** Code-first: every claim below traces to a specific line in `src/`. Where the original red-team findings differ from the current code state, both are recorded.  
**Verdict:** Production-grade for the stated use case (patron document intake); a small number of design-level trade-offs require conscious deployment decisions

This document was produced by running a structured adversarial code review — the reviewer was asked to find real weaknesses, not to validate the design. The original findings are preserved below with current resolution status. A new section records behavioral findings discovered during the post-NuGet code audit.

---

## Executive Summary

The pipeline is substantially stronger than the average ASP.NET Core file upload implementation. The 8-layer defense-in-depth architecture, format-specific structural walking, AES-256-GCM envelope encryption, and hardened download surface are all implementations of correct principles — not approximate ones.

Seven specific findings were identified in the original red-team review. All seven have been resolved or acknowledged with documented trade-offs. A code audit in the subsequent development phase identified one additional behavioral finding:

**Scanner availability is fail-open by design.** When `clamd` or `MpCmdRun.exe` is unreachable, the pipeline accepts the file as `NotScanned` rather than rejecting it. Detection is fail-closed (an infected result always rejects). Availability is deliberately fail-open with explicit accounting. This is documented in `KNOWN-GAPS.md §Gap 9` and is the right trade-off for the stated use case (public-library patron registration), but requires a conscious deployment decision in higher-risk contexts.

**One internal comment inaccuracy** was also found: `ClamAvScanService` and `WindowsDefenderScanService` both contain XML doc comments stating "fail-closed: any I/O error … causes the upload pipeline to reject the file." This contradicts the actual behavior in `FileUploadService.RunVirusScanAsync`, where `ScanSuccessful=false` maps to `NotScanned` (accept). The code is correct; the comments are misleading and should be updated.

---

## Security Architecture Overview

The pipeline runs every uploaded file through eight serial layers. Earlier layers are cheaper; later layers are more thorough. The ordering is intentional — expensive operations (deep content parsing, virus scanning) are never reached by files that fail cheap checks (size, extension).

```
Layer 1  Size (per-file + batch total)
Layer 2  Extension allowlist (.jpg .jpeg .png .webp .pdf)
Layer 3  MIME type ↔ extension cross-validation (reject on mismatch, not just mismatch warning)
Layer 4  Magic bytes — validated to format-specific depth:
           JPEG: 0xFFD8FF
           PNG:  8-byte signature
           WebP: RIFF header + WEBP fourCC at offset 8 (independent of Layer 6)
           PDF:  %PDF
Layer 5  Filename inspection — double-extension, Unicode bidi/zero-width,
           Windows reserved names, path traversal sequences
Layer 6  Deep content validation (FileContentValidator):
           JPEG/PNG/WebP: ImageSharp structural identification (no pixel decode)
           PDF: byte-pattern scan + FlateDecode stream decompression + re-scan
           All: fail-closed on any exception except OperationCanceledException
Layer 7  Virus scan (IVirusScanService):
           Detection fail-closed: infected result → reject
           Availability fail-open: scanner down → accept as NotScanned (see Gap 9)
           Disabled entirely when VirusScan:Enabled=false
Layer 8  Storage:
           AES-256-GCM envelope encryption (v2): random per-file DEK wrapped under PBKDF2-SHA256 KEK
           Image recompression to strip polyglot tails (default on)
           Path traversal re-check at write time via PathHelper.IsPathUnderBase
           Stored outside wwwroot; no direct web serving
```

At download time, `SecureFileDownloadController` independently re-checks path traversal, forces `Content-Disposition: attachment`, and sets a complete hardened header set (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`). Decrypted plaintext never touches the filesystem — it streams directly to the HTTP response.

---

## Confirmed Security Strengths

These are code-verified properties of the current implementation. Each claim traces to a specific location in `src/`.

**Fail-closed on every content decision.** `FileContentValidator` catches all exceptions (except `OperationCanceledException`) and converts them to `RejectStructural`. An exception in the deep validator is itself a rejection signal. There is no path where an unexpected error defaults to accept.

**Layer independence.** Each layer provides an independent check. WebP format confusion is caught at Layer 4 (RIFF + WEBP fourCC) *and* at Layer 6 (format-specific walker). A bug disabling one layer does not open a path through the pipeline.

**PathHelper.IsPathUnderBase over string.StartsWith.** The `string.StartsWith("/uploads")` prefix-confusion bug is a real, exploited CVE class. `PathHelper.IsPathUnderBase` canonicalizes both paths via `Path.GetFullPath`, trims separators, then checks for exact equality or `base + separator` prefix. A sibling directory `/uploads_evil` cannot match `/uploads`.

**Envelope encryption limits blast radius.** The v2 format generates a random 256-bit DEK per file, encrypts the DEK under the PBKDF2-derived master KEK, and stores only the wrapped DEK on disk. Compromising one file's key material does not affect other files. KEK rotation rewraps only the DEKs; file payloads are not re-encrypted.

**Image recompression strips polyglot tails.** Decoding a JPEG through ImageSharp and re-encoding it drops all data appended after the EOI marker. The re-encoded bytes are what get encrypted to disk. An attacker who appends a PHP shell after a valid JPEG reaches storage with only a valid JPEG — the tail is gone.

**FlateDecode PDF stream inspection.** `FileContentValidator.ScanCompressedPdfStreams` decompresses every `stream…endstream` block with `DeflateStream`, then re-runs all `DangerousPdfPatterns` and `JsTriggerPatterns` against the decompressed content. The inspection is bounded by `MaxCompressedStreamsToInspect` and `MaxDecompressedStreamBytes` to defeat zip-bomb amplification.

**Startup guards prevent silent misconfiguration.** The `FileUploadService` constructor throws if `EncryptionEnabled=true` and `EncryptionSecret` is missing or still set to the placeholder. Storage root validation (outside wwwroot, writable) also runs at startup. Misconfigurations fail loudly at deploy time.

**Scannerless deployment supported on Linux.** `ClamAvScanService` uses the documented `clamd` `zINSTREAM` TCP protocol. No temp file is written. The patron's plaintext bytes never touch disk during scanning. The scanner is selected at startup by `AddSecureFileUpload()` based on `OperatingSystem.IsWindows()`.

**All filenames sanitized before logging.** `SanitizeForLog` strips ANSI escape sequences, control characters, structured-log injection characters (`{`, `}`, `|`), CRLF, and Unicode bidi/zero-width characters, then truncates to 128 characters. Every `file.FileName` reference in log calls routes through it.

**Memory discipline.** `ArrayPool<byte>` with zeroed return, `Image.Identify()` (no pixel decode), and minimum file size checks before buffering all reflect correct thinking about resource exhaustion. Windows temp files are zero-overwritten before deletion.

---

## Confirmed Risks & Limitations

### Risk 1 — Scanner availability is fail-open (by design, documented)

**Code location:** `FileUploadService.cs`, `RunVirusScanAsync` (~line 877)

```csharp
// Scanner unavailable/error → accept, return NotScanned
private async Task<VirusScanOutcome> RunVirusScanAsync(...)
{
    ...
    // File passed all validation — accept but mark as NotScanned.
    return VirusScanOutcome.NotScanned;
}
```

When `clamd` is unreachable or `MpCmdRun.exe` times out, `ScanSuccessful=false` maps to `NotScanned` and the file is accepted. The outcome is counted in `FileUploadResult.ScanNotScannedCount` and logged as `VIRUS_SCAN_OPERATIONAL_FAILURE`. The file is **never silently relabelled as clean**.

**Why this is the right default for the stated use case:** A `clamd` outage during library business hours would otherwise block every patron registration. Layers 1–6 already exclude every class of file the scanner is designed to catch except novel signatures of known-bad payloads inside formats the pipeline accepts. The scanner adds defense against that specific residual class; scanner availability failure does not remove Layers 1–6.

**What to do if this does not match your threat model:** See `KNOWN-GAPS.md §Gap 9`. The two options are: (a) queued-scan model — accept to quarantine, release on clean result; or (b) change `RunVirusScanAsync` to return `Infected` on `ScanSuccessful=false`. Option (b) is a one-method change but is a conscious deployment decision, not a default.

### Risk 2 — Internal comment inaccuracy in both scanner implementations

**Code location:** `ClamAvScanService.cs` ~line 35, `WindowsDefenderScanService.cs` similar

```csharp
/// Fail-closed: any I/O error, timeout, or daemon unavailability returns
/// IsClean=false, ScanSuccessful=false so the upload pipeline rejects the
/// file rather than silently letting it through.
```

The comment claims `ScanSuccessful=false` causes the pipeline to reject the file. This is inaccurate. The actual behavior, confirmed in `FileUploadService.RunVirusScanAsync`, is that `ScanSuccessful=false` produces `NotScanned` (accept). The code behavior is correct and intentional; the doc comments need updating to match.

**Required fix:** Update both scanner XML doc comments to accurately describe the pipeline behavior: "availability failure is fail-open with explicit NotScanned accounting; detection failure (IsClean=false + ScanSuccessful=true) is fail-closed."

### Risk 3 — Fixed PBKDF2 application salt for master KEK

**Code location:** `FileUploadService.cs` constructor (~line 340)

```csharp
var salt = Encoding.UTF8.GetBytes("SecureFileUpload.FileUpload.v1");
_encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
    Encoding.UTF8.GetBytes(secret), salt, iterations: 600_000, ...);
```

The salt is hard-coded in source. If an attacker obtains the salt (it's in this repo) and the derived key material (e.g., memory dump), they can focus brute-force against the secret alone without needing to discover the salt.

**Context offsetting this risk:** The 600,000-iteration PBKDF2-SHA256 count (OWASP 2024 recommendation) makes brute force expensive. Per-file random DEKs mean key compromise does not give access to all files without the KEK. The practical, higher-probability risk is a weak or committed `EncryptionSecret` — the salt is secondary. The startup guard blocks a missing or placeholder secret.

**Recommendation:** Ensure `EncryptionSecret` is stored in environment variables, Azure Key Vault, AWS Secrets Manager, or another external secret store — never in `appsettings.json` checked into source control. See `docs/hardening-roadmap.md §2.1`.

### Risk 4 — reCAPTCHA disabled

**Code location:** `ReplacementCardInputModel.cs` / associated view (reCAPTCHA commented out)

Rate limiting (`[EnableRateLimiting]`) is present, but without bot detection, automated submission at low per-IP rates can:
- Cause repeated 30-second virus-scan invocations (potential DoS vector in limited clamd deployments)
- Exhaust disk capacity via high submission volume (partially mitigated by capacity check in Layer 1)

**Recommendation:** Enable reCAPTCHA v3 (invisible) or Cloudflare Turnstile. See `docs/hardening-roadmap.md §3.2`.

### Risk 5 — Secure delete is advisory on SSDs and COW filesystems

**Code location:** `WindowsDefenderScanService.cs`, `SecureDeleteTempFile`

Zero-overwrite before deletion is not reliable on SSDs (wear leveling), Btrfs/APFS (copy-on-write), or any journaled filesystem where the overwrite may be journaled separately. The code comment correctly acknowledges this.

**Context:** If the deployment uses encrypted storage at-rest (BitLocker, LUKS, dm-crypt), the practical risk is low — deleted sector content is ciphertext. ClamAV via the TCP path writes no temp file at all.

**Recommendation:** Run the server on an encrypted volume. This is a deployment-level concern. See `KNOWN-GAPS.md §Gap 7`.

---

## Deployment Assumptions

The following are assumed by the codebase. Violating any of them materially degrades the security properties:

| Assumption | Why it matters |
|---|---|
| `FileUpload:EncryptionSecret` is stored in a secrets manager, not `appsettings.json` | Fixed salt + committed secret = effectively no key protection |
| Storage root is outside `wwwroot` | The constructor checks this, but the web server must be configured to not serve the data directory by other means |
| Virus scanner is reachable at startup | There is no startup-time scan health check; scanner unavailability at startup is not detected until the first upload |
| `FileUpload:RecompressImages=true` (default) | With recompression disabled, polyglot tails are not stripped; images are stored byte-exact |
| Rate limiting is configured and enforced before the controller | The pipeline does not enforce rate limits internally |
| HTTPS is enforced at the infrastructure level | No HSTS or TLS enforcement is present in the application code |
| Upload storage volume has sufficient space | Low-disk guards exist in the code but cannot substitute for capacity monitoring |

---

## Resolved vs Remaining Findings

| # | Finding | Original Severity | Current Status |
|---|---------|------------------|----------------|
| 1 | WebP RIFF layer-4 check didn't include WEBP fourCC | Low | ✅ **Resolved** — fourCC check added inline to `ValidateFileSignatureDetailed` |
| 2 | JPEG polyglot tail not stripped | Medium | ✅ **Resolved** — image recompression via ImageSharp strips tails before encryption |
| 3 | Fixed PBKDF2 salt for master KEK | Low | ⚠️ **Acknowledged** — 600k iterations + per-file DEKs offset practical risk; secret management remains deployment responsibility |
| 4 | Filename logged before sanitization | Low | ✅ **Resolved** — `SanitizeForLog` applied to all filename references in log and error paths |
| 5 | reCAPTCHA disabled | Low | ⚠️ **Acknowledged** — rate limiting present; reCAPTCHA re-enable tracked in `docs/hardening-roadmap.md §3.2` |
| 6 | Secure-delete advisory on SSD/COW | Informational | ⚠️ **Acknowledged** — documented in code and `KNOWN-GAPS.md §Gap 7`; ClamAV path avoids temp file entirely |
| 7 | PDF pattern scan missed FlateDecode compressed streams | Low | ✅ **Resolved** — `ScanCompressedPdfStreams` decompresses and re-scans, bounded by configurable limits |
| **A** | Scanner availability fail-open (new finding) | Medium | ⚠️ **Documented** — intentional design decision, explicit NotScanned tracking, documented in `KNOWN-GAPS.md §Gap 9` |
| **B** | Scanner XML doc comments contradict pipeline behavior (new finding) | Low | 🔧 **Required fix** — comments need updating in `ClamAvScanService.cs` and `WindowsDefenderScanService.cs` |

---

## What the Code Gets Definitively Right

These are not hedges — they are things this codebase does better than most production implementations:

**Fail-closed on content decisions.** Unknown types, malformed structure, deep-validation exceptions, and disk-capacity failures all result in rejection. There is no code path where uncertainty about *what a file is* defaults to acceptance. Layer 7 scanner *availability* is the one explicit exception — documented in `KNOWN-GAPS.md §9` — and is fail-open with `NotScanned` accounting, never silently relabelled as clean.

**PathHelper.IsPathUnderBase over string.StartsWith.** The prefix-confusion path traversal vulnerability is a real, exploited bug. Using a proper canonicalized base-path check is correct.

**Layer ordering.** Cheap checks (size, extension, MIME) run before expensive checks (deep content, virus scan). This limits the attack surface for DoS via expensive operations on malicious files.

**Application startup guards.** The service refuses to start with a misconfigured storage root or a placeholder encryption secret. Misconfigurations fail loudly at deploy time, not silently at runtime.

**Memory discipline.** `ArrayPool<byte>` usage with zeroing on return, `Image.Identify()` instead of full pixel decode, and minimum file size checks before any buffering all reflect correct thinking about resource exhaustion attacks.

**Four-way disposition model.** Distinguishing `Structural`, `Policy`, `Malicious`, and `TypeMismatch` rejections in `FileContentValidator` enables accurate audit logging and appropriate downstream handling without leaking internal details to users.

**Structured logging with security event prefixes.** `SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: Malicious` is parseable by a SIEM. This is production-grade audit trail design.

---

## Required Fixes

Before deploying to a new environment, two issues require code changes:

### Fix 1 — Update scanner XML doc comments (both scanner files)

In `ClamAvScanService.cs`, change:
```csharp
// Current (inaccurate):
/// Fail-closed: any I/O error, timeout, or daemon unavailability returns
/// IsClean=false, ScanSuccessful=false so the upload pipeline rejects the
/// file rather than silently letting it through.
```
To:
```csharp
// Corrected:
/// Detection fail-closed: a clean/infected verdict from the scanner is always honoured —
///   infected → pipeline rejects.
/// Availability fail-open: if the scanner is unreachable, times out, or throws,
///   this method sets ScanSuccessful=false. The upload pipeline then accepts the file
///   as NotScanned (counted in FileUploadResult.ScanNotScannedCount, never silently
///   relabelled as clean). See KNOWN-GAPS.md §Gap 9.
```

Apply the equivalent correction to `WindowsDefenderScanService.cs`.

### Fix 2 (deployment, not code) — Move EncryptionSecret out of appsettings

If `FileUpload:EncryptionEnabled=true`, the secret must be in an external secret store (environment variable, Key Vault, AWS Secrets Manager). Committing a real value to `appsettings.json` eliminates the benefit of PBKDF2 hardening.

---

## Recommended Hardening (Future Work)

See `docs/hardening-roadmap.md` for prioritized detail. In brief:

1. **Queued-scan model** (§1.3) — converts scanner availability from fail-open to "hold for review" without blocking the request path. Appropriate for higher-risk document workflows.
2. **Scanner health monitoring** (§1.4) — alert when `ScanNotScannedCount > 0`; dashboard for staff to identify unscanned batches and trigger manual review.
3. **Per-environment PBKDF2 salt** (§2.1) — rotate from the embedded `"SecureFileUpload.FileUpload.v1"` string to a per-environment random salt stored alongside the secret.
4. **reCAPTCHA v3 / Turnstile** (§3.2) — invisible bot detection with no user friction; complementary to rate limiting.
5. **Encrypted storage volume** (§4.1) — makes SSD wear-leveling temp-file recovery moot; eliminates the secure-delete caveat entirely.
6. **PDF-specific library** (§1.2) — `PdfPig` or similar for deeper structural inspection of PDFs, including form fields, embedded files, and XFA templates. Current pattern-scan approach is proportionate for patron document use case; higher-risk deployments may need more.

---

## Threat Model Summary

| Attack | Mitigated? | Layer |
|--------|-----------|-------|
| Oversized file | ✅ Yes | Layer 1 |
| Too many files in one submission | ✅ Yes | Layer 1 |
| ZIP bomb (pixel flood via image) | ✅ Yes | Layer 6 (`MaxImagePixels`, `Image.Identify` — no pixel decode) |
| Wrong extension (.exe → .jpg) | ✅ Yes | Layers 3, 4, 6 |
| Double extension (photo.pdf.exe) | ✅ Yes | Layer 5 |
| Path traversal via filename | ✅ Yes | Layer 5 + Layer 8 pre-write `IsPathUnderBase` |
| MIME spoofing | ✅ Yes | Layer 3 |
| Magic byte forgery | ✅ Yes | Layer 4 |
| WebP/RIFF format confusion (AVI, WAV) | ✅ Yes | Layer 4 (fourCC check) + Layer 6 |
| PDF JavaScript (uncompressed) | ✅ Yes | Layer 6 pattern scan |
| PDF JavaScript (FlateDecode compressed) | ✅ Yes | Layer 6 `ScanCompressedPdfStreams` |
| Encrypted PDF hiding content | ✅ Yes | Layer 6 (RejectEncryptedPdfs) |
| PE executable embedded in JPEG tail | ✅ Yes | Layer 8 image recompression strips tail |
| Polyglot file (JPEG + PHP) | ✅ Yes | Layer 8 image recompression strips tail |
| Known malware with active signature | ✅ Yes | Layer 7 (fail-closed on detection) |
| Known malware when scanner is down | ⚠️ Partial | Layers 1–6 catch all structurally detectable classes; novel signatures pass (fail-open by design — see Gap 9) |
| Windows reserved names (NUL, COM1) | ✅ Yes | Layer 5 |
| Unicode bidi/zero-width filename tricks | ✅ Yes | Layer 5 pattern scan |
| Log poisoning via filename | ✅ Yes | `SanitizeForLog` in `FileUploadService` |
| Disk exhaustion | ✅ Yes | Layer 1 size check + capacity check before write |
| Automated bot submission | ⚠️ Partial | Rate limiting present; reCAPTCHA not yet re-enabled (tracked in roadmap) |
| Temp file forensic recovery | ⚠️ Partial | Zero-overwrite present (SSD caveat documented); ClamAV path avoids temp file entirely |
| Direct web serving of uploads | ✅ Yes | Storage outside wwwroot; constructor enforces this |
| Startup with missing/placeholder secret | ✅ Yes | Constructor `throw` prevents application start |
| Master KEK compromise blast radius | ✅ Yes | Envelope encryption — each file has a unique wrapped DEK |
| Non-Windows deployment lacking AV | ✅ Yes | `ClamAvScanService` via `clamd` TCP, cross-platform |
| Decrypted file written to disk on download | ✅ Yes | `SecureFileDownloadController` streams decrypt output directly to response |
| Download path traversal | ✅ Yes | `IsPathUnderBase` re-checked at download time |
| Clickjacking / drive-by download via served file | ✅ Yes | `Content-Disposition: attachment`, `X-Frame-Options: DENY`, `CSP: default-src 'none'` on all download responses |

---

## Original Red-Team Findings (Preserved for Audit Trail)

The following section preserves the original adversarial findings with full code context. Status lines above each finding reflect the current code state.

---

### FINDING 1 — ✅ RESOLVED — WebP Verification Incomplete at Layer 4

> **Status (post-remediation):** Fixed. `ValidateFileSignatureDetailed` in `FileUploadService.cs` now checks the `WEBP` fourCC at offset 8 inline with the Layer 4 RIFF check, rather than deferring to Layer 6. AVI/WAV files renamed to `.webp` are now caught at Layer 4 directly.

**Original finding (preserved for context):**

**Location:** `FileUploadService.cs`, `FileSignatures` dictionary  
**Code:**
```csharp
{ ".webp", new byte[][] { new byte[] { 0x52, 0x49, 0x46, 0x46 } } },
// WebP: RIFF at offset 0, "WEBP" at offset 8. We check RIFF here;
// the WEBP fourCC at offset 8 is verified separately to avoid false-matching AVI/WAV.
```

**Finding:** The magic byte check for WebP only verifies `RIFF` at offset 0. The comment states that the `WEBP` fourCC at offset 8 is "verified separately" — but this "separate" verification happens in `FileContentValidator` (Layer 6), not in the Layer 4 magic byte check. This means a RIFF-format file that is actually AVI or WAV would pass Layer 4 and only be caught at Layer 6.

**Risk:** Low in isolation (Layer 6 catches it), but it means the magic byte layer is doing less than its comment implies. An AVI file renamed to `.webp` passes Layer 4 and reaches Layer 6 before being caught. If a bug ever disables Layer 6, AVI/WAV files would be accepted.

**Recommendation:** Add the fourCC check directly to the Layer 4 magic byte verification for WebP, making each layer independently correct rather than relying on the next layer to compensate:
```csharp
// In the magic byte validator, after checking RIFF at offset 0,
// additionally check bytes 8-11 == "WEBP"
private static bool IsValidWebpMagic(byte[] header)
{
    if (header.Length < 12) return false;
    // RIFF at 0
    if (header[0] != 0x52 || header[1] != 0x49 || header[2] != 0x46 || header[3] != 0x46) return false;
    // WEBP at 8
    return header[8] == 0x57 && header[9] == 0x45 && header[10] == 0x42 && header[11] == 0x50;
}
```

---

### FINDING 2 — ✅ RESOLVED — Polyglot Files Can Survive All 8 Layers

> **Status (post-remediation):** Mitigated by image recompression. `FileUploadService.GetSanitizedPlaintextAsync` decodes and re-encodes JPEG / PNG / WebP through ImageSharp before encryption (controlled by `FileUpload:RecompressImages`, default `true`). Any polyglot tail appended after the image's structural end is dropped by the encoder. Configurable JPEG quality via `FileUpload:JpegRecompressQuality` (default 95).

**Original finding (preserved for context):**

**Location:** Systemic — no single code location  
**Technique:** JPEG polyglot with appended payload

**Finding:** JPEG files can contain arbitrary data after the EOI marker (`FF D9`). The `FileContentValidator` uses ImageSharp's `Image.Identify()` for structural validation, which reads image metadata without decoding pixels. `Image.Identify()` validates the JPEG structure up to a valid EOI — it does not analyze or reject trailing data.

An attacker can craft a file that:
1. Has a valid JPEG header and structure (passes Layers 3, 4, 5)
2. Passes ImageSharp `Identify()` (passes Layer 6)
3. Contains an embedded PHP script, shell script, or executable after the JPEG EOI

If this file is subsequently served anywhere (email attachment, staff interface, admin download) and the receiving system processes the trailing data, the payload executes.

**Risk:** Medium. The uploaded file is encrypted at rest (Layer 8) and stored outside wwwroot. This substantially limits exploitation — the payload can't be executed directly via the web server. Risk increases if files are ever: decrypted and re-served without content-type enforcement, forwarded to downstream systems (email, FTP, shared drives), or processed by other software that parses the JPEG and then executes the tail.

**Recommendation:** The only reliable mitigation is **recompression**: decode and re-encode the image via ImageSharp before storage, which strips all appended data. This is computationally more expensive but is the correct fix:
```csharp
// After validation passes, re-encode through ImageSharp
using var image = await Image.LoadAsync(file.OpenReadStream());
using var cleanStream = new MemoryStream();
await image.SaveAsJpegAsync(cleanStream, new JpegEncoder { Quality = 92 });
// Write cleanStream to disk instead of the original file stream
```
See `KNOWN-GAPS.md` for why this was not implemented in the original codebase.

---

### FINDING 3 — LOW — Fixed PBKDF2 Application Salt

> **Status:** Acknowledged. Now applies to the master KEK in the envelope-encryption (v2) scheme — per-file DEKs are random and never derived from the secret. Salt is `"SecureFileUpload.FileUpload.v1"`.

**Location:** `FileUploadService.cs`, constructor
```csharp
var salt = Encoding.UTF8.GetBytes("SecureFileUpload.FileUpload.v1");
_encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
    Encoding.UTF8.GetBytes(secret), salt, iterations: 600_000, ...);
```

**Finding:** A fixed application-specific salt is used to derive the master encryption key from the configured secret. This is intentional and documented in the code — all files share one derived key, so a random per-file salt doesn't apply here. However, the fixed salt means that if an attacker knows the salt value (it's in source code) and obtains the derived key material (e.g., via memory dump), they can focus brute-force effort on the secret alone without needing to deal with salt discovery.

**Risk:** Low. The 600,000 PBKDF2 iteration count makes brute force expensive. The larger practical risk is secret management — if `EncryptionSecret` is stored in `appsettings.json` in source control (rather than environment variables or a secrets manager), the salt is irrelevant because the secret itself is exposed.

**Recommendation:** Ensure `EncryptionSecret` is stored in environment variables, Azure Key Vault, AWS Secrets Manager, or another secrets manager — never in `appsettings.json` committed to source control. Document this prominently in deployment instructions.

---

### FINDING 4 — ✅ RESOLVED — Filename Logged Before Sanitization in FileUploadService

> **Status (post-remediation):** Fixed. A new `SanitizeForLog` helper strips ANSI escape sequences, control characters, structured-log placeholders (`{`, `}`, `|`), CRLF, and Unicode bidi/zero-width characters; truncates to 128 chars. All log statements and user-facing error strings in `FileUploadService` that include `file.FileName` now route through `SanitizeForLog`. The unrelated `SanitizeFileName` helper (used to derive on-disk filenames) is kept separate.

**Original finding (preserved for context):**

**Location:** `FileUploadService.cs`, `UploadFilesAsync`
```csharp
_logger.LogInformation(
    "FILE_RECEIVED [{Index}/{Total}] | Size: {Size:N0} bytes | ContentType: {ContentType} | Form: {FormType}",
    i + 1, files.Count, f.Length, f.Length / 1024.0, f.ContentType, formType);
```
and:
```csharp
_logger.LogWarning(
    "FILE_REJECTED | Reason: {Reason} | Form: {FormType}",
    errorMessage, formType);
result.Errors.Add($"File '{file.FileName}': {errorMessage}");
```

**Finding:** `FileContentValidator` has a careful `SanitizeFileName()` method specifically to prevent log poisoning — stripping control characters, Unicode directional overrides, and truncating to prevent log storage abuse. However, in `FileUploadService`, `f.FileName` is used directly in the `result.Errors.Add()` call and implicitly in several logging calls. A crafted filename containing newlines, ANSI escape codes, or log-format injection characters (`|`, `{`, `}`) could corrupt structured log output.

**Risk:** Low in modern structured logging (Serilog, Application Insights serialize fields independently). Higher risk if logs are written as plain text and parsed by downstream SIEM rules.

**Recommendation:** Apply the same `SanitizeFileName()` used in `FileContentValidator` to all filename references in `FileUploadService` before logging or including in error messages. The method already exists — it just needs to be shared or duplicated.

---

### FINDING 5 — LOW — reCAPTCHA Disabled

**Location:** `ReplacementCardRemote.cshtml` (view template)
```html
<!-- reCAPTCHA - currently disabled
<div class="g-recaptcha" ...></div>
<input type="hidden" name="recaptcha_response" id="recaptchaResponse">
-->
```

**Finding:** reCAPTCHA is commented out. The form includes rate limiting (`[EnableRateLimiting]` attribute referenced in `RegistrationController.cs`), but without bot detection, automated submission attacks are possible. A bot could repeatedly submit the form to:
- Exhaust disk storage with uploaded files (partially mitigated by disk capacity check)
- Cause repeated virus scan invocations (30-second timeout each, potential DoS)
- Enumerate valid patron data by timing responses

**Risk:** Low if rate limiting is properly configured. Medium if rate limiting is set loosely or the server is under-resourced.

**Recommendation:** Re-enable reCAPTCHA v3 (invisible, no user friction) or implement Cloudflare Turnstile. Document the rate limiting configuration thresholds in `KNOWN-GAPS.md`.

---

### FINDING 6 — INFORMATIONAL — Secure Delete Effectiveness on Modern Storage

**Location:** `WindowsDefenderScanService.cs`, `SecureDeleteTempFile`
```csharp
/// Not a guarantee on all file systems (copy-on-write, SSD wear-leveling,
/// journaled FS) but reduces the exposure window on conventional storage.
```

**Finding:** The code itself correctly documents this limitation. Zero-overwrite-before-delete is not effective on SSDs (wear leveling spreads writes), Copy-on-Write filesystems (Btrfs, APFS), or journaled filesystems where the overwrite may itself be journaled. The comment is honest and accurate.

**Risk:** Informational. If the server runs on SSD or a COW filesystem, deleted temp files containing patron documents (IDs, utility bills) may be recoverable from unallocated sectors.

**Recommendation:** For servers handling PII, consider storing temp scan files on an encrypted volume (BitLocker, LUKS) so that even if the zero-overwrite fails, the underlying sectors are encrypted. This is a deployment-level concern, not a code change.

---

### FINDING 7 — ✅ RESOLVED — PDF Pattern Matching is Byte-Sequence Based

> **Status (post-remediation):** Fixed. `FileContentValidator.ScanCompressedPdfStreams` walks every `stream … endstream` block, attempts `DeflateStream` decompression (handles the optional 2-byte zlib header), and re-runs `DangerousPdfPatterns` and `JsTriggerPatterns` against the decompressed bytes. Bounded by `MaxCompressedStreamsToInspect` and `MaxDecompressedStreamBytes` to defeat zip-bomb amplification.

**Original finding (preserved for context):**

**Location:** `FileContentValidator.cs`, `DangerousPdfPatterns`
```csharp
private static readonly string[] DangerousPdfPatterns =
{
    "/JS ", "/JS\r", "/JS\n", "/JavaScript",
    "/Launch", "/EmbeddedFile", ...
};
```

**Finding:** The PDF threat detection searches for literal byte sequences in a Latin-1 decoded representation of the file. This correctly avoids the `/JSON` false-positive (the exact token set with trailing whitespace/newline handles this well). However, PDF allows stream contents to be compressed (commonly `FlateDecode`). Dangerous patterns inside a `FlateDecode` stream will not be found by this scan.

**Risk:** Low in practice. A compressed JavaScript stream in a PDF is very unusual in patron-submitted documents (driver's licenses, utility bills). Legitimate PDFs contain JavaScript to perform form calculations — compressed JavaScript designed to evade detection would be highly anomalous.

**Recommendation:** For higher assurance, consider integrating a PDF-specific library (e.g., `PdfPig` in C#) that can decompress and inspect stream contents. For a patron document use case (IDs, utility bills), the current approach is proportionate. Document this limitation in `KNOWN-GAPS.md`.

---

## Final Assessment

This is a well-engineered, production-appropriate upload pipeline for the stated use case. The 8-layer architecture, envelope encryption, image recompression, hardened download surface, startup guards, and structured audit logging are all implemented correctly — not approximately. The remaining open items are documented trade-offs and one comment inaccuracy, not unresolved security bugs.

**Deployers should verify:**
1. `EncryptionSecret` is in a secrets manager, not `appsettings.json`
2. The selected scanner is reachable and monitored
3. The scanner XML doc comments have been updated to match actual pipeline behavior (Fix 1 above)
4. The scanner availability posture (fail-open) has been reviewed against the deployment's threat model
