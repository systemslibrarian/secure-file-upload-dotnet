# SECURITY-ANALYSIS.md

## Adversarial AI Red-Team Review

**Reviewed by:** Claude (Anthropic), acting as adversarial security reviewer  
**Review scope:** `FileUploadService.cs`, `FileContentValidator.cs`, `WindowsDefenderScanService.cs`, `ReplacementCardInputModel.cs`  
**Date:** 2026  
**Verdict:** Well-constructed defense-in-depth pipeline with specific, actionable gaps

This document was produced by running a structured adversarial review of the codebase — the AI was asked to find real weaknesses, not to validate the design. Findings are categorized by severity and include specific code references.

---

## Executive Summary

The pipeline is substantially stronger than the average ASP.NET file upload implementation. The 8-layer architecture, fail-closed posture, and format-specific structural walking are all correct approaches. However, several meaningful gaps exist that a motivated attacker could exploit depending on server configuration.

The most significant finding is the **polyglot file gap**: a carefully crafted file can simultaneously satisfy the JPEG magic byte check, pass ImageSharp structural identification, and contain embedded payload in regions the validator does not inspect. This is a hard problem — no purely server-side content validation fully eliminates polyglot risk without a recompression step.

---

## Findings by Severity

---

### FINDING 1 — MEDIUM — WebP Verification Incomplete at Layer 4

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

### FINDING 2 — MEDIUM — Polyglot Files Can Survive All 8 Layers

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

**Location:** `FileUploadService.cs`, constructor
```csharp
var salt = Encoding.UTF8.GetBytes("LcplOnlineRegistration.FileUpload.v1");
_encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
    Encoding.UTF8.GetBytes(secret), salt, iterations: 600_000, ...);
```

**Finding:** A fixed application-specific salt is used to derive the master encryption key from the configured secret. This is intentional and documented in the code — all files share one derived key, so a random per-file salt doesn't apply here. However, the fixed salt means that if an attacker knows the salt value (it's in source code) and obtains the derived key material (e.g., via memory dump), they can focus brute-force effort on the secret alone without needing to deal with salt discovery.

**Risk:** Low. The 600,000 PBKDF2 iteration count makes brute force expensive. The larger practical risk is secret management — if `EncryptionSecret` is stored in `appsettings.json` in source control (rather than environment variables or a secrets manager), the salt is irrelevant because the secret itself is exposed.

**Recommendation:** Ensure `EncryptionSecret` is stored in environment variables, Azure Key Vault, AWS Secrets Manager, or another secrets manager — never in `appsettings.json` committed to source control. Document this prominently in deployment instructions.

---

### FINDING 4 — LOW — Filename Logged Before Sanitization in FileUploadService

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

### FINDING 7 — INFORMATIONAL — PDF Pattern Matching is Byte-Sequence Based

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

## What the Code Gets Definitively Right

These are not hedges — they are things this codebase does better than most production implementations:

**Fail-closed at every decision point.** Unknown types, unavailable scanners, exceptions, and disk capacity failures all result in rejection. There is no code path where uncertainty defaults to acceptance.

**PathHelper.IsPathUnderBase over string.StartsWith.** The prefix-confusion path traversal vulnerability is a real, exploited bug. Using a proper canonicalized base-path check is correct.

**Layer ordering.** Cheap checks (size, extension, MIME) run before expensive checks (deep content, virus scan). This limits the attack surface for DoS via expensive operations on malicious files.

**Application startup guards.** The service refuses to start with a misconfigured storage root or a placeholder encryption secret. Misconfigurations fail loudly at deploy time, not silently at runtime.

**Memory discipline.** `ArrayPool<byte>` usage with zeroing on return, `Image.Identify()` instead of full pixel decode, and minimum file size checks before any buffering all reflect correct thinking about resource exhaustion attacks.

**Four-way disposition model.** Distinguishing `Structural`, `Policy`, `Malicious`, and `TypeMismatch` rejections in `FileContentValidator` enables accurate audit logging and appropriate downstream handling without leaking internal details to users.

**Structured logging with security event prefixes.** `SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: Malicious` is parseable by a SIEM. This is production-grade audit trail design.

---

## Threat Model Summary

| Attack | Mitigated? | Layer |
|--------|-----------|-------|
| Oversized file | ✅ Yes | Layer 1 |
| ZIP bomb (pixel flood via image) | ✅ Yes | Layer 6 (MaxImagePixels, Image.Identify only) |
| Wrong extension (.exe → .jpg) | ✅ Yes | Layers 3, 4, 6 |
| Double extension (photo.pdf.exe) | ✅ Yes | Layer 5 |
| Path traversal via filename | ✅ Yes | Layer 5 + Layer 8 pre-write check |
| MIME spoofing | ✅ Yes | Layer 3 |
| Magic byte forgery | ✅ Yes | Layer 4 |
| PDF JavaScript | ✅ Yes (uncompressed) | Layer 6 |
| PDF JavaScript (FlateDecode) | ⚠️ Partial | Layer 7 (AV may catch) |
| PE executable embedded in JPEG tail | ⚠️ Partial | Layer 7 (AV may catch) |
| Polyglot file (JPEG + PHP) | ⚠️ Partial | Layer 7 + encrypted storage |
| WebP/RIFF format confusion | ⚠️ Partial | Layer 6 catches, Layer 4 misses |
| Windows reserved names (NUL, COM1) | ✅ Yes | Layer 5 |
| Log poisoning via filename | ⚠️ Partial | Only in FileContentValidator |
| Disk exhaustion | ✅ Yes | Layer 1 + capacity check |
| Automated bot submission | ⚠️ Partial | Rate limiting (reCAPTCHA disabled) |
| Encrypted PDF content hiding | ✅ Yes (rejected) | Layer 6 (RejectEncryptedPdfs) |
| Temp file forensic recovery | ⚠️ Partial | Zero-overwrite (SSD caveat) |
| Direct web serving of uploads | ✅ Yes | Storage outside wwwroot |
| Startup with bad config | ✅ Yes | Constructor guards |
