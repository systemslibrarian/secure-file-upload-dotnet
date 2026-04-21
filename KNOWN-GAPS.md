# KNOWN-GAPS.md

## What This Code Does Not Protect Against

This document exists because intellectual honesty matters more than looking good. Every security codebase has gaps. The goal is to name them clearly so developers using this code know exactly what they're getting and what additional layers they need.

---

## Gap 1: Polyglot Files Are Not Fully Eliminated  ✅ FIXED (opt-in)

> **Status:** Mitigated. Image recompression is now implemented in `FileUploadService.GetSanitizedPlaintextAsync`. JPEG / PNG / WebP uploads are decoded and re-encoded with ImageSharp before encryption, which strips any data appended after the image's logical end (the polyglot vector).
>
> **Configuration:**
> - `FileUpload:RecompressImages` (default `true`) — set `false` to keep original bytes if quality is critical.
> - `FileUpload:JpegRecompressQuality` (default `95`, clamped 1–100) — JPEG output quality.
>
> The historical rationale below is retained for context.


**What it means:** A file can simultaneously be a valid JPEG (passes all validation) and contain an embedded executable, script, or payload in the tail bytes after the JPEG EOI marker. The validation pipeline detects the file as structurally valid JPEG. The virus scanner may or may not catch the payload depending on signature coverage.

**Why we didn't fix it:** The correct fix is recompression — decode the image via ImageSharp and re-encode it before storage. This strips all appended data definitively. We evaluated this and chose not to implement it for two reasons:

1. **Performance cost.** Full image decode + re-encode on every upload adds significant CPU and memory load. At our upload volume this was acceptable to defer.
2. **Lossy JPEG re-encoding.** Re-encoding a JPEG that a patron photographed with their phone introduces quality loss. For patron-submitted ID documents, this is undesirable — a patron's driver's license photo should not be degraded.

**What partially mitigates it:** Files are stored encrypted outside wwwroot and are never directly web-served. A virus scanner (Layer 7) may catch common payloads. The decrypted file is only accessed by authenticated staff.

**What you should do if this gap is unacceptable:** Implement recompression for JPEG/PNG/WebP at write time. Accept that JPEG quality will degrade slightly and that lossless formats (PNG, WebP lossless) will re-encode without quality loss.

---

## Gap 2: PDF FlateDecode Stream Contents Are Not Inspected  ✅ FIXED

> **Status:** Mitigated. `FileContentValidator.ScanCompressedPdfStreams` now walks every `stream … endstream` block, FlateDecodes it via `System.IO.Compression.DeflateStream`, and re-runs `DangerousPdfPatterns` / `JsTriggerPatterns` against the decompressed bytes. No PDF parsing dependency added.
>
> **Bounded by config (zip-bomb safe):**
> - `FileContent:InspectCompressedPdfStreams` (default `true`)
> - `FileContent:MaxCompressedStreamsToInspect` (default `64`)
> - `FileContent:MaxDecompressedStreamBytes` (default `16 MiB`)
>
> Malformed streams are silently skipped (fail-open per stream); pattern hits in any decompressed stream cause the whole file to be rejected (fail-closed per file).


**What it means:** The PDF pattern scanner searches for dangerous PDF object names (`/JS`, `/JavaScript`, `/Launch`, etc.) in the raw file bytes. PDF streams are often compressed using `FlateDecode` (zlib/deflate). Dangerous patterns inside compressed streams will not be found by string matching on the raw bytes.

**Why we didn't fix it:** Decompressing and inspecting all PDF streams requires a PDF parsing library. We evaluated `PdfPig` (C#) and decided the additional dependency and complexity was disproportionate for our threat model: patron-submitted documents are driver's licenses and utility bills, not attacker-crafted PDFs.

**What partially mitigates it:** The Layer 7 virus scanner uses signature-based detection that operates on the actual byte content. Windows Defender and ClamAV both inspect PDF stream contents during virus scanning, including decompressed streams.

**What you should do if this gap is unacceptable:** Integrate PdfPig or a similar library to decompress and inspect all PDF streams. The `DangerousPdfPatterns` array is the right starting point — apply those patterns against decompressed stream data, not just the raw file.

---

## Gap 3: reCAPTCHA / Bot Detection Is Disabled

**What it means:** The form has no bot detection. An automated attacker can submit the form repeatedly, triggering file validation, virus scanning (30 seconds per file), and disk writes for each submission.

**Current mitigation:** ASP.NET Core rate limiting is applied at the controller level via `[EnableRateLimiting]`. The rate limit configuration determines how effective this is.

**What you should do:** Enable reCAPTCHA v3 (invisible, no user friction) or Cloudflare Turnstile. Both are free for typical form volumes.

---

## Gap 4: Encrypted PDF Files Are Rejected Entirely  ✅ FIXED (UX)

> **Status:** Improved. The pipeline still rejects encrypted PDFs (correct fail-closed posture), but `FileUploadService` now surfaces a specific user-facing message when `ContentValidationResult.ValidationType == "PDF-EncryptedRejected"`:
>
> > *"Password-protected PDFs cannot be accepted because their contents cannot be inspected for safety. Please upload an unprotected copy of this document."*
>
> Patrons no longer see a generic rejection.


**What it means:** `RejectEncryptedPdfs: true` (the default) means patron-submitted PDFs that are encrypted/password-protected are rejected outright, even if they contain no malicious content.

**Why this is the right trade-off:** We cannot inspect the content of an encrypted PDF. Since we can't verify it's safe, we reject it. Fail-closed.

**User impact:** Patrons who scan a PDF and then apply password protection (which some PDF apps do automatically) will have their upload rejected with no clear explanation of why.

**What you should do if this matters:** Add clear error messaging when an encrypted PDF is detected. The `ValidationDisposition.RejectedPolicy` return value can be used to present a specific message like "Password-protected PDFs cannot be accepted. Please upload an unprotected copy."

---

## Gap 5: No Rate Limiting on Individual File Validation Cost

**What it means:** An attacker who bypasses the file count limit (or submits the maximum allowed files) can cause the server to run expensive validation — ImageSharp identification, PDF pattern scanning, virus scanning — on each file. A batch of 5 large PDFs, each requiring a 30-second Defender scan, ties up a scan slot for 2.5 minutes per request.

**Current mitigation:** Max file count (5), max per-file size (10 MB), max total batch size (50 MB), and OS-level rate limiting.

**What you should do:** Consider async/queued virus scanning for high-volume deployments — accept the file optimistically, queue the scan, and notify the staff reviewer of scan completion. This trades immediate rejection for higher throughput.

---

## Gap 6: Windows Defender Only — No Linux/Cross-Platform AV Support  ✅ FIXED

> **Status:** Mitigated. `src/ClamAvScanService.cs` provides a cross-platform `IVirusScanService` implementation that talks to `clamd` directly over TCP using the documented `zINSTREAM` protocol — no temp file is written and patron bytes never touch disk.
>
> **Configuration (`VirusScan:ClamAv:*`):**
> - `Host` (default `localhost`)
> - `Port` (default `3310`)
> - `TimeoutSeconds` (default `30`, max `120`)
> - `MaxStreamBytes` (default `25 MiB`; must align with `clamd.conf` `StreamMaxLength`)
>
> Fail-closed: any timeout, socket error, or unrecognised response yields `IsClean=false, ScanSuccessful=false`. Health check uses `nPING` (no state mutation).
>
> Register one or the other in DI based on platform — `WindowsDefenderScanService` for Windows, `ClamAvScanService` for Linux/containers/macOS.


**What it means:** `WindowsDefenderScanService` requires `MpCmdRun.exe` and therefore requires a Windows server. There is no provided ClamAV implementation for Linux deployments.

**What you should do:** The `IVirusScanService` interface is the right abstraction. Implementing ClamAV support via `clamd` socket or `clamscan` subprocess would make this pipeline fully cross-platform. Contributions welcome.

---

## Gap 7: Secure Delete Caveats on Modern Storage

**What it means:** `WindowsDefenderScanService.SecureDeleteTempFile` overwrites temp file contents with zeros before deletion. This is ineffective on:
- SSD drives (wear leveling may write the zeros to different physical cells than the original data)
- Copy-on-Write filesystems (Btrfs, APFS, ReFS in some modes)
- Journaled filesystems where the overwrite transaction itself is journaled

**Why it's included anyway:** It reduces the exposure window on conventional HDD storage and reflects correct intent. The code comment is explicit about the limitation.

**What you should do:** For servers handling PII on SSD, use full-volume encryption (BitLocker, LUKS) so that physically recovered sectors are unreadable without the volume key.

---

## Gap 8: Single Encryption Key for All Files  ✅ FIXED

> **Status:** Mitigated. `FileUploadService` now writes envelope-encrypted files (`FormatVersionV2 = 0x02`):
>
> 1. Generate a random 256-bit Data Encryption Key (DEK) per file.
> 2. Encrypt the file payload with the DEK using AES-256-GCM.
> 3. Wrap (encrypt) the DEK itself with the master Key Encryption Key (KEK) using a separate AES-256-GCM operation.
> 4. Store on disk as: `marker || dek_nonce || dek_tag || wrapped_dek || file_nonce || file_tag || ciphertext`.
>
> **Backward-compatible reads:** `GetDecryptedFileStreamAsync` dispatches on the version byte, so legacy `0x01` single-key files continue to decrypt via `DecryptV1SingleKey`. Unsupported versions are logged and refused.
>
> **Key rotation** is now possible by rewrapping each file's DEK under a new KEK — no need to re-encrypt the file payload itself. `TryUnwrapDek` already supports a master + legacy KEK fallback to make that migration online-safe.


**What it means:** All uploaded files share a single derived master key. Key rotation requires re-encrypting all stored files. There is no per-file key or key versioning system.

**Why this was acceptable:** For a staff-accessible patron document store accessed via an authenticated admin interface, a single application key is operationally simpler and proportionate. Per-file keys are appropriate for multi-tenant systems where different parties own different files.

**What you should do if this gap is unacceptable:** Implement envelope encryption: generate a random per-file data encryption key (DEK), encrypt the file with the DEK, then encrypt the DEK with the master key. Store the encrypted DEK alongside the file. This enables key rotation by re-encrypting only the DEKs.

---

## Gap 9: Layer 7 Is Fail-Open on Scanner *Availability* (by design)

**What it means:** The virus-scan layer (`IVirusScanService`) has two distinct failure modes, and the pipeline treats them differently:

| Scanner outcome | Pipeline behaviour | Counted as |
|---|---|---|
| Clean signature result | Accept | `ScanCleanCount` |
| Infected signature result | **Reject** | `InfectedRejectedCount` |
| Scanner unreachable / timeout / exception / unparseable response | **Accept** | `ScanNotScannedCount` |

In other words: **detection is fail-closed; availability is fail-open**. A clear malware signature always blocks the upload. A `clamd` outage or `MpCmdRun.exe` timeout does *not* block the upload \u2014 the file is accepted on the strength of Layers 1\u20136 and explicitly recorded as `NotScanned`. The outcome is logged as `VIRUS_SCAN_OPERATIONAL_FAILURE` and surfaced in `FileUploadResult` so staff dashboards can flag the batch for re-scanning.

**Why this is the chosen trade-off:** The original deployment is a public-library patron-registration workflow. A scanner outage during business hours must not block patrons from registering for a library card; the operational cost of false rejections in that context outweighs the residual risk, given that Layers 1\u20136 already exclude every class of file the scanner is designed to catch except *novel signatures of known-bad payloads inside formats we accept*.

**What you should do if this trade-off does not match your context:**

1. **Switch to a queued-scan model** (recommended for higher-risk workloads): accept the file into a `pending/` quarantine, run the scanner asynchronously, and only release to `cleared/` on a clean result. See [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md) \u00a71.3. This converts \"scanner down\" from \"accept\" into \"hold for review\" without blocking the request path.\n2. **Make availability fail-closed** by changing `RunVirusScanAsync` in `FileUploadService` to return `Infected` (or a new `ScannerUnavailable` outcome that the caller rejects) on the operational-failure paths. This is a one-method change but inverts the availability/UX trade-off and should be a conscious deployment decision, not a default.\n\n---\n\n## Not a Gap: Relying on Browser-Reported Content-Type (Layer 3)

One common objection: "You can't trust the browser Content-Type header." This is true — but the design accounts for it. Layer 3 does not *accept* a file based on MIME type alone. It *cross-validates* that the browser-reported MIME type is consistent with the claimed extension. A mismatch is a rejection signal. The actual file type is determined independently by magic bytes (Layer 4) and deep content (Layer 6). Layer 3 is a consistency check, not a trust gate.
