# tests/attack-vectors.md

## Attack Vector Test Cases

A manual and automated testing guide for verifying the upload pipeline. Each test case describes what to submit and what the expected outcome is. These can be used to build a formal test suite or for manual penetration testing.

All tests assume the pipeline is configured with default settings unless otherwise noted.

---

## Layer 1: File Size Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 1.1 | A valid JPEG larger than `MaxFileSizeBytes` (default 10 MB) | Rejected: "File exceeds maximum allowed size" |
| 1.2 | 6 valid files when `MaxFileCount` is 5 | Rejected: "Maximum 5 files allowed" |
| 1.3 | 5 valid files totaling more than `MaxTotalUploadBytes` | Rejected: "Combined upload size is too large" |
| 1.4 | A file with 0 bytes | Rejected: minimum file size check |
| 1.5 | A JPEG containing only 3 bytes (valid SOI but nothing else) | Rejected: minimum file size (4 bytes required) |
| 1.6 | A PNG containing only 15 bytes | Rejected: minimum file size (16 bytes required) |

---

## Layer 2: Extension Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 2.1 | `malware.exe` | Rejected: extension not in allowlist |
| 2.2 | `script.php` | Rejected: extension not in allowlist |
| 2.3 | `archive.zip` | Rejected: extension not in allowlist |
| 2.4 | `document.docx` | Rejected: extension not in allowlist |
| 2.5 | `image.svg` | Rejected: extension not in allowlist (SVG can contain scripts) |
| 2.6 | `file.GIF` | Rejected: extension not in allowlist (also note: case-insensitive check) |
| 2.7 | A file with no extension | Rejected: no extension to check against allowlist |
| 2.8 | A valid JPEG named `photo.jpg` | Passes Layer 2 |

---

## Layer 3: MIME Type Cross-Validation Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 3.1 | `photo.jpg` with `Content-Type: application/octet-stream` | Rejected: MIME not in allowed set |
| 3.2 | `document.pdf` with `Content-Type: image/jpeg` | Rejected: MIME does not match extension |
| 3.3 | `photo.png` with `Content-Type: image/jpeg` | Rejected: MIME does not match .png extension |
| 3.4 | `photo.jpg` with `Content-Type: image/jpeg` | Passes Layer 3 |
| 3.5 | `photo.jpeg` with `Content-Type: image/jpg` | Passes Layer 3 (image/jpg is in the .jpeg MIME set) |

---

## Layer 4: Magic Bytes Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 4.1 | A Windows PE executable renamed to `photo.jpg` | Rejected: magic bytes are `4D 5A` (MZ), not `FF D8 FF` |
| 4.2 | A ZIP archive renamed to `document.pdf` | Rejected: magic bytes are `50 4B 03 04`, not `25 50 44 46` (%PDF) |
| 4.3 | An ELF binary renamed to `photo.png` | Rejected: magic bytes are `7F 45 4C 46`, not `89 50 4E 47` |
| 4.4 | A PHP script renamed to `photo.jpg` | Rejected: magic bytes are `3C 3F 70 68 70` (`<?php`), not `FF D8 FF` |
| 4.5 | A GZIP archive renamed to `photo.jpg` | Rejected: magic bytes are `1F 8B 08` |
| 4.6 | A valid JPEG with correct magic bytes | Passes Layer 4 |
| 4.7 | A RIFF-format AVI file renamed to `image.webp` | Passes Layer 4 (RIFF check passes), caught at Layer 6 (WEBP fourCC check fails) |

---

## Layer 5: Filename Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 5.1 | `photo.pdf.exe` | Rejected: `.exe` found in filename stem |
| 5.2 | `document.php.jpg` | Rejected: `.php` found in filename stem |
| 5.3 | `script.js.jpeg` | Rejected: `.js` found in filename stem |
| 5.4 | `../../../etc/passwd.jpg` | Rejected: path traversal characters `..` and `/` |
| 5.5 | `..\windows\system32\evil.jpg` | Rejected: path traversal characters |
| 5.6 | `NUL.jpg` | Rejected: Windows reserved device name |
| 5.7 | `COM1.pdf` | Rejected: Windows reserved device name |
| 5.8 | `file\0hidden.jpg` (null byte injection) | Rejected: null byte in filename |
| 5.9 | `photo‮gpj.exe` (RLO Unicode trick displayed as `photo.jpg`) | Rejected: Unicode directional override character |
| 5.10 | `photo.jpg` (clean filename) | Passes Layer 5 |

---

## Layer 6: Deep Content Validation Tests

### PDF Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 6.1 | A PDF containing `/JavaScript` | Rejected: dangerous pattern |
| 6.2 | A PDF containing `/Launch` | Rejected: dangerous pattern |
| 6.3 | A PDF containing `/EmbeddedFile` | Rejected: dangerous pattern |
| 6.4 | A PDF containing `/XFA` | Rejected: dangerous pattern |
| 6.5 | A PDF containing `/JS ` (with trailing space) | Rejected: dangerous pattern |
| 6.6 | A PDF containing `/JSON` | Passes: `/JSON` does not match the exact JS trigger tokens |
| 6.7 | A password-protected/encrypted PDF | Rejected: `RejectEncryptedPdfs: true` (default) |
| 6.8 | A valid, clean PDF (utility bill scan) | Passes Layer 6 |
| 6.9 | A PDF containing JavaScript in a FlateDecode compressed stream | Passes Layer 6 — see KNOWN-GAPS.md |

### JPEG Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 6.10 | A JPEG with malformed segment lengths | Rejected: JPEG segment walker |
| 6.11 | A valid JPEG with `#!/bin/sh` appended after EOI | Passes Layer 6 — see KNOWN-GAPS.md (polyglot gap) |
| 6.12 | A valid JPEG with a PE executable embedded at the start | Rejected: embedded executable signature scan |
| 6.13 | A valid JPEG with `<script>` tag in EXIF comment field | Rejected: embedded script pattern scan |
| 6.14 | A file with JPEG magic bytes but containing a PE executable body | Rejected: JPEG segment walker fails immediately after the SOI marker |
| 6.15 | A valid JPEG declaring pixel dimensions exceeding `MaxImagePixels` | Rejected: pixel count exceeds limit |

### PNG Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| 6.16 | A PNG with invalid chunk lengths | Rejected: PNG chunk walker |
| 6.17 | A PNG with missing IHDR chunk | Rejected: PNG chunk walker |
| 6.18 | A PNG claiming 100,000 × 100,000 dimensions in IHDR | Rejected: pixel count exceeds MaxImagePixels |
| 6.19 | A valid PNG scan of a utility bill | Passes Layer 6 |

---

## Layer 7: Virus Scan Tests

| # | What to submit | Configuration | Expected outcome |
|---|----------------|--------------|-----------------|
| 7.1 | EICAR test file (standard AV test) as `eicar.jpg` (with valid JPEG header added) | `VirusScan:Enabled: true` | Rejected: virus scan detects EICAR signature |
| 7.2 | A clean JPEG | `VirusScan:Enabled: true` | Passes: no threat detected |
| 7.3 | Any file | `VirusScan:Enabled: false` | Scan skipped; file proceeds to Layer 8 if all other layers pass |
| 7.4 | Any file | Scanner binary missing | Rejected: fail-closed — scanner unavailable |

---

## Layer 8: Storage Tests

| # | What to test | Expected outcome |
|---|-------------|-----------------|
| 8.1 | Attempt to access uploaded files via web URL | 404 or access denied — uploads are outside wwwroot |
| 8.2 | Inspect stored file bytes when encryption is enabled | AES-256-GCM ciphertext with GCM marker prefix |
| 8.3 | Inspect stored filenames | Randomized: `{lastName}{date}{formType}Doc{n}{random}.ext` — no original filename |
| 8.4 | Configure `StorageRoot` to a path inside wwwroot | Application refuses to start |
| 8.5 | Set `EncryptionEnabled: true` with placeholder secret | Application refuses to start |

---

## Full-Stack Integration Tests

| # | What to submit | Expected outcome |
|---|----------------|-----------------|
| I.1 | A completely valid JPEG (clean, correct extension, correct MIME, clean filename, under size limit) | `WorkflowOutcome: AllSaved` |
| I.2 | 3 valid files + 1 JPEG with embedded script | `WorkflowOutcome: PartialSaved`, `RejectedCount: 1` |
| I.3 | 5 valid files + 1 oversized file | `WorkflowOutcome: AllRejected` (batch-level rejection before per-file processing) |
| I.4 | A valid JPEG + a renamed PE executable | `WorkflowOutcome: PartialSaved` |

---

## Building a Formal Test Suite

To automate these tests:

1. Use `IFormFile` mocks (e.g., via `FormFile` from `Microsoft.AspNetCore.Http`) to construct test files with controlled content.
2. Register `FileUploadService` and `FileContentValidator` in a test DI container with a temp storage root.
3. Set `VirusScan:Enabled: false` for all tests that don't specifically test Layer 7.
4. Assert `FileUploadResult.WorkflowOutcome`, `SavedCount`, `RejectedCount`, and specific error messages.

The four-way disposition in `ContentValidationResult` (`Structural`, `Policy`, `Malicious`, `TypeMismatch`) can be used to assert *why* a file was rejected, not just *that* it was rejected.
