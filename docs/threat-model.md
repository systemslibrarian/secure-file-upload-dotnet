# docs/threat-model.md

## Threat Model: What Each Layer Defeats

This document maps specific attack vectors to the pipeline layers that stop them. Understanding *why* each layer exists helps you evaluate whether to keep, modify, or remove it for your own deployment context.

---

## Layer 1 — File Size Check

**Attacks defeated:**
- **Zip bomb via oversized upload**: A 10 GB file masquerading as a JPEG cannot proceed past Layer 1. The check runs before any buffering, so the file bytes never enter memory.
- **Disk exhaustion via individual large files**: Per-file size limit (default 10 MB) caps individual file storage.
- **Disk exhaustion via batch accumulation**: Total batch size limit (default 50 MB) caps the per-request disk impact regardless of how files are distributed.
- **Truncated header bypass**: Minimum file sizes per format (e.g., 16 bytes for PNG, 12 bytes for WebP) reject files that are too small to contain a valid header. This prevents an attacker from submitting a partial magic-byte sequence designed to pass the signature check while avoiding format-specific parsing.

---

## Layer 2 — Extension Allowlist

**Attacks defeated:**
- **Arbitrary file type upload**: Only `.jpg`, `.jpeg`, `.png`, `.webp`, `.pdf` are accepted. A `.php`, `.aspx`, `.exe`, `.sh` — or any other file type — is rejected immediately.
- **Unknown format exploration**: New file formats introduced after this code was written are rejected by default. Allowlists are safer than blocklists for file types.

**What this layer does NOT do:**
- Does not verify the file *is* actually the claimed type — that's Layer 4 and Layer 6.
- A file named `malware.jpg` with executable content passes this layer.

---

## Layer 3 — MIME Type + Extension Cross-Validation

**Attacks defeated:**
- **MIME spoofing**: A file claiming to be `image/jpeg` but named `.pdf` is rejected because the MIME type and extension don't match the cross-validation map.
- **Partial MIME manipulation**: A `.jpg` file uploaded with `Content-Type: application/octet-stream` is rejected because `application/octet-stream` is not in the allowed MIME set for `.jpg`.

**What this layer does NOT do:**
- Does not validate the actual file content — a `.jpg` file with `image/jpeg` MIME that contains a PE executable passes this layer (caught at Layers 4 and 6).
- The browser-reported Content-Type is not trusted as proof of file type. It is checked only for *consistency* with the claimed extension.

---

## Layer 4 — Magic Bytes (File Signature Check)

**Attacks defeated:**
- **Extension disguise**: A Windows PE executable renamed to `photo.jpg` has `MZ` magic bytes instead of `FF D8 FF`. It is rejected.
- **Known dangerous format identification**: The `KnownDangerousSignatures` dictionary identifies what a rejected file *actually is* (ZIP, ELF, OLE document, PHP, shebang script) for audit logging — even when the dangerous file would be rejected anyway on extension grounds.

**What this layer does NOT do:**
- Does not verify the complete file structure — a JPEG header attached to arbitrary data passes this layer (caught at Layer 6 — and the trailing data is then stripped by image recompression in Layer 8 when enabled).
- WebP verification at this layer checks `RIFF` at offset 0 **and** the `WEBP` fourCC at offset 8. RIFF-format AVI/WAV files renamed to `.webp` are caught here directly.

---

## Layer 5 — Filename Inspection

**Attacks defeated:**
- **Double-extension attack** (`photo.pdf.exe`, `doc.php.jpg`): The filename stem is scanned for any dangerous extension from the `DangerousExtensions` set. A file named `document.js.pdf` is rejected because `.js` appears in the stem.
- **Path traversal via filename** (`../../etc/passwd.jpg`, `..\..\windows\system32\bad.pdf`): Filenames containing `..`, `/`, or `\` are rejected.
- **Unicode right-to-left override attacks** (`photo‮gpj.exe` displayed as `photo.jpg`): Unicode bidirectional control characters in filenames are rejected.
- **Null byte injection** (`file.jpg\0.php`): Null bytes in filenames are rejected.
- **Windows reserved device names** (`NUL.jpg`, `COM1.pdf`, `AUX.png`): Reserved names that cause undefined behavior on Windows filesystems are rejected.

---

## Layer 6 — Deep Content Validation (FileContentValidator)

This is the most complex and most powerful layer. It does format-specific structural walking of the actual file bytes.

**JPEG attacks defeated:**
- **Truncated or malformed JPEG**: The segment walker validates marker types and lengths through the entire file. A JPEG with a malformed segment structure is rejected.
- **Embedded shell content** (`#!/bin/sh`, `<?php`): Scanned in the Latin1-decoded file content.
- **Embedded script content** (`<script>`, `<svg`): Scanned across the full file content.
- **Embedded executable signatures** (PE, ELF, Mach-O): Byte signature scan across the full file.
- **Embedded archive containers** (ZIP, GZIP, RAR, 7-Zip): Byte signature scan. ZIP is particularly important because `.docx`, `.jar`, and `.apk` are ZIP archives.

**PNG attacks defeated:**
- **Chunk structure manipulation**: The chunk tree is walked from the IHDR to IEND, validating chunk lengths and types. A PNG with invalid chunk structure is rejected.
- **Pixel flood (decompression bomb)**: `MaxImagePixels` (default 40 million) caps the declared pixel count. A PNG claiming a 100,000 × 100,000 image is rejected before any decompression occurs.
- **All embedded content checks**: Same as JPEG above.

**WebP attacks defeated:**
- **RIFF chunk tree manipulation**: The chunk tree is walked and validated. Invalid chunk lengths or missing required chunks are rejected.
- **RIFF format confusion (AVI/WAV disguised as WebP)**: The WEBP fourCC at offset 8 is verified during structural walking, catching files that passed the Layer 4 RIFF check.

**PDF attacks defeated:**
- **JavaScript execution** (`/JS`, `/JavaScript`): Hard-rejected. There is no legitimate use for JavaScript in patron-submitted ID documents.
- **Launch actions** (`/Launch`): Hard-rejected. Launch actions execute arbitrary programs.
- **Embedded files** (`/EmbeddedFile`): Hard-rejected. Patron documents should not contain embedded files.
- **Rich media / XFA / 3D** (`/RichMedia`, `/XFA`, `/3D`): Hard-rejected.
- **JBIG2Decode**: Hard-rejected. JBIG2Decode has been used in exploit chains.
- **Encrypted PDFs**: Rejected when `RejectEncryptedPdfs: true` (default). Encrypted PDFs cannot be inspected, so we reject them — with a friendly user-facing message instructing patrons to upload an unprotected copy.
- **Suspicious but conditional patterns** (`/URI`, `/OpenAction`, `/AcroForm`, `/SubmitForm`): Logged as suspicious; `/OpenAction` and `/AA` are hard-rejected when JavaScript is also present.
- **Threat tokens hidden in `FlateDecode`-compressed object streams**: `ScanCompressedPdfStreams` walks every `stream … endstream` block, decompresses with `DeflateStream`, and re-runs the dangerous-pattern scan against the decompressed bytes. Bounded by `MaxCompressedStreamsToInspect` and `MaxDecompressedStreamBytes` (zip-bomb safe).

**Type mismatch attacks defeated:**
- **Any file whose actual signature doesn't match its claimed extension**: The validator classifies the actual type from magic bytes first. If a file claims `.pdf` but has JPEG magic bytes, it's a type mismatch rejection (distinct disposition from a structural or malicious rejection).

**What this layer does NOT do:**
- Does not catch novel format confusions in unsupported types (validator is allowlist-based).
- Polyglot tails are not removed here — they are stripped by the image recompression step in Layer 8 instead.

---

## Layer 7 — Virus Scan (IVirusScanService)

**Implementations available:**
- `WindowsDefenderScanService` — invokes `MpCmdRun.exe`. Windows-only. Writes a temp file (zeroed before delete).
- `ClamAvScanService` — talks to `clamd` directly over TCP using the documented `zINSTREAM` protocol. Cross-platform. **No temp file is written** — patron bytes never touch disk on the scanner path.

**Attacks defeated:**
- **Known malware signatures**: Both Windows Defender and ClamAV maintain frequently-updated signature databases covering thousands of known malware families, including many polyglot and steganographic attack tools.
- **Known malicious PDF patterns**: AV engines inspect PDF content including decompressed streams — a defence-in-depth complement to Layer 6's own `ScanCompressedPdfStreams`.
- **Polymorphic variants of known malware**: Heuristic scanning catches some zero-day variants.

**What this layer does NOT do:**
- Does not catch unknown (zero-day) malware with no signature match.
- Is not effective if disabled (`VirusScan:Enabled: false`). When disabled, this layer returns `NotScanned` and the file is accepted — the other 7 layers still apply.
- The scan is fail-closed on **detection** but fail-open on **availability**: a clear malware signature blocks the upload, while a transient scanner failure (timeout, daemon down) marks the file as `NotScanned` rather than rejecting it. This is intentional — the file already passed all six prior validation layers.

---

## Layer 8 — Encrypted Storage

**Attacks defeated:**
- **Direct web serving of uploaded files**: Storage outside wwwroot means the web server cannot directly serve uploaded files. There is no URL that resolves to the upload directory.
- **Filename-based path traversal at write time**: The final storage path is validated against the storage root using `PathHelper.IsPathUnderBase` before any write occurs.
- **Storage content disclosure**: AES-256-GCM authenticated encryption means uploaded patron documents (IDs, utility bills) are not readable even if an attacker gains filesystem access.
- **Filename enumeration**: Randomized filenames (`{lastName}{date}{formType}Doc{n}{randomSuffix}.ext`) remove attacker control over stored filenames and prevent sequential enumeration.
- **Encrypted file tampering**: GCM authentication tags detect any modification to encrypted file contents. A tampered file will fail decryption and be rejected.
- **Polyglot tails after image EOI**: When `RecompressImages=true` (default), JPEG / PNG / WebP files are re-encoded through ImageSharp before encryption. The encoder emits only the bytes it produces, so any data appended after the image's structural end is dropped.
- **Single-key blast radius**: Files are stored using **envelope encryption (format v2)** — a per-file random Data Encryption Key (DEK) encrypts the payload, and the DEK itself is wrapped under the master Key Encryption Key (KEK). The master key can be rotated by re-wrapping each file's DEK without re-encrypting the file payload.

**What this layer does NOT do:**
- Encryption is optional (`EncryptionEnabled: false` by default). When disabled, files are stored in plaintext — all other layers still apply, but stored files are readable if an attacker accesses the filesystem.
- Does not protect against KEK compromise. If `EncryptionSecret` is obtained, all wrapped DEKs (and therefore all stored files) can be decrypted. See `KNOWN-GAPS.md` and `docs/hardening-roadmap.md` on KMS / HSM integration.
