# secure-file-upload-dotnet

**Defense-in-depth file upload pipeline for ASP.NET Core 8+**

[![NuGet](https://img.shields.io/nuget/v/SecureFileUpload.Core.svg)](https://www.nuget.org/packages/SecureFileUpload.Core)
[![Build](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml/badge.svg)](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)

An 8-layer file upload validation and storage pipeline derived from a production ASP.NET Core 8 document-intake workflow. The code has been de-branded, generalized, and published for reuse — it is the same pipeline structure used in production, not a toy example.

The goal of this repo is to show what a *measured, fail-closed* upload pipeline looks like in real C#: every claim below is backed by code in [`src/`](src), and every known limitation is documented in [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

[`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md) records a structured adversarial AI red-team review of this exact code — original findings, current resolution status, and the residual gaps that remain.

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31

---

## Why This Exists

Secure file upload is one of the most consistently mishandled areas in web development. Most tutorials show you how to *receive* a file. Very few show you how to defend against:

- Polyglot files (valid image + embedded executable)
- Double-extension attacks (`photo.pdf.exe`)
- MIME spoofing
- Magic-byte forgery
- Path traversal via filename manipulation
- PDF JavaScript injection
- ZIP bomb / pixel flood attacks
- Log poisoning via crafted filenames
- Disk exhaustion attacks

This codebase addresses all of them, and the red-team analysis tells you where it still falls short.

---

## The 8-Layer Validation Pipeline

Every uploaded file passes through all layers in order. **Failure at any validation layer rejects the file immediately.** The pipeline is fail-closed on every *content* decision — unknown types, malformed files, and validation exceptions all result in rejection. The single deliberate exception is virus-scanner *availability* (Layer 7), which is fail-open by design and explicitly tracked; see [Key Design Decisions](#key-design-decisions-and-why) below.

```
┌─────────────────────────────────────────────────────────────────┐
│                     INCOMING FILE UPLOAD                         │
└─────────────────────────┬───────────────────────────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 1: File Size Check       │  Rejects oversized files before any buffering
          │  (per-file and total batch)     │  Also enforces minimum size per format
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 2: Extension Allowlist   │  Strict allowlist: .jpg .jpeg .png .webp .pdf
          │                                 │  Everything else is rejected
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 3: MIME + Extension      │  Browser-reported MIME must match extension
          │  Cross-Validation               │  Catches extension-spoofed uploads
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 4: Magic Bytes           │  File signature read from actual bytes
          │  (File Signature Check)         │  Not from filename or Content-Type header
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 5: Filename Inspection   │  Double-extension, Unicode tricks,
          │                                 │  path traversal, reserved names (NUL, COM1...)
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 6: Deep Content          │  Format-specific structural walking:
          │  Validation (FileContentValidator) │  JPEG segment walker, PNG chunk walker,
          │                                 │  WebP RIFF tree, PDF pattern scan,
          │                                 │  PDF FlateDecode stream inspection.
          │                                 │  Detects embedded executables, scripts,
          │                                 │  JavaScript in PDF, dangerous PDF objects
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 7: Virus Scan            │  Windows Defender (Windows) OR
          │  (IVirusScanService)            │  ClamAV via clamd zINSTREAM (Linux/cross-platform).
          │                                 │  Fail-closed on signature hit (infected → reject).
          │                                 │  Fail-open on scanner availability (timeout/down →
          │                                 │  accept as NotScanned; tracked in result, never
          │                                 │  silently "clean"). Only runs when VirusScan:Enabled=true.
          └───────────────┬────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  Layer 8: Encrypted Storage     │  AES-256-GCM envelope encryption (v2):
          │                                 │  per-file random DEK wrapped under master KEK.
          │                                 │  Image recompression strips polyglot tails.
          │                                 │  Randomized filename, outside wwwroot,
          │                                 │  path traversal re-checked before write
          └───────────────┴────────────────┘
```

---

## Source Files

| File | Purpose |
|------|---------|
| `src/FileUploadService.cs` | Orchestrates the full 8-layer pipeline. Handles batch limits, disk capacity checks, image recompression (Gap 1 mitigation), envelope-encrypted write (v2), decryption for retrieval, log-poisoning-safe filename handling. |
| `src/FileContentValidator.cs` | Layer 6 deep content validation. Format-specific structural walking for JPEG, PNG, WebP, PDF. Pattern-based threat detection. **FlateDecode-compressed PDF stream inspection** (Gap 2 mitigation). Fail-closed on unknown types. |
| `src/WindowsDefenderScanService.cs` | Layer 7 virus scanning via Windows Defender `MpCmdRun.exe`. Includes temp-file secure delete (zero-before-delete). Use on Windows. |
| `src/ClamAvScanService.cs` | Layer 7 virus scanning via `clamd` over TCP using the `zINSTREAM` protocol. No temp file written — patron bytes never touch disk. Use on Linux / containers / macOS. |
| `src/SecureFileDownloadController.cs` | Reference staff-side download handler. Forces `Content-Disposition: attachment`, locks down response headers (CSP `sandbox`, `nosniff`, `X-Frame-Options: DENY`, COOP/COEP/CORP, no-store), and re-checks path traversal at read time. |
| `src/ReplacementCardInputModel.cs` | Example model showing how file uploads are bound via `List<IFormFile>` in a multipart form alongside validated patron fields. |
| `tests/Fuzz/` | SharpFuzz + AFL++ harness for `FileContentValidator.ValidateAsync`. Catches unhandled exceptions, hangs, and runaway allocation in attacker-crafted inputs. See `tests/Fuzz/README.md`. |

---

## Key Design Decisions (and Why)

### Fail-Closed on Content Decisions
Unknown file types, malformed structures, deep-validation exceptions, missing or placeholder encryption secrets, and storage paths inside `wwwroot` all result in rejection or refusal to start. The default for any *content* decision is **deny**, not allow.

The one deliberate exception is **virus-scanner availability** (Layer 7). A scanner that returns *infected* always rejects the file. A scanner that is unreachable, times out, or throws is treated as **fail-open with explicit `NotScanned` tracking** — the file is accepted only because Layers 1–6 have already cleared it, and the outcome is surfaced in `FileUploadResult.ScanNotScannedCount` and logged as `VIRUS_SCAN_OPERATIONAL_FAILURE`. This is documented in [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and is the right trade-off for a patron-document workflow where a `clamd` outage must not block legitimate registrations; deployments that need scanner-availability to be hard-blocking should switch to a queued-scan model (see [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md) §1.3).

### Signature-First Classification (FileContentValidator)
The deep validator detects the *actual* file type from magic bytes before dispatching to the format-specific validator. A file claiming to be `.jpg` that opens with `%PDF` gets caught as a type mismatch before any format-specific logic runs.

### Extension ↔ MIME Cross-Validation (Layer 3)
The browser-reported `Content-Type` header is validated against the claimed extension. A `.pdf` file arriving with `image/jpeg` MIME is rejected. Neither the extension nor the MIME type is trusted independently.

### Storage Outside wwwroot (Layer 8)
The storage root is validated at construction time to be outside `wwwroot`. If someone misconfigures the path to resolve inside the web root (where files would be directly servable), the application **refuses to start**. This is enforced at the `IWebHostEnvironment` level, not just as documentation.

### Randomized Filenames
Files are stored as `{sanitizedLastName}{dateStamp}{formType}Doc{n}{randomSuffix}.ext`. The original filename is never used on disk. This prevents filename-based path traversal and removes any attacker control over the final storage path.

### AES-256-GCM with PBKDF2 (Envelope Encryption)
When encryption is enabled, files are stored using **envelope encryption (format v2)**:

1. A fresh random 256-bit Data Encryption Key (DEK) is generated per file.
2. The file payload is encrypted under the DEK with AES-256-GCM.
3. The DEK itself is then wrapped (encrypted) under the master Key Encryption Key (KEK), which is derived from `EncryptionSecret` via PBKDF2-SHA256 at 600,000 iterations (OWASP 2024 recommendation).
4. Layout on disk: `marker || dek_nonce || dek_tag || wrapped_dek || file_nonce || file_tag || ciphertext`.

This means **rotating the master key requires only re-wrapping each file's DEK** — the file payloads themselves don't need to be re-encrypted. Legacy single-key v1 files remain readable for backward compatibility. The application refuses to start if `EncryptionEnabled=true` but the secret is missing or still set to the placeholder.

### Image Recompression (Polyglot Defence)
When `FileUpload:RecompressImages=true` (default), JPEG / PNG / WebP uploads are decoded and re-encoded through ImageSharp before encryption. This **strips any data appended after the image's structural end** (the polyglot vector — a JPEG that's also a valid PHP/EXE). PDFs and other formats are untouched.

### FlateDecode-compressed PDF Stream Inspection
The PDF validator walks every `stream … endstream` block, attempts `DeflateStream` decompression, and re-runs the dangerous-pattern scan against the decompressed bytes. This catches `/JavaScript`, `/Launch`, etc. hidden inside compressed object streams. Bounded by `MaxCompressedStreamsToInspect` and `MaxDecompressedStreamBytes` for zip-bomb safety.

### Log-Poisoning-Safe Filename Handling
Every attacker-controlled filename is run through `SanitizeForLog` before being written to logs or echoed in user-facing error messages. Strips ANSI escape sequences, control characters, structured-log placeholders (`{`, `}`, `|`), CRLF, and Unicode bidi/zero-width tricks.

### Cross-Platform Virus Scanning
`IVirusScanService` has two production implementations:

- **`WindowsDefenderScanService`** — invokes `MpCmdRun.exe`; requires Windows.
- **`ClamAvScanService`** — talks to `clamd` directly over TCP using the documented `zINSTREAM` protocol. No temp file is written. Cross-platform (Linux, macOS, containers).

Detection is fail-closed: any clear malware signature rejects the upload. Operational failures (timeout, daemon down, unparseable response) are fail-open with explicit `NotScanned` tracking — the file is accepted only because it already passed Layers 1–6, and the outcome is counted in `FileUploadResult.ScanNotScannedCount` and emitted as a `VIRUS_SCAN_OPERATIONAL_FAILURE` log event. The result is **never silently relabelled as "clean"**.

### Hardened Download Surface (`SecureFileDownloadController`)
Serving decrypted patron documents safely is a separate problem from accepting them safely. The reference download controller:

- Re-checks path traversal at read time (defence in depth on top of upload-time check).
- Forces every response to `Content-Type: application/octet-stream` + `Content-Disposition: attachment` so the browser **cannot render the file inline** — PDFs never invoke Adobe Reader, images never get MIME-sniffed as HTML.
- Sends a strict header set: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; … sandbox`, `Cache-Control: no-store, private`, `Cross-Origin-{Resource,Opener,Embedder}-Policy`, `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`.
- Encodes the filename via `ContentDispositionHeaderValue.SetHttpFileName` (RFC 6266 UTF-8) to defeat header injection.

Wire it under an authenticated, MFA-gated staff route. Do **not** expose it anonymously.

### Secure Temp File Deletion (WindowsDefenderScanService)
The virus scanner writes files to a temp directory for scanning. After scanning, the temp file is overwritten with zeros before deletion. This reduces (though does not guarantee) recovery of sensitive content from freed disk sectors.

### ArrayPool + Buffer Zeroing (FileContentValidator)
Content validation uses `ArrayPool<byte>` for the read buffer. The buffer is **zeroed before being returned to the pool** to prevent patron document content (IDs, utility bills) from leaking into subsequent requests.

### PathHelper.IsPathUnderBase (Not StartsWith)
Path traversal checks use a proper base-path check rather than `string.StartsWith`. The `StartsWith` approach has a well-known prefix confusion bug: `/uploads_evil` matches `/uploads` when doing naive prefix checking. The helper uses canonicalized paths and directory separator boundary checks.

---

## Configuration Reference

```json
{
  "FileUpload": {
    "StorageRoot": "../uploads",
    "MaxFileSizeBytes": 10485760,
    "MaxFileCount": 5,
    "MaxTotalUploadBytes": 52428800,
    "MinStorageFreeBytes": 536870912,
    "MinTempFreeBytes": 536870912,
    "LowDiskWarningBytes": 2147483648,
    "RecompressImages": true,
    "JpegRecompressQuality": 95,
    "EncryptionEnabled": false,
    "EncryptionSecret": "CHANGE_THIS_TO_A_REAL_SECRET_MINIMUM_32_CHARS"
  },
  "FileContent": {
    "InspectCompressedPdfStreams": true,
    "MaxCompressedStreamsToInspect": 64,
    "MaxDecompressedStreamBytes": 16777216,
    "RejectEncryptedPdfs": true,
    "RejectInteractivePdfs": false,
    "MaxImageWidth": 10000,
    "MaxImageHeight": 10000,
    "MaxImagePixels": 40000000
  },
  "VirusScan": {
    "Enabled": false,
    "WindowsDefender": {
      "MpCmdRunPath": "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
      "TempScanPath": "C:\\Temp\\VirusScan",
      "TimeoutSeconds": 30
    },
    "ClamAv": {
      "Host": "localhost",
      "Port": 3310,
      "TimeoutSeconds": 30,
      "MaxStreamBytes": 26214400
    }
  }
}
```

**StorageRoot** is resolved relative to `ContentRootPath` (not `wwwRootPath`). A relative path like `../uploads` is typical to ensure it lands outside the web root.

**EncryptionSecret** must be at least 32 characters and must not contain the string `CHANGE_THIS`. If `EncryptionEnabled` is true and the secret fails this check, **the application will not start**.

**RecompressImages** defaults to `true`. Set it to `false` only if byte-exact preservation of patron-uploaded images is a hard requirement (you accept the polyglot risk).

**ClamAv:MaxStreamBytes** must align with the `StreamMaxLength` setting in your `clamd.conf`.

---

## Dependencies

The NuGet package declares these dependencies — no manual installation needed:

- **ASP.NET Core 8+** shared framework (via `FrameworkReference`)
- **[SixLabors.ImageSharp 3.1.x](https://github.com/SixLabors/ImageSharp)** — image structural validation and polyglot-tail recompression

At runtime, one scanner backend is also required (not a NuGet package):
- **Windows Defender** (`MpCmdRun.exe`) — Windows only, used by `WindowsDefenderScanService`
- **ClamAV** (`clamd` listening on TCP) — Linux/macOS/containers, used by `ClamAvScanService`

The scanner is selected automatically by `AddSecureFileUpload()` based on `OperatingSystem.IsWindows()`. Virus scanning can be disabled entirely via `VirusScan:Enabled: false` in appsettings (other 7 layers still run).

---

## Installation

```bash
dotnet add package SecureFileUpload.Core
```

Requires .NET 8+ with ASP.NET Core. The package targets `net8.0` and depends on the ASP.NET Core shared framework, which ships with every ASP.NET Core 8+ runtime — nothing extra needs to be installed.

---

## Integration Pattern

### Minimal registration (recommended)

```csharp
// Program.cs
using SecureFileUpload.Services;

// Registers FileContentValidator, the platform-appropriate IVirusScanService,
// and IFileUploadService in one call. Scanner options are read from appsettings
// ("FileContent" section). Pass a lambda to override in code.
builder.Services.AddSecureFileUpload();

// Size limit must match FileUpload:MaxTotalUploadBytes in appsettings.
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 53_477_376; // 51 MB — adjust to match your config
});
```

### Manual registration (if you need full control)

```csharp
// Program.cs / Startup registration
builder.Services.AddSingleton<FileContentValidator>();

// Pick ONE virus scanner based on platform:
if (OperatingSystem.IsWindows())
    builder.Services.AddSingleton<IVirusScanService, WindowsDefenderScanService>();
else
    builder.Services.AddSingleton<IVirusScanService, ClamAvScanService>();

builder.Services.AddSingleton<IFileUploadService, FileUploadService>();

// Configure multipart body size limit to match your FileUpload:MaxTotalUploadBytes
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 53_477_376; // 51 MB
});
```

### Controller usage

```csharp
[HttpPost]
[RequestSizeLimit(53_477_376)]
public async Task<IActionResult> Submit(MyInputModel model)
{
    if (!ModelState.IsValid)
        return View(model);

    var files = Request.Form.Files;
    var result = await _fileUploadService.UploadFilesAsync(files, model.LastName, "remote");

    if (!result.Success)
    {
        // result.Errors contains user-safe messages
        // result.WorkflowOutcome: AllSaved | PartialSaved | AllRejected | NoFiles
        foreach (var error in result.Errors)
            ModelState.AddModelError(string.Empty, error);
        return View(model);
    }
    // ...
}
```

---

## Docs

- [`docs/threat-model.md`](docs/threat-model.md) — What attack each layer defeats
- [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md) — Recommendations to reach the strongest realistic posture
- [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md) — AI red-team adversarial findings (with current resolution status)
- [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — Honest limitations and what this does NOT protect against
- [`tests/attack-vectors.md`](tests/attack-vectors.md) — Per-layer attack test cases (manual + automation guide)
- [`tests/Fuzz/`](tests/Fuzz) — SharpFuzz + AFL++ harness for the deep content validator

---

## License

MIT. Use freely. Attribution appreciated but not required.

---

## Contributing

Issues and PRs welcome, especially:
- Unit test coverage for the validation layers
- Additional format validators (GIF, BMP deep content validation)
- Async/queued virus-scan worker for high-volume deployments
