# SecureFileUpload.Core

**Defense-in-depth file upload pipeline for ASP.NET Core 10+ — AES-256-GCM envelope encryption, Argon2id key derivation, deep content validation, and pluggable virus scanning.**

[![NuGet](https://img.shields.io/nuget/v/SecureFileUpload.Core.svg?style=flat-square)](https://www.nuget.org/packages/SecureFileUpload.Core)
[![NuGet downloads](https://img.shields.io/nuget/dt/SecureFileUpload.Core.svg?style=flat-square)](https://www.nuget.org/packages/SecureFileUpload.Core)
[![Build](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml/badge.svg)](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml)
[![Target: net10.0](https://img.shields.io/badge/target-net10.0-512BD4.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

`SecureFileUpload.Core` is a battle-tested file-upload pipeline lifted from a production ASP.NET Core document-intake workflow, de-branded, hardened, and shipped as a single NuGet package. Every layer is implemented in code you can read; every limitation is named in [`KNOWN-GAPS.md`](KNOWN-GAPS.md); every security claim traces to a specific line in `src/` per the audit in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md).

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31

---

## What's New in 2.0.0

`2.0.0` is the first stable release of the modernized line. **The 8-layer pipeline is unchanged from the 1.0.x preview series.** The crypto floor and the runtime target both moved up. If you're on `1.0.0`, treat this as a breaking upgrade — the TFM dropped from `net8.0` to `net10.0` and the KEK derivation defaults changed.

- **Argon2id for KEK derivation.** The master Key Encryption Key is now derived via Argon2id (RFC 9106, OWASP 2024+ recommendation) with memory-hard defaults — `m=64 MiB, t=3, p=4`. Memory-hardness raises the cost-per-guess on GPUs and ASICs by orders of magnitude over the prior PBKDF2-SHA256 derivation.
- **Backward-compatible online upgrade.** Files wrapped under prior PBKDF2 KEKs (600 000 and 210 000 iterations) still decrypt via `FileUpload:KeyDerivation:LegacyKekFallback=true` (default). No file on disk is bricked by the upgrade. New writes always use the Argon2id-derived KEK.
- **Configurable KDF.** Argon2id is the default; `KeyDerivation:Algorithm = "Pbkdf2"` is available for FIPS-restricted environments. All Argon2id parameters and the PBKDF2 iteration count are tunable from `appsettings.json`.
- **.NET 10.** Target framework consolidated on `net10.0` only. Pin `1.0.x-preview.0` if you need a `net8.0`-only build.
- **Packaging.** Deterministic build, Source Link, `.snupkg` symbols, and `README.md` / `LICENSE` / `SECURITY-ANALYSIS.md` / `KNOWN-GAPS.md` bundled inside the package itself.

The crypto posture, parameters, and honest residual risks are documented in [Implementation & Crypto Posture](#implementation--crypto-posture) below and in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md).

---

## Why this exists

File upload is one of the most consistently mishandled surfaces in web development. Most tutorials show you how to *receive* a file. Very few defend against:

- Polyglot files (a valid JPEG that is also a working PHP shell)
- Double-extension attacks (`photo.pdf.exe`)
- MIME spoofing and magic-byte forgery
- Path traversal via filename manipulation
- PDF JavaScript injection (including inside FlateDecode-compressed object streams)
- ZIP-bomb / pixel-flood attacks via image decoding
- Log poisoning via crafted filenames
- Disk exhaustion via batched uploads
- Direct web-serving of attacker-controlled bytes

This package addresses every item on that list in code, then names the gaps it does *not* close. The red-team review in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md) traces each claim to its source line.

---

## The 8-layer pipeline

Every uploaded file passes through eight serial layers. **Failure at any content-decision layer rejects the file.** The pipeline is fail-closed on content; the single fail-open seam is virus-scanner *availability* (Layer 7), and that is documented, counted, and never silently relabelled as clean — see [`KNOWN-GAPS.md §Gap 9`](KNOWN-GAPS.md).

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         INCOMING FILE UPLOAD                              │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │
       ┌───────────────────────▼────────────────────────┐
       │  Layer 1   File size (per-file + batch total)   │
       │            Minimum size per format               │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 2   Extension allowlist                   │
       │            .jpg .jpeg .png .webp .pdf            │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 3   MIME ↔ extension cross-validation     │
       │            Browser MIME must match extension     │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 4   Magic-byte signature check            │
       │            JPEG / PNG / WebP fourCC / PDF        │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 5   Filename inspection                   │
       │            Double-extension, Unicode bidi,       │
       │            path traversal, Windows reserved      │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 6   Deep content validation               │
       │            JPEG/PNG/WebP structural walkers,     │
       │            PDF byte-pattern scan,                │
       │            FlateDecode-compressed PDF stream     │
       │            decompression and re-scan             │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 7   Virus scan (pluggable)                │
       │            Windows Defender OR ClamAV / clamd    │
       │            Detection fail-closed,                │
       │            Availability fail-open (tracked)      │
       └───────────────────────┬────────────────────────┘
       ┌───────────────────────▼────────────────────────┐
       │  Layer 8   Encrypted storage                     │
       │            AES-256-GCM envelope (v2):            │
       │              per-file random DEK                 │
       │              wrapped under Argon2id-derived KEK  │
       │            Image recompression strips polyglot   │
       │            tails before encryption.              │
       │            Randomized filename, outside wwwroot. │
       │            Path traversal re-checked before      │
       │            write via PathHelper.IsPathUnderBase. │
       └──────────────────────────────────────────────────┘
```

---

## Install

```bash
dotnet add package SecureFileUpload.Core
```

Requires **.NET 10+** with ASP.NET Core. The package references `Microsoft.AspNetCore.App` as a framework reference, so nothing extra ships inside it — your runtime's existing ASP.NET Core does the heavy lifting.

If you need a `net8.0` build, pin to `1.0.0` (the prior stable line) — Argon2id and `net10.0` arrived in the `1.0.0-preview.2` candidates and are the default in `2.0.0`.

---

## Quick start

### 1. Register the services

```csharp
// Program.cs
using SecureFileUpload.Services;

builder.Services.AddSecureFileUpload();

// Match this to FileUpload:MaxTotalUploadBytes in appsettings.json.
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 53_477_376; // 51 MB
});
```

`AddSecureFileUpload()` registers `FileContentValidator`, the platform-appropriate `IVirusScanService` (Windows Defender on Windows, ClamAV elsewhere), and `IFileUploadService` in one call. The scanner backend is picked at startup; switching it is one DI line, not a code change.

### 2. Receive an upload

```csharp
[HttpPost]
[RequestSizeLimit(53_477_376)]
public async Task<IActionResult> Submit(MyInputModel model)
{
    if (!ModelState.IsValid)
        return View(model);

    var result = await _fileUploadService.UploadFilesAsync(
        Request.Form.Files, model.LastName, "intake");

    if (!result.Success)
    {
        // result.Errors are user-safe; result.WorkflowOutcome is
        // AllSaved | PartialSaved | AllRejected | NoFiles.
        foreach (var msg in result.Errors)
            ModelState.AddModelError(string.Empty, msg);
        return View(model);
    }

    return RedirectToAction(nameof(Submitted), new { id = result.SubmissionFolder });
}
```

### 3. Serve a file safely

```csharp
// Wire the reference controller behind an authenticated, MFA-gated route.
// SecureFileDownloadController forces Content-Disposition: attachment,
// a strict CSP, X-Frame-Options: DENY, COOP/COEP/CORP, and re-checks
// path traversal at read time — the file never renders inline.
services.AddControllers().AddApplicationPart(typeof(SecureFileDownloadController).Assembly);
```

A complete `appsettings.json` reference is in [Configuration](#configuration) below.

---

## Implementation & Crypto Posture

This section names primitives, parameters, and residual risks. It is the single source of truth for the cryptographic posture; the marketing tagline is at the top of this README.

| Aspect | Implementation | Notes |
|---|---|---|
| Symmetric encryption | **AES-256-GCM** via `System.Security.Cryptography.AesGcm` | 96-bit nonce, 128-bit auth tag — NIST SP 800-38D / RFC 5288. |
| Encryption scheme | **Envelope (v2)** — per-file random 256-bit DEK wrapped under a master KEK | KEK rotation rewraps DEKs without re-encrypting file payloads. |
| KEK derivation (writes) | **Argon2id** via `Konscious.Security.Cryptography.Argon2` 1.3.x | RFC 9106; OWASP 2024+ recommendation. Memory-hard. |
| Argon2id parameters (defaults) | `m=64 MiB`, `t=3`, `p=4`, fixed application salt | Above OWASP server-side minimum; targets ~250–500 ms derivation on a modern x64 core. |
| KEK derivation (decrypt fallback) | PBKDF2-SHA256, 600 000 and 210 000 iterations | Tried during decryption when `LegacyKekFallback=true`; never for new writes. |
| RNG | `RandomNumberGenerator` (CSPRNG) for DEKs, nonces, filename suffixes | No `System.Random`, no `Guid.NewGuid()`, no `DateTime.Ticks` in security paths. |
| Storage format markers | `ENCGCM\0\x01` (legacy single-key) / `ENCGCM\0\x02` (current envelope) | Layout: `marker‖dek_nonce‖dek_tag‖wrapped_dek‖file_nonce‖file_tag‖ciphertext`. |
| Buffer hygiene | Plaintext, DEK, and password buffers zeroed via `CryptographicOperations.ZeroMemory` | Reduces in-memory exposure window. Not a guarantee against GC copies. |
| Startup guards | `EncryptionEnabled=true` + missing/placeholder secret ⇒ `InvalidOperationException` | Misconfigurations fail loudly at deploy time, not silently at runtime. |
| FIPS posture | **Not FIPS-validated.** Argon2id is not in FIPS 140-3 ASMs as of 2026 | Opt into `KeyDerivation:Algorithm = "Pbkdf2"` for FIPS-only deployments. |
| TLS / transport | Not provided by this library | Enforce HSTS and HTTPS at Kestrel / reverse-proxy level. |
| At-rest device encryption | Not provided by this library | BitLocker / LUKS / dm-crypt strongly recommended on the storage volume. |

### Honest limitations

- **The KDF salt is in source.** It is identical across deployments of this library version. The protection model assumes the *secret* lives in a real secrets manager (Key Vault, AWS Secrets Manager, env var injected by the platform) — never `appsettings.json` committed to a repo.
- **Argon2id is not FIPS-validated.** Compliance-bound deployments must select `Pbkdf2` explicitly.
- **The KEK lives in process memory.** A memory-disclosure or core-dump capability on the host bypasses the KDF entirely. Mitigations are deployment-level (least privilege, ASLR, sealed VMs, confidential compute).
- **No HSM / KMS integration in v1.** A KMS-backed KEK is tracked in [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md) as the right next step for high-assurance deployments.
- **Argon2id parameters are CPU/RAM-bound.** On a constrained container, startup derivation may take longer than the ~250–500 ms target. The library logs `KDF_ARGON2ID_DERIVED | ElapsedMs=...` so this is measurable.

For the full code-traced security review, see [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md). For things this pipeline does *not* protect against, see [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

---

## Configuration

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
    "EncryptionSecret": "CHANGE_THIS_TO_A_REAL_SECRET_MINIMUM_32_CHARS",
    "KeyDerivation": {
      "Algorithm": "Argon2id",
      "Argon2id": {
        "MemoryKiB": 65536,
        "Iterations": 3,
        "Parallelism": 4
      },
      "Pbkdf2": {
        "Iterations": 600000
      },
      "LegacyKekFallback": true
    }
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

| Setting | Purpose |
|---|---|
| `FileUpload:StorageRoot` | Resolved relative to `ContentRootPath`. Must land outside `wwwroot`. The service refuses to start otherwise. |
| `FileUpload:EncryptionSecret` | ≥ 32 chars, must not contain `CHANGE_THIS`. Store in a secrets manager — **never** in checked-in config. |
| `FileUpload:KeyDerivation:Algorithm` | `Argon2id` (default) or `Pbkdf2` (FIPS-restricted environments only). |
| `FileUpload:KeyDerivation:Argon2id:*` | Tune for your CPU/RAM budget. Library logs derivation time at startup. |
| `FileUpload:KeyDerivation:LegacyKekFallback` | `true` (default) keeps PBKDF2 fallback KEKs available for *decryption only*. Set `false` after every file has been re-wrapped. |
| `FileUpload:RecompressImages` | `true` (default) strips polyglot tails by re-encoding JPEG/PNG/WebP through ImageSharp. |
| `VirusScan:Enabled` | When `false`, Layer 7 is bypassed. Layers 1–6 + 8 still run. |
| `VirusScan:ClamAv:MaxStreamBytes` | Must align with `StreamMaxLength` in your `clamd.conf`. |

---

## Dependencies

Declared by the NuGet package — no manual installation required:

- **ASP.NET Core 10+** shared framework (via `FrameworkReference`)
- **[SixLabors.ImageSharp 3.1.x](https://github.com/SixLabors/ImageSharp)** — image identification and polyglot-tail recompression
- **[Konscious.Security.Cryptography.Argon2 1.3.x](https://github.com/kmaragon/Konscious.Security.Cryptography)** — Argon2id KEK derivation

Required at runtime if `VirusScan:Enabled=true` (not NuGet packages):

- **Windows Defender** (`MpCmdRun.exe`) — Windows only, used by `WindowsDefenderScanService`
- **ClamAV** (`clamd` listening on TCP) — Linux / macOS / containers, used by `ClamAvScanService`

The scanner is selected automatically by `AddSecureFileUpload()` based on `OperatingSystem.IsWindows()`.

---

## Source layout

| File | Responsibility |
|---|---|
| `src/FileUploadService.cs` | Orchestrates the 8-layer pipeline. Batch limits, capacity checks, image recompression (Gap 1), envelope encryption (v2), Argon2id KEK derivation with PBKDF2 fallback, log-poisoning-safe filename handling. |
| `src/FileContentValidator.cs` | Layer 6 deep validation. JPEG / PNG / WebP structural walking, PDF pattern scan, FlateDecode-compressed PDF stream inspection (Gap 2). Fail-closed on unknown types. |
| `src/WindowsDefenderScanService.cs` | Layer 7 — Windows Defender `MpCmdRun.exe`. Secure-delete (zero-before-delete) of temp files. |
| `src/ClamAvScanService.cs` | Layer 7 — `clamd` over TCP using `zINSTREAM`. No temp file is written. Cross-platform. |
| `src/SecureFileDownloadController.cs` | Reference hardened download surface. `Content-Disposition: attachment`, strict CSP, COOP/COEP/CORP, re-checks path traversal. |
| `src/DependencyInjection/SecureFileUploadServiceCollectionExtensions.cs` | `AddSecureFileUpload()` one-liner DI registration. |
| `src/Utilities/PathHelper.cs` | Canonicalized `IsPathUnderBase` — defeats the `string.StartsWith("/uploads")` prefix-confusion bug. |
| `tests/Fuzz/` | SharpFuzz + AFL++ harness for `FileContentValidator.ValidateAsync`. |
| `tests/SmokeTest/` | Runtime smoke test — Argon2id round-trip, v2 envelope, legacy PBKDF2 fallback, misconfig guard. Run with `dotnet run --project tests/SmokeTest -c Release` before publishing. |

---

## Docs

- [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md) — full code-traced security review, with each claim pointing at source lines
- [`KNOWN-GAPS.md`](KNOWN-GAPS.md) — honest limitations and what this does NOT protect against
- [`docs/threat-model.md`](docs/threat-model.md) — what attack each layer defeats
- [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md) — recommended next steps toward the strongest realistic posture
- [`tests/attack-vectors.md`](tests/attack-vectors.md) — per-layer attack test cases
- [`tests/Fuzz/`](tests/Fuzz/) — SharpFuzz + AFL++ harness for the deep content validator

---

## Release process

Publishing is handled by GitHub Actions in `.github/workflows/nuget-publish.yml`.

- Push to `main` runs build, pack, and a fuzz-harness build — no publish.
- Push a `v*` tag to publish to NuGet.org. The workflow derives the package version from the tag (`v2.0.0` → `2.0.0`).
- `--skip-duplicate` is used, so re-running on an existing version is non-destructive.

```bash
git tag v2.0.0
git push origin v2.0.0
```

The `<Version>` in `src/SecureFileUpload.Core.csproj` is the source of truth for local packs and CI artifacts; tag builds override it for the published NuGet version.

---

## Contributing

Issues and PRs welcome — especially:

- Unit-test coverage for the per-layer validation paths
- Additional format validators (GIF, BMP deep content validation)
- Async / queued virus-scan worker for higher-volume deployments
- KMS / HSM-backed KEK provider

If you're filing a security report, please open a private advisory on GitHub rather than a public issue.

---

## License

[MIT](LICENSE). Use freely. Attribution appreciated, not required.

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31
