# SecureFileUpload.Core

**The defense-in-depth file-upload pipeline from a real production library system, packaged for ASP.NET Core 8 / 9 / 10.**

[![NuGet](https://img.shields.io/nuget/v/SecureFileUpload.Core.svg?style=flat-square)](https://www.nuget.org/packages/SecureFileUpload.Core)
[![NuGet downloads](https://img.shields.io/nuget/dt/SecureFileUpload.Core.svg?style=flat-square)](https://www.nuget.org/packages/SecureFileUpload.Core)
[![Build](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml/badge.svg)](https://github.com/systemslibrarian/secure-file-upload-dotnet/actions/workflows/nuget-publish.yml)
[![Targets: net8.0 / net9.0 / net10.0](https://img.shields.io/badge/targets-net8.0%20%7C%20net9.0%20%7C%20net10.0-512BD4.svg?style=flat-square)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)

`SecureFileUpload.Core` is lifted from the document-intake workflow of a live public-library patron-registration system, de-branded, hardened, and shipped as a single NuGet package. Eight serial validation layers, encrypted-at-rest storage outside `wwwroot`, and a hardened reference download surface — all behind one `AddSecureFileUpload()` call. Every layer is implemented in code you can read; every limitation is named in [`KNOWN-GAPS.md`](KNOWN-GAPS.md); every security claim traces to a specific line in `src/` per the audit in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md).

> This package is **independent of the PostQuantum.\* family.** It is a classical (non-PQC) security library: AES-256-GCM at rest, Argon2id for the master KEK, no post-quantum asymmetric layer. See [`SECURITY.md → Crypto classification`](SECURITY.md) for the explicit posture statement.

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31

---

## What's New in 3.0.3

`3.0.3` is a **defense-in-depth hardening patch**. No public API break. `AssemblyVersion` stays at `3.0.0.0` — drop-in upgrade from any `3.0.x`.

- **Filename validation is NFKC-normalized.** A fullwidth `．．` (U+FF0E ×2) can no longer pretend not to be `..`; fullwidth reserved names (`ＣＯＮ.pdf`) and fullwidth-disguised double-extensions (`evil．exe.pdf`) are caught alongside their literal forms. Trailing dot and trailing space are rejected before Windows path resolution strips them. Hard 255-character length cap. **Legitimate non-ASCII filenames** (accented Latin, CJK, Cyrillic, Greek, etc.) **pass through unchanged** — NFKC is identity on those.
- **PDF deep validation gains hard caps against decompression bombs and polyglots.** Per-stream **decompression-ratio cap** (default `200×`), per-file **wall-clock timeout** (default `2 000 ms`), bounded **nested-stream recursion depth** (default `2` for `/ObjStm`), and full `CancellationToken` propagation through the FlateDecode walker.
- **AV availability mode is now configurable.** `VirusScan:FailClosedOnUnavailable` (default `false` = prior fail-open behavior). Set `true` to reject the upload when the scanner cannot give a verdict. Detection mode is **always** fail-closed regardless of this flag. A uniform `VIRUS_SCAN_SKIPPED` security event fires in both modes — operators alert on a single signal.
- **Crypto classification is now explicit.** At-rest encryption is **classical AES-256-GCM** (quantum-tolerant by key size for confidentiality, but no PQ asymmetric layer). New [`SECURITY.md`](SECURITY.md) states the posture and the deliberate separation from the `PostQuantum.*` family.
- **`HardeningRegressionTests` adds 25 cases** covering filename evasions and legitimate-Unicode acceptance, decompression-bomb rejection inside the time budget, nested FlateDecode recursion, cancellation propagation, fail-closed AV mode, concurrent encrypted uploads, and `PathHelper.IsPathUnderBase` encoded-separator resistance. Fuzz harness gains a triage assertion that treats any `Allowed` verdict on a curated seed under [`tests/Fuzz/seeds/`](tests/Fuzz/seeds/) as a finding.
- **No change** to the 8-layer pipeline order, the v2 envelope encryption format (`ENCGCM\0\x02`), the Argon2id KEK derivation, the PBKDF2 legacy decrypt fallback, or the plaintext / DEK / KDF-input zeroing discipline. Smoke harness still 18/18 green.

## What's New in 3.0.2

`3.0.2` restores **multi-targeting** for `net8.0`, `net9.0`, and `net10.0`. Dropping to `net10.0`-only in `3.0.0` was a strategic mistake — it forced consumers on currently-supported LTS / STS runtimes to either pin to the `2.x` line or upgrade their host before they could take any of the `3.x` hardening. This release re-publishes the same source as a multi-targeted package.

- **TargetFrameworks: `net8.0;net9.0;net10.0`.** Same source, same crypto posture, same on-disk envelope formats. The entire pipeline already compiled against the .NET 8 BCL; no conditional compilation was needed.
- **No behavioral or breaking changes from `3.0.1`.** Argon2id KEK derivation, AES-256-GCM v2 envelope, legacy PBKDF2 fallback, opaque download tokens, hardened download controller, and Data Protection deployment guidance are unchanged.
- **AssemblyVersion stays at `3.0.0.0`** so this is a drop-in upgrade with no binding-redirect change required.

## What's New in 3.0.0

`3.0.0` is the hardened download-surface release. **The 8-layer upload pipeline and on-disk crypto formats are unchanged from `2.0.0`.** This release is about the staff-download contract, release validation, and operator-facing correctness.

- **Opaque download tokens replace path-based download links.** The reference controller now accepts `fileToken`, issued by `IFileAccessTokenService`, instead of a storage-relative path. If you linked staff downloads with `relativePath`, update that integration before upgrading.
- **Release validation is now an actual gate.** The solution tests and the runtime smoke harness both run in CI before pack/publish, so the NuGet package is validated against the same path documented in this repo.
- **Scanner outage logs now match runtime behavior.** ClamAV and Windows Defender unavailability are logged as `NotScanned` fail-open conditions instead of incorrectly implying fail-closed rejection.

`2.0.0` was the first stable release of the modernized line. The Argon2id KEK and PBKDF2 fallback story from that release still applies:

- **Argon2id for KEK derivation.** The master Key Encryption Key is now derived via Argon2id (RFC 9106, OWASP 2024+ recommendation) with memory-hard defaults — `m=64 MiB, t=3, p=4`. Memory-hardness raises the cost-per-guess on GPUs and ASICs by orders of magnitude over the prior PBKDF2-SHA256 derivation.
- **Backward-compatible online upgrade.** Files wrapped under prior PBKDF2 KEKs (600 000 and 210 000 iterations) still decrypt via `FileUpload:KeyDerivation:LegacyKekFallback=true` (default). No file on disk is bricked by the upgrade. New writes always use the Argon2id-derived KEK.
- **Configurable KDF.** Argon2id is the default; `KeyDerivation:Algorithm = "Pbkdf2"` is available for FIPS-restricted environments. All Argon2id parameters and the PBKDF2 iteration count are tunable from `appsettings.json`.
- **Packaging.** Deterministic build, Source Link, `.snupkg` symbols, and `README.md` / `LICENSE` / `SECURITY-ANALYSIS.md` / `KNOWN-GAPS.md` bundled inside the package itself.

The crypto posture, parameters, and honest residual risks are documented in [Implementation & Crypto Posture](#implementation--crypto-posture) below and in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md).

---

## What this is

Most ASP.NET Core upload examples show you how to *receive* a file. This package is the production version of an intake workflow that has accepted thousands of patron documents — driver's licenses, utility bills, library replacement-card paperwork — under real-world adversarial conditions. The eight layers exist because each one caught something in production:

- Polyglot files (a valid JPEG that is also a working PHP shell)
- Double-extension attacks (`photo.pdf.exe`, including fullwidth-Unicode disguises after NFKC normalization)
- MIME spoofing and magic-byte forgery
- Path traversal via filename manipulation, NTFS alternate data streams, and Windows reserved device names
- PDF JavaScript injection (including inside FlateDecode-compressed object streams, with hard caps on stream count, decompressed bytes, decompression ratio, and wall-clock time)
- ZIP-bomb / pixel-flood attacks via image decoding
- Log poisoning via crafted filenames
- Disk exhaustion via batched uploads
- Direct web-serving of attacker-controlled bytes

This package addresses every item on that list in code, then names the gaps it does *not* close. The red-team review in [`SECURITY-ANALYSIS.md`](SECURITY-ANALYSIS.md) traces each claim to its source line. You do not need to care about cryptography to adopt the upload pipeline — crypto details are in §[Implementation & Crypto Posture](#implementation--crypto-posture) below; the validation pipeline runs identically whether or not you read that section.

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

### What each layer actually does

For an ASP.NET developer adopting this pipeline without any cryptography interest, here is the one-paragraph "what does this defend against" view of each layer. Crypto details remain in §[Implementation & Crypto Posture](#implementation--crypto-posture) below — the pipeline runs identically whether or not you read that section.

| Layer | Defends against | One-line summary |
|---|---|---|
| 1 — Size + batch | Disk-exhaustion DoS, oversized scans | Per-file and per-batch byte caps enforced before any buffering. |
| 2 — Extension allowlist | Wrong-format uploads, executables-by-name | Only `.jpg .jpeg .png .webp .pdf` proceed. Everything else stops here. |
| 3 — MIME ↔ extension cross-check | MIME-spoofing toolchains | Browser-reported `Content-Type` must match the extension. Mismatch rejects. |
| 4 — Magic-byte signature | Renamed `.exe → .pdf` and disguised payloads | Header bytes must match the format; known-dangerous headers (PE/ELF/Mach-O/OLE/PHP/script) are named in the log message so an operator can spot the disguise. |
| 5 — Filename inspection | Path traversal, NTFS alternate data streams, Unicode bidi/zero-width tricks, double-extension (`photo.pdf.exe`), Windows reserved device names (`CON`, `PRN`, `NUL`, `COM1-9`, `LPT1-9`), trailing dots/spaces, control characters, fullwidth-Unicode disguises | NFKC-normalized scan so a fullwidth `．．` cannot pretend not to be `..`; 255-character length cap; trailing `.` or space is rejected before Windows path resolution strips it. |
| 6 — Deep content validation | Polyglot files, PDF JavaScript / `/Launch` / `/EmbeddedFile` / JBIG2, embedded executables, ZIP-bomb image dimensions, PHP shells in image metadata | Format-specific structural walkers (JPEG segments, PNG chunks, WebP RIFF tree, GIF blocks, BMP DIB) plus a FlateDecode-compressed PDF stream scanner with hard caps on stream count, total decompressed bytes, **per-stream decompression ratio**, **per-file wall-clock time**, and **recursion depth** for nested compressed object streams. Fail-closed on any unknown type or exception. |
| 7 — Virus scan | Known-bad signatures the prior layers can't fingerprint | Windows Defender (`MpCmdRun.exe`) on Windows, ClamAV (`clamd` over TCP) elsewhere. **Detection is always fail-closed; availability is a configured operator choice — see §AV failure mode below.** |
| 8 — Encrypted storage | At-rest disclosure if the storage volume leaks or is exfiltrated | AES-256-GCM envelope (v2): per-file random 256-bit DEK wrapped under an Argon2id-derived master KEK. Image recompression strips polyglot tails before encryption. Randomized filename outside `wwwroot`. Final `PathHelper.IsPathUnderBase` re-check at write time. Plaintext, DEK, and KDF-input buffers zeroed in `finally` blocks. |

### AV failure mode: fail-open vs. fail-closed (explicit operator choice)

When the virus scanner is **unreachable** (clamd down, `MpCmdRun.exe` missing, timeout, parser error, exception), the pipeline must pick one of two behaviors. As of `3.0.2` this is an explicit configuration option:

- **Fail-open on availability** — `VirusScan:FailClosedOnUnavailable=false` *(default; matches prior behavior)*. The file is accepted and recorded as `NotScanned`, counted in `FileUploadResult.ScanNotScannedCount`, and a single `VIRUS_SCAN_SKIPPED` security event is emitted with `Reason=ScannerUnavailable` so operators can alert on a non-zero count per window. This is the trade-off the original library deployment made: a Defender hiccup must not block patrons from registering for a library card.
- **Fail-closed on availability** — `VirusScan:FailClosedOnUnavailable=true`. Scanner unavailability **rejects** the upload with a clear `scanner unavailable` workflow error. The same `VIRUS_SCAN_SKIPPED` metric is still emitted so operations can alert identically in either mode.

**Detection** (an `Infected` verdict from a reachable scanner) is **always fail-closed**, regardless of this setting. The knob only controls what happens when the scanner cannot give a verdict at all. Pick the mode that matches your environment's risk tolerance; do not pick by default.

---

## Install

```bash
dotnet add package SecureFileUpload.Core
```

Multi-targets **`net8.0`**, **`net9.0`**, and **`net10.0`** — same source, same crypto posture, on every currently-supported .NET runtime. The package references `Microsoft.AspNetCore.App` as a framework reference, so nothing extra ships inside it; your runtime's existing ASP.NET Core does the heavy lifting.

Pick the TFM that matches your host:

| Host runtime              | NuGet picks         | Notes |
|---------------------------|---------------------|-------|
| .NET 8 (LTS, in support)  | `net8.0` build      | Same `FileUploadService` / `FileContentValidator` source. |
| .NET 9 (STS, in support)  | `net9.0` build      | Same source. |
| .NET 10 (LTS, current)    | `net10.0` build     | Same source. |

> If you're upgrading from any prior `3.0.x` (`3.0.0` / `3.0.1` / `3.0.2`), this is a drop-in change — `AssemblyVersion` is unchanged at `3.0.0.0` and the on-disk envelope formats (`ENCGCM\0\x01` / `ENCGCM\0\x02`) are byte-for-byte compatible. No re-wrap, no migration. The new `VirusScan:FailClosedOnUnavailable` knob defaults to `false`, which preserves the prior fail-open behavior — opt in to fail-closed availability only if your environment requires it.

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

`AddSecureFileUpload()` registers `FileContentValidator`, the platform-appropriate `IVirusScanService` (Windows Defender on Windows, ClamAV elsewhere), `IFileUploadService`, and `IFileAccessTokenService` in one call. The scanner backend is picked at startup; download tokens are issued through ASP.NET Core Data Protection with a short lifetime by default.

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
using SecureFileUpload.Services;

builder.Services
  .AddAuthentication("Cookies")
  .AddCookie("Cookies");

builder.Services.AddAuthorization(options =>
{
  options.AddPolicy("StaffFiles", policy =>
  {
    policy.RequireAuthenticatedUser();
    policy.RequireRole("Staff");
    // Add your own MFA / claim requirements here.
  });
});

// SecureFileDownloadController is [Authorize] by default. Apply your stricter
// staff-only policy at the endpoint layer so the sample policy is actually used.
builder.Services.AddControllers().AddApplicationPart(typeof(SecureFileDownloadController).Assembly);

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers().RequireAuthorization("StaffFiles");
```

### 4. Issue an opaque download token

```csharp
public sealed class StaffFilesController : Controller
{
    private readonly IFileAccessTokenService _fileAccessTokenService;

    public StaffFilesController(IFileAccessTokenService fileAccessTokenService)
    {
        _fileAccessTokenService = fileAccessTokenService;
    }

    public IActionResult DownloadFirst(FileUploadResult result)
    {
        string token = _fileAccessTokenService.CreateToken(result.UploadedFilePaths[0]);
        string url = $"/staff/files/download?fileToken={Uri.EscapeDataString(token)}";
        return Redirect(url);
    }
}
```

The token is opaque, signed, and short-lived by default. Staff-facing URLs never need to expose a storage-relative path. If your application has both public and staff-only controllers, scope the `RequireAuthorization("StaffFiles")` call to the staff route set instead of every controller endpoint in the app.

A complete `appsettings.json` reference is in [Configuration](#configuration) below.

---

## Deployment notes

### Data Protection and multi-instance deployments

`AddSecureFileUpload()` calls `services.AddDataProtection()` so that `IFileAccessTokenService` can sign download tokens. With the default registration, **each process generates its own ephemeral key ring** — fine for a single-instance app, but **broken across replicas**: a token issued by node A will not validate on node B, so any load-balanced staff request to `/staff/files/download` has a chance of returning `400 Invalid file reference.`

For any deployment with more than one instance (Kubernetes, multiple App Service workers, an autoscaled VM scale set, dev → staging container, blue-green), configure Data Protection to share a key store and pin an application name **before** `AddSecureFileUpload()`:

```csharp
// Pick ONE persistence backend that all instances can read.

// Shared filesystem mount (Linux + ReadWriteMany PVC, Windows file share):
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo("/var/keys/secure-file-upload"))
    .SetApplicationName("SecureFileUpload");

// — OR — Azure Blob + Key Vault (recommended on Azure):
// builder.Services.AddDataProtection()
//     .PersistKeysToAzureBlobStorage(blobUri, credential)
//     .ProtectKeysWithAzureKeyVault(keyIdentifier, credential)
//     .SetApplicationName("SecureFileUpload");

builder.Services.AddSecureFileUpload();
```

`SetApplicationName(...)` is the gate that makes keys interchangeable across processes — without it, ASP.NET Core derives a per-content-root application discriminator and tokens still won't cross instances even with a shared key store. The string itself is not a secret; just keep it stable across deployments.

**Symptom of getting this wrong:** intermittent `DOWNLOAD_REJECTED_BAD_TOKEN` warnings in the logs, only on multi-instance environments, only for tokens issued by a different instance than the one handling the download. The single-instance happy-path keeps working, which makes it easy to ship the misconfiguration. Catch it in load-balanced staging.

### Token replay window

A signed download token is reusable for its configured lifetime (`FileDownload:TokenLifetimeMinutes`, default 15 minutes). If a token leaks via a referrer, a screen recording, a log entry, or shared-screen support, an attacker with network access to the staff endpoint can replay it until expiry. Mitigations layered into the library and the recommended deployment:

- `Cache-Control: no-store, no-cache, must-revalidate, private` on every download response — no shared proxy keeps a copy.
- `Referrer-Policy: no-referrer` so the token doesn't leak to other origins.
- `[Authorize]` on `SecureFileDownloadController` plus the recommended `RequireAuthorization("StaffFiles")` policy — a leaked token is useless to an unauthenticated attacker.
- Short default lifetime; lower it further for high-sensitivity workflows.
- **User binding (3.1.0, opt-in):** set `FileDownload:BindTokensToUser=true` and the authenticated user's identity (`ClaimTypes.NameIdentifier`, falling back to `Identity.Name`) is folded into the Data Protection purpose chain at token creation. The token then only unprotects for a request carrying the *same* identity — a token replayed by any other account fails cryptographic verification, not just a policy check. Issuing a token on an unauthenticated request throws. Requires `IHttpContextAccessor`, which `AddSecureFileUpload()` registers for you. Tokens issued before enabling the flag stop validating (they are unbound) — a non-issue in practice given the 15-minute default lifetime.

With user binding enabled, the replay window shrinks to "the same authenticated account within the token lifetime." There is still no single-use / nonce-redemption mode in v3. If you need one, track it as a v3.x feature request — the right shape is a redemption store keyed by token hash, gated by `IFileAccessTokenService`.

---

## Implementation & Crypto Posture

This section names primitives, parameters, and residual risks. It is the single source of truth for the cryptographic posture; the marketing tagline is at the top of this README.

| Aspect | Implementation | Notes |
|---|---|---|
| Crypto classification | **Classical, not post-quantum.** AES-256-GCM provides quantum-resistant *confidentiality* by key size (Grover's algorithm halves the effective key size to 128 bits, which remains comfortable). There is **no PQ asymmetric layer** — no ML-KEM, no ML-DSA, no asymmetric primitives at all. | This package is intentionally separate from the `PostQuantum.*` family. No PQC migration path is planned for v3.x. See [`SECURITY.md`](SECURITY.md) for the explicit posture. |
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
    "RejectOnRecompressFailure": true,
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
  "FileDownload": {
    "TokenLifetimeMinutes": 15,
    "BindTokensToUser": false
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
| `FileUpload:RejectOnRecompressFailure` | `true` (default, 3.1.0) rejects the upload when the sanitizing re-encode fails — a header that parses but a decode that fails is the shape of a crafted polyglot. Set `false` to restore the pre-3.1.0 store-original-bytes fallback. |
| `FileDownload:TokenLifetimeMinutes` | Lifetime for opaque download tokens issued by `IFileAccessTokenService`. Default 15 minutes; max 24 hours. |
| `FileDownload:BindTokensToUser` | `false` (default). When `true`, download tokens are cryptographically bound to the issuing authenticated user; replay from any other account fails verification. |
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
| `src/FileAccessTokenService.cs` | Opaque, signed, time-limited download tokens backed by ASP.NET Core Data Protection. |
| `src/SecureFileDownloadController.cs` | Reference hardened download surface. Tokenized file reference, `Content-Disposition: attachment`, strict CSP, COOP/COEP/CORP, re-checks resolved path traversal. |
| `src/DependencyInjection/SecureFileUploadServiceCollectionExtensions.cs` | `AddSecureFileUpload()` one-liner DI registration. |
| `src/Utilities/PathHelper.cs` | Canonicalized `IsPathUnderBase` — defeats the `string.StartsWith("/uploads")` prefix-confusion bug. |
| `tests/Fuzz/` | SharpFuzz + AFL++ harness for `FileContentValidator.ValidateAsync`. |
| `tests/SmokeTest/` | Runtime smoke test — Argon2id round-trip, v2 envelope, legacy PBKDF2 fallback, misconfig guard. Executed in CI and runnable locally with `dotnet run --project tests/SmokeTest -c Release`. |

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

- Push to `main` runs library build, solution tests, the runtime smoke harness, pack, and a fuzz-harness build — no publish.
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
