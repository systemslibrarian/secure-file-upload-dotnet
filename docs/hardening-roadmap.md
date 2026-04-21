# Hardening Roadmap

## What Would Make This the Strongest Realistic File Upload App

This document is the answer to the question: *"You've already done the obvious things. What's left?"*

The 8-layer pipeline already covers nearly every public OWASP-class file-upload threat. After the Gap 1 / 2 / 4 / 6 / 8 fixes, the remaining improvements are mostly **operational, architectural, or defence-in-depth** — not single bugs to patch in a controller.

Items are grouped by how much they raise the bar versus how much they cost.

---

## Tier 1 — Highest Impact, Low–Medium Cost (do these first)

### 1.1 Move the master KEK to a real Key Management Service

Today the master KEK is derived from `EncryptionSecret` via PBKDF2-SHA256 (600k iterations). That secret lives in app config / environment variables. If the host is compromised, the secret is exposed and *every* wrapped DEK can be unwrapped.

**Recommendation:** Replace the local PBKDF2 derivation with a managed KMS:

- **Azure Key Vault** — wrap/unwrap DEKs via `KeyClient` (`WrapKey` / `UnwrapKey`). The KEK never leaves the HSM.
- **AWS KMS** — `Encrypt` / `Decrypt` API on a customer-managed key. Same property: KEK never leaves AWS HSM.
- **HashiCorp Vault Transit** engine — same model, on-prem option.
- **PKCS#11 HSM** for regulated environments (FIPS 140-2 Level 3).

The envelope-encryption format (v2) was designed for exactly this — only `TryUnwrapDek` needs to change. The on-disk file format does not.

### 1.2 Bot / abuse defence at the edge

Layer 7's per-file scan can take 10–30 seconds. An unauthenticated attacker can exhaust scanner capacity with a few hundred concurrent submissions. ASP.NET Core rate limiting helps but is L7 in-process.

**Recommendation:**

1. Put **Cloudflare Turnstile** or **reCAPTCHA v3** on the submit form (invisible, no friction).
2. Add an **edge WAF** (Cloudflare, Azure Front Door, AWS WAF) with:
   - Per-IP rate limits on `POST /upload` (e.g. 10 req/min/IP).
   - Geographic / ASN deny-list if your audience is local.
   - Bot Management to block known scraper / scanner ASNs.
3. Require an **authenticated session** for upload endpoints whenever the use case allows.

### 1.3 Asynchronous virus scan with quarantine

Right now scanning is synchronous and blocking. A clamd outage or a very large file slows everyone.

**Recommendation:** Move Layer 7 off the request path:

1. Accept the file synchronously through Layers 1–6 + Layer 8 write to a **`pending/` quarantine folder** (still encrypted, still outside wwwroot).
2. Enqueue a job (Azure Storage Queue, AWS SQS, RabbitMQ, or `IHostedService` + `Channel<T>`) to scan the file.
3. The worker runs ClamAV / Defender, then **moves** the file to `released/` on clean or `infected/` on a hit.
4. Staff UI only lists `released/`. Patron sees an immediate "received — pending review" response.

Net effect: scanner load is decoupled from concurrent uploads, and a slow scanner can never DoS the form.

### 1.4 Content Security Policy for any UI that displays uploads

Even though files are stored encrypted and outside wwwroot, a future change might add a viewer or thumbnail endpoint. Pre-emptively lock down:

```http
Content-Security-Policy: default-src 'none'; img-src 'self'; object-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="..."   ← for any download endpoint
```

Plus serve PDFs with `Content-Type: application/pdf` **and** `Content-Disposition: attachment` so the browser never tries to render PDF JavaScript inline.

### 1.5 Per-tenant / per-user storage isolation

If this is multi-tenant or multi-staff: store each tenant's uploads under a tenant-scoped subfolder, and check `IsPathUnderBase(filePath, tenantRoot)` on retrieval too — not just on write. Already enforced on write; ensure the read path checks too.

---

## Tier 2 — Strong Defence-in-Depth (high value at modest cost)

### 2.1 Run AV in two engines

ClamAV signatures and Microsoft Defender signatures overlap heavily but not completely. A file judged "clean" by both is meaningfully stronger evidence than one engine alone.

**Recommendation:** Implement an `IVirusScanService` aggregator that calls both `ClamAvScanService` and `WindowsDefenderScanService`. Reject if **either** returns a hit.

### 2.2 PDF rasterisation as the canonical stored form

For deployments where the visual content of the PDF matters but the structure does not (e.g. proof-of-address documents that a human will view):

1. Render every page to PNG (e.g. via `PDFtoImage`, `Ghostscript`, or `Aspose.PDF`).
2. Store the page images. **Discard the original PDF entirely.**
3. The "PDF" the staff downloads is a fresh PDF rebuilt from the rasterised pages — it carries no original PDF objects, so JavaScript / Launch / EmbeddedFile cannot survive even if Layer 6 missed something.

This is the strongest possible PDF-borne-malware defence. Cost: rendering CPU + loss of OCR-able text.

### 2.3 Sandboxed analysis workers

Run ClamAV, ImageSharp recompression, and any future PDF-rendering inside containers / VMs with:

- No outbound network (`--network none` / NetworkPolicy: deny-all).
- Read-only root filesystem (`--read-only`).
- `seccomp` / AppArmor profiles restricted to file read/write + AV daemon socket.
- Non-root user (`USER 1000`).
- Memory + CPU caps.

A zero-day in ImageSharp or ClamAV becomes contained — it cannot exfiltrate, escalate, or persist.

### 2.4 Per-DEK Additional Authenticated Data (AAD)

The current envelope-encryption (v2) doesn't use AAD when wrapping the DEK. Binding the AAD to the on-disk file path (or a stable file ID) prevents an attacker who can swap encrypted blobs on disk from making one file decrypt as another's content.

**Recommendation:** In `WriteEnvelopeEncryptedAsync`, pass an AAD = `UTF8(submissionId + "|" + storedFileName)` to **both** GCM operations. In `DecryptV2Envelope`, pass the same AAD reconstructed from the file path. Old v1/v2 files without AAD remain readable; new writes get the binding.

### 2.5 Detect and reject duplicate / replayed uploads

Add a SHA-256 of the **plaintext** (computed in memory before encryption) and store it alongside the file metadata. On upload, reject if the same hash already exists for the same patron within N days. Cheap defence against:

- Repeated submission used to enumerate validation rules.
- Re-uploading a file that was previously flagged after deletion.

### 2.6 Filesystem-level encryption underneath app encryption

Belt and suspenders. The app's AES-256-GCM protects the file contents; LUKS / BitLocker / EBS encryption protects:

- Temp files written by the OS (page file, swap, dump files).
- Filesystem metadata (filenames, sizes, timestamps).
- Defragmentation / journal blocks that the app cannot zero.

Mitigates Gap 7 (SSD secure-delete on COW filesystems).

---

## Tier 3 — Maximum Paranoia (regulated / high-value targets)

### 3.1 Detached air-gapped scan farm

For ID documents, medical records, or anything subject to GLBA / HIPAA / PCI:

1. Web tier accepts uploads, encrypts them with the patron-tier KEK, writes to a one-way drop folder.
2. A separate, **outbound-only-internet** scanning farm pulls the encrypted files, decrypts, scans with multiple AV engines + commercial sandbox detonation (e.g. Joe Sandbox, Cuckoo), re-encrypts under the staff-tier KEK.
3. Staff tier decrypts only with its own KEK. Compromising the web tier does not give the attacker readable patron content.

### 3.2 Detonation chamber for PDFs

Any PDF flagged by Layer 6's pattern scan as "suspicious but not blocked" gets queued for execution in a real-PDF-reader sandbox (Adobe Reader in a stripped Windows VM with a network sinkhole). If the sandbox observes any network connection attempt, file write outside the temp dir, or process spawn, the file is reclassified as malicious and blocked.

Commercial: `JoeSandbox`, `Hybrid Analysis`, `VMRay`.
Open source: `Cuckoo Sandbox`.

### 3.3 Cryptographic transparency log

Append every upload event (timestamp, patron ID, file SHA-256, KEK version, scan result) to a tamper-evident log (Sigstore Rekor, AWS QLDB, or a homegrown Merkle tree with periodic root publication). Any later modification or deletion of a stored file becomes detectable.

### 3.4 mTLS between web tier and scan / storage tier

Mutual TLS with short-lived certificates from a private CA between every internal hop. Even if the web tier is compromised, the attacker cannot directly call the storage decryption service without a valid client certificate signed by the internal CA.

### 3.5 Hardware-backed signing of decisions

Sign each `ContentValidationResult` with an HSM-resident key. The viewer endpoint refuses to display any file whose stored decision record fails signature verification. Rules out an attacker who gains write access to the validation result store from "approving" a previously rejected file.

---

## Operational Practices (free, just discipline)

- **Dependency updates:** ImageSharp, ClamAV, .NET runtime — all on a 30-day SLA for security patches.
- **Threat-feed-driven signature refresh:** `freshclam --daemon` for ClamAV; Defender auto-update for Windows.
- **Fuzzing:** Run AFL++ / `SharpFuzz` against `FileContentValidator.ValidateAsync` with a corpus seeded from real PDFs / JPEGs and from public exploit samples (Offensive Security's PoC-in-GitHub, etc.).
- **Red-team drill quarterly:** Hand a contractor the README and ask them to bypass the pipeline. Pay for the bug, fix it, regression-test it.
- **SBOM + provenance:** Build with `dotnet publish --use-current-runtime`, generate SBOM (`dotnet sbom-tool`), sign with `cosign`, verify on deploy.
- **Backup + immutable storage:** Encrypted off-site backups to object storage with object-lock / compliance-mode retention. Ransomware cannot delete what it cannot mutate.
- **Staff-side controls:** The viewer interface is itself an attack surface. Force MFA, short session timeouts, audit every download, watermark visible PII when displayed.

---

## What's Still Hard Even After All of This

No file-upload system can fully defend against:

- **Insider with a valid session** uploading something they shouldn't (this is an authorisation problem, not a content-validation problem).
- **A zero-day in ImageSharp / ClamAV / .NET** itself. Defence: sandboxed workers (Tier 2.3), rapid patching, multi-engine scanning.
- **Social engineering that bypasses the form entirely** (e.g. phishing staff into accepting a file via email). Defence: organisational, not technical.
- **A KEK exfiltration via memory dump on the running process.** Defence: KMS/HSM (Tier 1.1) so the KEK is never in process memory.

The pipeline as it stands, plus Tier 1 of this roadmap, is at or above what you would find in commercial document-acceptance platforms. Tier 2 puts you ahead of most of them. Tier 3 is regulated-industry territory.
