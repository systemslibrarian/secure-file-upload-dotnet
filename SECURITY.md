# SECURITY.md

Crypto classification, AV failure mode, and the explicit non-membership of this package in the `PostQuantum.*` family. Read this before adopting `SecureFileUpload.Core` in regulated, PQ-aware, or high-assurance environments.

---

## Crypto classification

`SecureFileUpload.Core` is a **classical (non-PQC) security library**. It is intentionally and operationally separate from the `PostQuantum.*` family of packages.

| Layer | Primitive | Class | Notes |
|---|---|---|---|
| At-rest payload | **AES-256-GCM** (symmetric AEAD) | Classical | NIST SP 800-38D / RFC 5288. 96-bit nonce, 128-bit auth tag. Quantum-tolerant for confidentiality by key size — Grover's algorithm halves the effective key size to 128 bits, which remains comfortable. |
| KEK derivation (writes) | **Argon2id** (memory-hard KDF) | Classical | RFC 9106 / OWASP 2024+. Defaults `m=64 MiB, t=3, p=4`. No PQC equivalent is applicable — Argon2id is a password-stretching KDF, not an asymmetric primitive. |
| KEK derivation (FIPS opt-in) | **PBKDF2-SHA256** | Classical | OWASP 2024 600 000-iter default. Available via `KeyDerivation:Algorithm = "Pbkdf2"` for FIPS-restricted environments. Also retained as the legacy decrypt-only fallback (600 000 and 210 000 iter). |
| Envelope wrap | **AES-256-GCM** (DEK wrapped under KEK) | Classical | Per-file random 256-bit DEK from `RandomNumberGenerator.Fill`. |
| Asymmetric crypto | **None** | — | No public-key primitives are used anywhere in the package. No key exchange, no signing, no certificate handling. No ML-KEM, no ML-DSA. |

**If your threat model requires post-quantum asymmetric primitives in the at-rest envelope, this is not the package for you.** No PQC migration path is planned for v3.x. The package's roadmap (queued AV, KMS-backed KEK, additional format walkers — see [`docs/hardening-roadmap.md`](docs/hardening-roadmap.md)) does not include PQ migration.

---

## AV failure mode

The virus-scan layer (Layer 7) has two distinct failure modes:

| Scanner outcome | Pipeline behavior | Counted as |
|---|---|---|
| Clean signature result | Accept and save | `ScanCleanCount` |
| Infected signature result | **Always reject** | `InfectedRejectedCount` |
| Scanner unreachable / timeout / exception / unparseable response | Configurable — see below | `ScanNotScannedCount` |

**Detection is always fail-closed.** A clear malware signature always blocks the upload regardless of any configuration.

**Availability is a configured operator choice.** Set `VirusScan:FailClosedOnUnavailable` in `appsettings.json`:

- `false` *(default)*: file is accepted and recorded as `NotScanned`. Matches the original library deployment's posture — a Defender hiccup must not block patrons.
- `true`: scanner unavailability **rejects** the upload with a `scanner unavailable` workflow error.

In **both** modes a `VIRUS_SCAN_SKIPPED` security event is emitted with `Reason=ScannerUnavailable` and `FailClosed={mode}` so operations can alert on the same metric regardless of the policy choice.

The pipeline's other seven layers run identically and do not depend on the scanner being reachable.

---

## Separation from the `PostQuantum.*` family

`SecureFileUpload.Core` is the non-PQC outlier in the broader package portfolio:

- Its threat model is classical-only.
- Its version line (`3.0.x`) is independent of the `PostQuantum.*` coupling and follows its own semver clock.
- It shares no `Foundation` pin, no release-note copy, no shared badge with the PQ packages.
- It is presented separately on profile pages and shared landing surfaces under "ASP.NET security" rather than "Post-quantum."

Adoption decisions for this package should be made on classical-security grounds, not as part of a PQ migration plan.

---

## Reporting

Open a **private GitHub security advisory** at <https://github.com/systemslibrarian/secure-file-upload-dotnet/security/advisories>, not a public issue.

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31
