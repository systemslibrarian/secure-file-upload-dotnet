# ADR 0001: Encryption at rest stays opt-in through 3.x; default flips in 4.0

- **Status:** Accepted, 2026-10-18
- **Prompted by:** October 2026 audit finding SFU-OCT-003 (`docs/audits/2026-10-16-sfu-oct-2026-audit.md`)
- **Affects:** `FileUpload:EncryptionEnabled` default; `FileUploadService` startup; README posture statements

## Context

`FileUpload:EncryptionEnabled` has defaulted to `false` since the first release. With that
default the write path (`WriteFileToDiskAsync`) stores every accepted file in plaintext under
`StorageRoot`. Envelope encryption (AES-256-GCM, per-file DEK, Argon2id-derived KEK) runs
only when the flag is `true`.

The October 2026 audit flagged this as HIGH in a library whose name and README lead with
encryption. The audit also stated that the README "does NOT claim files never sit
unencrypted on disk." That was wrong: the README's opening paragraph said exactly that. The
documentation overstated the default posture, and that overstatement is the part of the
finding that needed fixing immediately.

Two facts about the code shape the decision below:

1. **The read path already tolerates mixed storage.** `GetDecryptedFileStreamAsync` dispatches
   on the `ENCGCM\0` marker. A file without the marker is served as-is and logged as
   `FILE_DECRYPT_LEGACY`. Turning encryption on in an existing deployment does not make
   existing plaintext files unreadable.
2. **The startup guard is already strict when encryption is on.** `EncryptionEnabled=true` with
   a missing or placeholder `EncryptionSecret` throws at construction. A deployment that
   upgrades into a `true` default without a secret does not start.

## Decision

1. **The default stays `false` for every 3.x release.**
2. **3.4.0 makes the default visible rather than changing it.** The service logs a
   `SECURITY_EVENT | ENCRYPTION_DISABLED` record at Warning level on every start with
   encryption off, naming the resolved storage root and the planned change. The README no
   longer claims files never sit unencrypted on disk. This is disclosure, not remediation: a
   deployment that ignores the warning is exactly as exposed as before.
3. **4.0 flips the default to `true`.** This is recorded in the CHANGELOG as a planned breaking
   change and announced in the 3.x warning text so operators see it before it lands.
4. **Explicit opt-out remains supported in 4.0.** `EncryptionEnabled=false` keeps working and
   keeps producing the warning. The library does not remove the plaintext mode; it stops
   choosing it silently.

## Why not flip the default now

Flipping in a minor release would be the least-effort fix for the finding and the most
disruptive thing this library could do to the people running it.

- **Startup failure on upgrade.** Every existing deployment that never configured a secret
  would fail the startup guard the moment it picked up the new package. The failure is loud
  and safe, but a package-manager update that stops a production intake system is a major
  version event, not a minor one.
- **"Encryption on" would not mean "files encrypted."** Nothing re-encrypts files already on
  disk. After a flip, a store holds plaintext files written before the upgrade and envelope
  files written after, and the read path hides the difference. An operator who sees
  `Encryption: AES-256-GCM` in the startup log would reasonably conclude the store is
  encrypted when a large part of it is not. That belief is worse than knowing the store is
  plaintext.
- **A forced secret turns key loss into data loss.** With encryption on, losing
  `EncryptionSecret` loses every file written under it, permanently; there is no recovery
  path by design. The deployments this library came from are small public-library intake
  systems with volume encryption and backups but no key-management infrastructure. For
  them, plaintext on an encrypted, backed-up volume can be the safer failure mode. Opting in
  must remain a choice the operator makes knowing that trade.
- **Volume encryption underneath is a legitimate posture** for a single-host deployment, and
  the README already recommends it. It is not a substitute against a host-level reader, which
  is why the application layer exists, but it is why a silent default change would harm
  deployments that made a reasoned choice.

## What has to be true before 4.0 ships the flip

1. **A migration story for existing plaintext stores**, either a shipped utility that walks
   `StorageRoot` and rewrites legacy files as v2 envelopes, or a documented, tested
   out-of-band procedure. Without it, condition two above is not met.
2. **A way to see how much legacy plaintext a store still holds**, at minimum a counter or
   metric alongside `FILE_DECRYPT_LEGACY`, so an operator can confirm migration finished.
3. **At least one 3.x release carrying the warning** with the planned change named in its text
   (3.4.0 satisfies this).
4. **A CHANGELOG entry under the 4.0 heading** describing the break, the startup failure
   mode for deployments without a secret, and the opt-out.

If those are not in place when 4.0 is otherwise ready, the flip waits for 4.1 rather than
shipping without them; the warning keeps running either way.

## Consequences

- Operators on the default configuration see one new Warning record per process start from
  3.4.0 onward. Anyone alerting on `SECURITY_EVENT` will page once per start until they either
  enable encryption or accept the configuration. That is intended.
- The README's layer-8 description and crypto-posture section describe encryption as opt-in.
  The marketing-style claim in the opening paragraph is gone.
- `KNOWN-GAPS.md` gains Gap 10 so the "every limitation is named there" promise holds.
