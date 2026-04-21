# Fuzzing the Deep Content Validator

A coverage-guided fuzz harness for `FileContentValidator.ValidateAsync` using
[SharpFuzz](https://github.com/Metalnem/sharpfuzz) on top of [AFL++](https://aflplus.plus/).

The goal is **not** to find crashes in malicious files (we want those rejected).
The goal is to find inputs that make the validator:

1. **Hang or run unbounded** — DoS surface. AFL flags any input that exceeds
   the `-t` per-execution timeout.
2. **Allocate unbounded memory** — DoS surface. AFL flags any input that
   exceeds the `-m` memory cap (run with `-m 512` or similar).
3. **Leak an `OperationCanceledException`** out of `ValidateAsync` — the only
   exception type the validator re-throws. We don't pass a cancellation token,
   so this should never fire; if AFL records it, that's a real bug.
4. **Return `IsValid = true` for a known-malicious input class** in the seed
   corpus. ⚠️ AFL alone cannot detect this: `ValidateAsync` catches every
   internal exception and converts it to `RejectStructural`. To find this
   class of bug, replay each crash file in single-file mode (see Triage
   below) and assert the printed `Disposition` is not `Allowed`.

Anything in those four categories is a real bug.

---

## Layout

```
tests/Fuzz/
├── FuzzHarness.csproj      ← console exe wired to SharpFuzz
├── Program.cs              ← entry point: feeds AFL one file at a time
├── seeds/                  ← starter corpus (real JPEGs, PNGs, WebPs, PDFs)
│   ├── valid-photo.jpg
│   ├── valid-doc.pdf
│   ├── eicar-in-jpg.jpg
│   └── …
└── README.md               ← (this file)
```

---

## Setup (one-time)

```bash
# 1. AFL++
sudo apt-get install afl++

# 2. SharpFuzz CLI
dotnet tool install --global SharpFuzz.CommandLine

# 3. Restore + publish the harness as a self-contained binary
cd tests/Fuzz
dotnet publish -c Release -o publish

# 4. Instrument the validator's containing assembly with SharpFuzz
sharpfuzz publish/SecureFileUpload.dll
```

> The instrumentation step rewrites IL in the published `SecureFileUpload.dll`
> to emit AFL coverage edges. Re-run it after any code change to the validator.

---

## Running

```bash
# From tests/Fuzz/
afl-fuzz -i seeds -o findings -- ./publish/FuzzHarness @@
```

AFL writes any crash that escaped the harness's `try/catch` to
`findings/default/crashes/`. Anything in there is a bug — the validator must
either return a `ContentValidationResult` or fail closed via a *known*
exception type that the upload service handles. Unhandled exceptions are not
acceptable.

Hangs land in `findings/default/hangs/`. Same standard: every input must
complete within `MaxDeepScanBytes` worth of work.

---

## Seed corpus guidance

A good seed corpus accelerates AFL by orders of magnitude. Include:

- **One small valid file per supported format** (`.jpg`, `.png`, `.webp`, `.pdf`).
- **The EICAR test string wrapped in each format** (validates the full pipeline path).
- **Public PoC samples**: minimal known-bad JPEGs / PDFs from
  [Offensive Security's PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub),
  [Didier Stevens' PDF tools](https://blog.didierstevens.com/programs/pdf-tools/)
  test files, etc.
- **Truncated valid files** (first 16 bytes, first 64 bytes, first half) — catches
  bounds-check bugs at every offset.
- **A single all-zero file and a single all-0xFF file** — boundary inputs.

Keep each seed under 64 KB. AFL prefers many small inputs over a few large ones.

---

## Triage workflow

```bash
# Re-run a specific crashing input under the harness with .NET exception output:
./publish/FuzzHarness findings/default/crashes/id:000001*

# If it reproduces, write a unit test pinning the input as a regression case
# and fix the root cause in FileContentValidator.cs.
```

---

## Why this is in the repo

The validator is the highest-leverage piece of code in the entire pipeline —
it's the one place that walks attacker-controlled bytes deeply enough to be
plausibly buggy. Fuzzing the dispatcher and the format-specific walkers
(JPEG segment walker, PNG chunk walker, WebP RIFF tree walker, PDF
`ScanCompressedPdfStreams`) is the single most effective way to gain
confidence that no crafted input flips the failure mode from "rejected"
to "exception".
