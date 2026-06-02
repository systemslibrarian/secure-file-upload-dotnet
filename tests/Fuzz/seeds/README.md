# tests/Fuzz/seeds/

Curated **bad-input** corpus for the `FileContentValidator` fuzz harness.

## Convention

Every binary file in this directory is a known-malicious or adversarial input
that the validator **must reject**. When `FuzzHarness path/to/seed` is invoked
in triage mode and the input lives under any `/seeds/` directory, an
`Allowed` disposition exits with code `1` — i.e. **a seed that passes is a
fuzz finding**. See `tests/Fuzz/Program.cs`.

## Suggested categories (add as `.bin` files)

| Filename prefix | What it should trigger |
|---|---|
| `polyglot_jpeg_php_tail_*.bin`        | Embedded shell rejected by JPEG threat scan |
| `pdf_decompression_bomb_*.bin`        | `PDF-DecompressionBomb` rejection within time budget |
| `pdf_nested_flatedecode_*.bin`        | Nested-stream walk catches inner threat |
| `pdf_js_in_compressed_stream_*.bin`   | `PDF-CompressedStreamThreat` JS trigger |
| `pdf_launch_obfuscated_*.bin`         | `PDF-DangerousPattern` `/Launch` |
| `png_idat_oversized_*.bin`            | Structural rejection (chunk layout) |
| `webp_appended_zip_*.bin`             | Embedded container rejected |
| `bmp_dib_size_overflow_*.bin`         | Structural rejection (DIB header size) |

## Workflow

1. Generate or hand-craft a seed.
2. Drop it here.
3. Run `dotnet run --project tests/Fuzz -c Release -- ./tests/Fuzz/seeds/your_seed.bin`.
4. Confirm the validator rejected it (exit code 0, `Disposition` non-`Allowed`).
5. If the seed ever starts passing again, AFL/CI will exit non-zero — that is
   the regression signal.

For AFL/SharpFuzz persistent runs, point `afl-fuzz -i ./tests/Fuzz/seeds`
at this directory and `-o` at a sibling `findings/` directory.

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."*
> — 1 Corinthians 10:31
