using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using SharpFuzz;

namespace SecureFileUpload.Fuzz;

/// <summary>
/// AFL/SharpFuzz entry point for FileContentValidator.
///
/// Two modes:
///   1. AFL persistent: `Fuzzer.OutOfProcess.Run(Fuzz)` — stdin loop driven by afl-fuzz.
///      Used when launched from `afl-fuzz -i seeds -o findings -- ./FuzzHarness @@`.
///   2. Single-file replay: `FuzzHarness path/to/crash` — re-runs one input
///      directly. Prints the ContentValidationResult or any exception that
///      escaped, with full .NET stack trace. Used during triage from
///      `findings/default/crashes/` and `findings/default/hangs/`.
///
/// What this harness can find:
///   * Hangs / pathological CPU — AFL flags inputs that exceed `-t` timeout.
///   * Runaway allocation / OOM — AFL flags inputs that exceed `-m` memory cap.
///   * OperationCanceledException leaks — only exception type ValidateAsync
///     re-throws (everything else is caught and converted to RejectStructural).
///   * False-clean results — out of band: re-run known-bad seeds in replay
///     mode and assert the printed Disposition is not `Allowed`.
///
/// What this harness CANNOT find directly:
///   * Logic bugs that produce IsValid=true for malicious input — ValidateAsync
///     swallows internal exceptions, so you must check the returned result.
///     Use replay mode + a curated bad-seed corpus for this class of bug.
/// </summary>
public static class Program
{
    private static readonly FileContentValidator Validator = BuildValidator();

    public static int Main(string[] args)
    {
        if (args.Length == 1 && File.Exists(args[0]))
        {
            // Triage / replay mode — re-run one specific input with full output.
            byte[] bytes = File.ReadAllBytes(args[0]);
            try
            {
                var result = RunOnce(bytes, fileName: Path.GetFileName(args[0]));
                Console.WriteLine(
                    $"Result: IsValid={result.IsValid} Disposition={result.Disposition} " +
                    $"ValidationType={result.ValidationType} Threat={result.ThreatDescription}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"UNHANDLED EXCEPTION (this is a fuzz finding):\n{ex}");
                return 1;
            }
        }

        // Default: AFL out-of-process loop. afl-fuzz feeds inputs over stdin.
        Fuzzer.OutOfProcess.Run(stream =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] bytes = ms.ToArray();

            // ValidateAsync catches all internal exceptions and converts them
            // to a RejectStructural result, so the only exception type that
            // can escape is OperationCanceledException (we don't pass a token,
            // so this should never fire either). We deliberately do NOT wrap
            // RunOnce in a catch — anything that escapes IS a real finding
            // and AFL must record it.
            _ = RunOnce(bytes, fileName: "fuzz.bin");
        });

        return 0;
    }

    private static ContentValidationResult RunOnce(byte[] bytes, string fileName)
    {
        IFormFile file = new FormFile(
            baseStream: new MemoryStream(bytes, writable: false),
            baseStreamOffset: 0,
            length: bytes.Length,
            name: "file",
            fileName: fileName);

        // ValidateAsync is async but never awaits IO that requires a sync ctx —
        // .GetAwaiter().GetResult() is safe and avoids AFL noise from the
        // task scheduler.
        return Validator.ValidateAsync(file).GetAwaiter().GetResult();
    }

    private static FileContentValidator BuildValidator()
    {
        var options = Options.Create(new FileContentValidatorOptions
        {
            // Cap the per-input work to keep the fuzz loop fast. AFL prefers
            // many short executions over a few long ones.
            MaxDeepScanBytes = 2 * 1024 * 1024,
            InspectCompressedPdfStreams = true,
            MaxCompressedStreamsToInspect = 32,
            MaxDecompressedStreamBytes = 4 * 1024 * 1024,
        });

        return new FileContentValidator(NullLogger<FileContentValidator>.Instance, options);
    }
}
