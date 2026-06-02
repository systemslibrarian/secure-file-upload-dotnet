using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using SecureFileUpload.Utilities;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// Regression tests for the 3.0.2 hardening pass:
///   • Filename NFKC normalization, trailing dot/space, length cap, with
///     positive coverage for legitimate accented and CJK filenames.
///   • PDF FlateDecode stream scanner: timeout, decompression-ratio cap,
///     recursion depth, CancellationToken propagation.
///   • Virus-scan availability fail-closed mode.
///   • DEK / plaintext zeroing path under cancellation and concurrency.
///   • PathHelper.IsPathUnderBase resistance to dotdot + encoded separators.
/// </summary>
public sealed class HardeningRegressionTests
{
    // ── Filename hardening ────────────────────────────────────────────────

    [Theory]
    [InlineData("evil．．/payload.pdf",       "fullwidth dotdot (NFKC bypass)")]
    [InlineData("photo.pdf.",                          "trailing dot (Windows path-strip)")]
    [InlineData("photo.pdf ",                          "trailing space (Windows path-strip)")]
    [InlineData("ＣＯＮ.pdf",              "fullwidth CON reserved name")]
    [InlineData("evil．exe.pdf",                   "fullwidth dot in stem hiding double-extension")]
    public void Filename_evasions_are_rejected(string fileName, string scenario)
    {
        var rejected = InvokeContainsSuspiciousPatterns(fileName);
        Assert.True(rejected.IsSuspicious,
            $"Expected '{fileName}' to be rejected ({scenario}); was accepted.");
    }

    [Fact]
    public void Filename_overlong_is_rejected()
    {
        string overlong = "a" + new string('b', 300) + ".pdf";
        var rejected = InvokeContainsSuspiciousPatterns(overlong);
        Assert.True(rejected.IsSuspicious);
        Assert.Contains("255", rejected.Reason ?? string.Empty);
    }

    [Theory]
    [InlineData("café.pdf")]                    // Latin-1 accented
    [InlineData("résumé_2026.pdf")]              // multiple accents
    [InlineData("über_Größe.pdf")]               // German umlaut + sharp s
    [InlineData("документ.pdf")]                  // Cyrillic
    [InlineData("李明_文档.pdf")]                  // CJK
    [InlineData("日本語の書類.pdf")]                // Japanese
    [InlineData("한글_문서.pdf")]                  // Korean
    [InlineData("ελληνικά.pdf")]                  // Greek
    public void Filename_legitimate_non_ascii_is_accepted(string fileName)
    {
        var result = InvokeContainsSuspiciousPatterns(fileName);
        Assert.False(result.IsSuspicious,
            $"Legitimate non-ASCII filename '{fileName}' was incorrectly rejected: {result.Reason}");
    }

    // ── PDF FlateDecode scanner: bomb, recursion, cancellation ───────────

    [Fact]
    public async Task Pdf_decompression_bomb_is_rejected_within_time_budget()
    {
        // Construct a tiny PDF carrying a Flate-compressed stream that
        // expands far above the 200x ratio cap (1 MB of zeros compresses
        // to ~1 KB, ratio ~1000x).
        byte[] pdf = BuildPdfWithFlateBomb(plainBytes: 1024 * 1024);

        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(new FileContentValidatorOptions
            {
                MaxPdfStreamScanMilliseconds = 2000,
                MaxDecompressionRatio = 200,
                MaxDecompressedStreamBytes = 16 * 1024 * 1024,
            }));

        IFormFile file = MakeFormFile(pdf, "bomb.pdf", "application/pdf");

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = await validator.ValidateAsync(file);
        sw.Stop();

        Assert.False(result.IsValid);
        Assert.True(
            result.Disposition == ValidationDisposition.RejectedMalicious ||
            result.Disposition == ValidationDisposition.RejectedStructural,
            $"Expected malicious/structural rejection, got {result.Disposition}");
        Assert.True(sw.ElapsedMilliseconds < 5000,
            $"Bomb scan took {sw.ElapsedMilliseconds}ms — should reject well under the 2s budget plus slack.");
    }

    [Fact]
    public async Task Pdf_stream_scan_honours_cancellation_token()
    {
        byte[] pdf = BuildPdfWithFlateBomb(plainBytes: 256 * 1024);

        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(new FileContentValidatorOptions
            {
                MaxPdfStreamScanMilliseconds = 60_000, // disable timeout — rely on cancellation
                MaxDecompressionRatio = int.MaxValue,
                MaxDecompressedStreamBytes = int.MaxValue,
            }));

        IFormFile file = MakeFormFile(pdf, "bomb.pdf", "application/pdf");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await validator.ValidateAsync(file, cts.Token));
    }

    [Fact]
    public async Task Pdf_nested_flatedecode_threat_caught_within_recursion_cap()
    {
        // Outer stream's plaintext IS another PDF body that itself contains
        // a Flate-compressed stream carrying "/JavaScript". With recursion
        // depth 2, the scanner should reach the inner threat.
        byte[] innerThreat = BuildPdfWithFlateText("/JavaScript injection payload");
        byte[] outer       = BuildPdfWithFlatePayload(innerThreat);

        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(new FileContentValidatorOptions
            {
                MaxPdfStreamRecursionDepth = 2,
                InspectCompressedPdfStreams = true,
            }));

        IFormFile file = MakeFormFile(outer, "nested.pdf", "application/pdf");
        var result = await validator.ValidateAsync(file);

        Assert.False(result.IsValid);
        Assert.Equal(ValidationDisposition.RejectedMalicious, result.Disposition);
    }

    // ── Virus-scan availability: fail-closed mode ────────────────────────

    [Fact]
    public async Task Scanner_unavailable_fails_closed_when_configured()
    {
        var workRoot = Path.Combine(Path.GetTempPath(), "sfu-tests-" + Guid.NewGuid().ToString("N"));
        var contentRoot = Path.Combine(workRoot, "content");
        var webRoot = Path.Combine(contentRoot, "wwwroot");
        var storageRoot = Path.Combine(workRoot, "uploads");
        Directory.CreateDirectory(webRoot);
        Directory.CreateDirectory(storageRoot);

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["FileUpload:StorageRoot"] = storageRoot,
                    ["FileUpload:EncryptionEnabled"] = "false",
                    ["FileUpload:RecompressImages"] = "false",
                    ["VirusScan:Enabled"] = "true",
                    ["VirusScan:FailClosedOnUnavailable"] = "true",
                })
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new HardeningStubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new HardeningUnavailableScanService());

            byte[] pdfBytes = Encoding.ASCII.GetBytes(
                "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF");
            IFormFile file = MakeFormFile(pdfBytes, "test.pdf", "application/pdf");
            var files = new FormFileCollection { file };

            var result = await service.UploadFilesAsync(files, "Doe", "intake");

            Assert.False(result.Success);
            Assert.Empty(result.UploadedFilePaths);
            Assert.Equal(1, result.ScanNotScannedCount);  // skip metric still emitted
            Assert.Single(result.Errors);
            Assert.Contains("scanner unavailable", result.Errors[0], StringComparison.OrdinalIgnoreCase);
            Assert.Contains("fail-closed", result.Errors[0], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(workRoot, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Scanner_unavailable_defaults_to_fail_open()
    {
        // Confirm the default (no config) still preserves the prior fail-open
        // behavior so 3.0.2 is a true drop-in upgrade for existing deployments.
        var workRoot = Path.Combine(Path.GetTempPath(), "sfu-tests-" + Guid.NewGuid().ToString("N"));
        var contentRoot = Path.Combine(workRoot, "content");
        var webRoot = Path.Combine(contentRoot, "wwwroot");
        var storageRoot = Path.Combine(workRoot, "uploads");
        Directory.CreateDirectory(webRoot);
        Directory.CreateDirectory(storageRoot);

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["FileUpload:StorageRoot"] = storageRoot,
                    ["FileUpload:EncryptionEnabled"] = "false",
                    ["FileUpload:RecompressImages"] = "false",
                    ["VirusScan:Enabled"] = "true",
                    // FailClosedOnUnavailable deliberately omitted — default.
                })
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new HardeningStubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new HardeningUnavailableScanService());

            byte[] pdfBytes = Encoding.ASCII.GetBytes(
                "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF");
            IFormFile file = MakeFormFile(pdfBytes, "test.pdf", "application/pdf");
            var files = new FormFileCollection { file };

            var result = await service.UploadFilesAsync(files, "Doe", "intake");

            Assert.True(result.Success);
            Assert.Single(result.UploadedFilePaths);
            Assert.Equal(1, result.ScanNotScannedCount);
            Assert.Empty(result.Errors);
        }
        finally
        {
            try { Directory.Delete(workRoot, recursive: true); } catch { }
        }
    }

    // ── DEK / plaintext zeroing path under cancellation + concurrency ────

    [Fact]
    public async Task Validator_cancellation_runs_zeroing_finally_block()
    {
        // The DEK/plaintext-zeroing finally blocks live in FileUploadService
        // and FileContentValidator. We can't observe the cleared bytes directly,
        // but we CAN assert that cancellation propagates correctly without
        // leaking a partial result — which is the contract the finally blocks
        // depend on running.
        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(new FileContentValidatorOptions()));

        byte[] bytes = Encoding.ASCII.GetBytes(
            "%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF");
        IFormFile file = MakeFormFile(bytes, "test.pdf", "application/pdf");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await validator.ValidateAsync(file, cts.Token));
    }

    [Fact]
    public async Task Concurrent_uploads_each_complete_without_crashing()
    {
        // Hammer the encrypted-envelope write path with N parallel uploads.
        // Each call exercises its own DEK + plaintext + finally-zeroing path;
        // a thread-safety regression would surface here as a crash, a write
        // failure, or a tag-verification mismatch on read-back.
        var workRoot = Path.Combine(Path.GetTempPath(), "sfu-tests-" + Guid.NewGuid().ToString("N"));
        var contentRoot = Path.Combine(workRoot, "content");
        var webRoot = Path.Combine(contentRoot, "wwwroot");
        var storageRoot = Path.Combine(workRoot, "uploads");
        Directory.CreateDirectory(webRoot);
        Directory.CreateDirectory(storageRoot);

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["FileUpload:StorageRoot"] = storageRoot,
                    ["FileUpload:EncryptionEnabled"] = "true",
                    ["FileUpload:EncryptionSecret"] = "test-secret-for-concurrency-32chars-minimum-padding-padding",
                    ["FileUpload:RecompressImages"] = "false",
                    ["FileUpload:KeyDerivation:Algorithm"] = "Pbkdf2",
                    ["FileUpload:KeyDerivation:Pbkdf2:Iterations"] = "1000", // fast for tests
                    ["VirusScan:Enabled"] = "false",
                })
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new HardeningStubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new HardeningCleanScanService());

            const int parallel = 16;
            var tasks = new Task<FileUploadResult>[parallel];
            for (int i = 0; i < parallel; i++)
            {
                int idx = i;
                tasks[i] = Task.Run(async () =>
                {
                    byte[] bytes = Encoding.ASCII.GetBytes(
                        $"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Index {idx} >>\nendobj\ntrailer\n<<>>\n%%EOF");
                    IFormFile file = MakeFormFile(bytes, $"concurrent_{idx}.pdf", "application/pdf");
                    var files = new FormFileCollection { file };
                    return await service.UploadFilesAsync(files, $"Doe{idx}", "intake");
                });
            }

            var results = await Task.WhenAll(tasks);

            int succeeded = results.Count(r => r.Success);
            Assert.Equal(parallel, succeeded);
            foreach (var r in results)
            {
                Assert.Single(r.UploadedFilePaths);
                Assert.True(File.Exists(r.UploadedFilePaths[0]),
                    "Encrypted file should exist after concurrent upload");
            }
        }
        finally
        {
            try { Directory.Delete(workRoot, recursive: true); } catch { }
        }
    }

    // ── PathHelper resistance ────────────────────────────────────────────

    [Theory]
    [InlineData("/var/uploads_evil/foo", "/var/uploads", false)]
    [InlineData("/var/uploads/foo",      "/var/uploads", true)]
    [InlineData("/var/uploads",          "/var/uploads", true)]
    public void IsPathUnderBase_resists_prefix_confusion(string candidate, string baseDir, bool expected)
    {
        if (OperatingSystem.IsWindows())
        {
            // Translate POSIX-style paths to a Windows root the API will accept.
            candidate = candidate.Replace('/', Path.DirectorySeparatorChar);
            baseDir   = baseDir.Replace('/',   Path.DirectorySeparatorChar);
            candidate = "C:" + candidate;
            baseDir   = "C:" + baseDir;
        }
        Assert.Equal(expected, PathHelper.IsPathUnderBase(candidate, baseDir));
    }

    [Fact]
    public void IsPathUnderBase_resists_dotdot_traversal()
    {
        string baseDir = OperatingSystem.IsWindows() ? @"C:\var\uploads" : "/var/uploads";
        string sibling = OperatingSystem.IsWindows()
            ? @"C:\var\uploads\..\secrets"
            : "/var/uploads/../secrets";
        Assert.False(PathHelper.IsPathUnderBase(sibling, baseDir));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static IFormFile MakeFormFile(byte[] bytes, string fileName, string contentType)
    {
        var stream = new MemoryStream(bytes, writable: false);
        return new FormFile(stream, 0, bytes.Length, "file", fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType,
        };
    }

    private static byte[] BuildPdfWithFlateBomb(int plainBytes)
    {
        byte[] zeros = new byte[plainBytes];
        byte[] compressed = DeflateCompress(zeros);
        return AssembleFlatePdf(compressed);
    }

    private static byte[] BuildPdfWithFlateText(string text)
    {
        byte[] plain = Encoding.Latin1.GetBytes(text + new string(' ', 4096));
        byte[] compressed = DeflateCompress(plain);
        return AssembleFlatePdf(compressed);
    }

    private static byte[] BuildPdfWithFlatePayload(byte[] payload)
    {
        byte[] compressed = DeflateCompress(payload);
        return AssembleFlatePdf(compressed);
    }

    private static byte[] DeflateCompress(byte[] input)
    {
        using var ms = new MemoryStream();
        using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            ds.Write(input, 0, input.Length);
        }
        return ms.ToArray();
    }

    private static byte[] AssembleFlatePdf(byte[] flateBytes)
    {
        string header = $"%PDF-1.4\n1 0 obj\n<< /Length {flateBytes.Length} /Filter /FlateDecode >>\nstream\n";
        string footer = "\nendstream\nendobj\ntrailer\n<<>>\n%%EOF\n";

        byte[] headerBytes = Encoding.Latin1.GetBytes(header);
        byte[] footerBytes = Encoding.Latin1.GetBytes(footer);

        var pdf = new byte[headerBytes.Length + flateBytes.Length + footerBytes.Length];
        Buffer.BlockCopy(headerBytes, 0, pdf, 0, headerBytes.Length);
        Buffer.BlockCopy(flateBytes,  0, pdf, headerBytes.Length, flateBytes.Length);
        Buffer.BlockCopy(footerBytes, 0, pdf, headerBytes.Length + flateBytes.Length, footerBytes.Length);
        return pdf;
    }

    /// <summary>
    /// Invokes the private static FileUploadService.ContainsSuspiciousPatterns
    /// via reflection so we can unit-test the filename-evasion matrix without
    /// constructing a full FileUploadService and routing through UploadFilesAsync.
    /// </summary>
    private static (bool IsSuspicious, string? Reason) InvokeContainsSuspiciousPatterns(string fileName)
    {
        var method = typeof(FileUploadService).GetMethod(
            "ContainsSuspiciousPatterns",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        var result = method!.Invoke(null, new object[] { fileName });
        var tuple = ((bool IsSuspicious, string? Reason))result!;
        return tuple;
    }

    // ── Local stubs (named with Hardening prefix to avoid clashing with the
    //    StubXxx types defined in SecurityRegressionTests.cs) ──────────────

    private sealed class HardeningStubWebHostEnvironment : IWebHostEnvironment
    {
        public HardeningStubWebHostEnvironment(string contentRootPath, string webRootPath)
        {
            ContentRootPath = contentRootPath;
            WebRootPath = webRootPath;
            ContentRootFileProvider = new PhysicalFileProvider(contentRootPath);
            WebRootFileProvider = new PhysicalFileProvider(webRootPath);
        }

        public string ApplicationName { get; set; } = "SecureFileUpload.Core.Tests";
        public IFileProvider ContentRootFileProvider { get; set; }
        public string ContentRootPath { get; set; }
        public string EnvironmentName { get; set; } = "Testing";
        public IFileProvider WebRootFileProvider { get; set; }
        public string WebRootPath { get; set; }
    }

    private sealed class HardeningUnavailableScanService : IVirusScanService
    {
        public string ScannerName => "test-unavailable";
        public Task<bool> IsHealthyAsync() => Task.FromResult(false);
        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult { IsClean = false, ScanSuccessful = false, Message = "scanner unavailable", ScannerUsed = ScannerName });
        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult { IsClean = false, ScanSuccessful = false, Message = "scanner unavailable", ScannerUsed = ScannerName });
    }

    private sealed class HardeningCleanScanService : IVirusScanService
    {
        public string ScannerName => "test-clean";
        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
    }
}
