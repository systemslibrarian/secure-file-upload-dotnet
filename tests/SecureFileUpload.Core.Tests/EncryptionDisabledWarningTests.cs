using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.Collections.Concurrent;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// Guards the startup warning that fires when <c>FileUpload:EncryptionEnabled</c> is
/// false. That is the default, so this is the path almost every deployment is on; a
/// warning that silently stops firing would leave plaintext storage invisible again.
///
/// The tests run the real constructor with a capturing logger and assert on the log
/// level explicitly: a record emitted at Information instead of Warning is filtered
/// out by most production logging configurations, which would make the warning
/// decorative.
/// </summary>
public sealed class EncryptionDisabledWarningTests
{
    private const string Marker = "SECURITY_EVENT | ENCRYPTION_DISABLED";

    [Fact]
    public void Encryption_disabled_explicitly_emits_one_warning_naming_the_storage_root()
    {
        using var env = new WarningTestEnvironment();
        var logger = new CapturingLogger();

        var service = env.CreateService(logger, new Dictionary<string, string?>
        {
            ["FileUpload:StorageRoot"] = env.StorageRoot,
            ["FileUpload:EncryptionEnabled"] = "false",
        });

        var record = Assert.Single(logger.Records, r => r.Message.Contains(Marker, StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.False(string.IsNullOrWhiteSpace(service.StorageRoot));
        Assert.Contains(service.StorageRoot, record.Message, StringComparison.Ordinal);
        Assert.Contains("PLAINTEXT", record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Encryption_disabled_by_default_with_no_storage_root_configured_emits_warning_naming_the_resolved_root()
    {
        // The out-of-the-box configuration: neither EncryptionEnabled nor StorageRoot set.
        // The storage root is resolved and created before the warning runs, so the
        // message must name the real fallback path, not an empty or null value.
        using var env = new WarningTestEnvironment();
        var logger = new CapturingLogger();

        var service = env.CreateService(logger, new Dictionary<string, string?>());

        var expectedRoot = Path.GetFullPath(Path.Combine(env.ContentRoot, "UploadedFiles"));
        Assert.Equal(expectedRoot, service.StorageRoot);
        Assert.True(Directory.Exists(expectedRoot), "storage root should already exist when the warning fires");

        var record = Assert.Single(logger.Records, r => r.Message.Contains(Marker, StringComparison.Ordinal));
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Contains("under " + expectedRoot, record.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Encryption_enabled_does_not_emit_the_warning()
    {
        using var env = new WarningTestEnvironment();
        var logger = new CapturingLogger();

        env.CreateService(logger, new Dictionary<string, string?>
        {
            ["FileUpload:StorageRoot"] = env.StorageRoot,
            ["FileUpload:EncryptionEnabled"] = "true",
            ["FileUpload:EncryptionSecret"] = "unit-test-secret-that-is-long-enough-0123456789",
            // Keep the Argon2id derivation cheap; the KDF parameters are not under test here.
            ["FileUpload:KeyDerivation:Argon2id:MemoryKiB"] = "8192",
            ["FileUpload:KeyDerivation:Argon2id:Iterations"] = "1",
            ["FileUpload:KeyDerivation:Argon2id:Parallelism"] = "1",
        });

        // Initialization reached the end of the constructor (otherwise it would have thrown),
        // and no ENCRYPTION_DISABLED record was produced at any level.
        Assert.Contains(logger.Records, r => r.Message.Contains("FileUploadService initialized", StringComparison.Ordinal));
        Assert.DoesNotContain(logger.Records, r => r.Message.Contains(Marker, StringComparison.Ordinal));
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private sealed record LogRecord(LogLevel Level, string Message);

    private sealed class CapturingLogger : ILogger<FileUploadService>
    {
        public ConcurrentQueue<LogRecord> Records { get; } = new();

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NoopScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Records.Enqueue(new LogRecord(logLevel, formatter(state, exception)));
        }

        private sealed class NoopScope : IDisposable
        {
            public static readonly NoopScope Instance = new();
            public void Dispose() { }
        }
    }

    private sealed class WarningTestEnvironment : IDisposable
    {
        private readonly string _workRoot;

        public WarningTestEnvironment()
        {
            _workRoot = Path.Combine(Path.GetTempPath(), "sfu-encwarn-" + Guid.NewGuid().ToString("N"));
            ContentRoot = Path.Combine(_workRoot, "content");
            WebRoot = Path.Combine(ContentRoot, "wwwroot");
            StorageRoot = Path.Combine(_workRoot, "uploads");
            Directory.CreateDirectory(WebRoot);
            Directory.CreateDirectory(StorageRoot);
        }

        public string ContentRoot { get; }
        public string WebRoot { get; }
        public string StorageRoot { get; }

        public FileUploadService CreateService(ILogger<FileUploadService> logger, Dictionary<string, string?> settings)
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            return new FileUploadService(
                logger,
                configuration,
                new WarningStubWebHostEnvironment(ContentRoot, WebRoot),
                validator,
                new WarningCleanScanService());
        }

        public void Dispose()
        {
            try { Directory.Delete(_workRoot, recursive: true); } catch { }
        }
    }

    private sealed class WarningStubWebHostEnvironment : IWebHostEnvironment
    {
        public WarningStubWebHostEnvironment(string contentRootPath, string webRootPath)
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

    private sealed class WarningCleanScanService : IVirusScanService
    {
        public string ScannerName => "test-clean";
        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
    }
}
