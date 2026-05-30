using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Xunit;

namespace SecureFileUpload.Core.Tests;

public sealed class SecurityRegressionTests
{
    [Fact]
    public async Task Download_requires_authenticated_user_by_default()
    {
        using var host = await CreateDownloadHostAsync();
        using var client = host.GetTestClient();
        var tokenService = host.Services.GetRequiredService<IFileAccessTokenService>();
        string fileToken = tokenService.CreateToken(Path.Combine(StubFileUploadService.StorageRootPath, "submission", "test.pdf"));

        using var response = await client.GetAsync($"/staff/files/download?fileToken={Uri.EscapeDataString(fileToken)}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Download_returns_attachment_for_authenticated_user()
    {
        using var host = await CreateDownloadHostAsync();
        using var client = host.GetTestClient();
        var tokenService = host.Services.GetRequiredService<IFileAccessTokenService>();
        string fileToken = tokenService.CreateToken(Path.Combine(StubFileUploadService.StorageRootPath, "submission", "test.pdf"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(TestAuthHandler.SchemeName);

        using var response = await client.GetAsync($"/staff/files/download?fileToken={Uri.EscapeDataString(fileToken)}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/octet-stream", response.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(response.Content.Headers.ContentDisposition);
        Assert.Equal("attachment", response.Content.Headers.ContentDisposition?.DispositionType);
        Assert.Equal("secure pdf payload", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Download_rejects_invalid_or_tampered_token()
    {
        using var host = await CreateDownloadHostAsync();
        using var client = host.GetTestClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(TestAuthHandler.SchemeName);

        using var response = await client.GetAsync("/staff/files/download?fileToken=definitely-not-valid");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_accepts_validated_file_as_not_scanned_when_scanner_fails()
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
                })
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new StubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new UnavailableVirusScanService());

            var bytes = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF");
            IFormFile file = new FormFile(new MemoryStream(bytes, writable: false), 0, bytes.Length, "file", "test.pdf")
            {
                Headers = new HeaderDictionary(),
                ContentType = "application/pdf"
            };

            var files = new FormFileCollection { file };

            var result = await service.UploadFilesAsync(files, "Doe", "intake");

            Assert.True(result.Success);
            Assert.Single(result.UploadedFilePaths);
            Assert.Single(result.UploadedFilePaths, File.Exists);
            Assert.Equal(1, result.ScanNotScannedCount);
            Assert.Equal(0, result.ScanCleanCount);
            Assert.Equal(0, result.InfectedRejectedCount);
            Assert.Empty(result.Errors);
        }
        finally
        {
            try
            {
                Directory.Delete(workRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task Upload_rejects_infected_file_when_scanner_finds_threat()
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
                })
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new StubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new InfectedVirusScanService());

            var bytes = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF");
            IFormFile file = new FormFile(new MemoryStream(bytes, writable: false), 0, bytes.Length, "file", "test.pdf")
            {
                Headers = new HeaderDictionary(),
                ContentType = "application/pdf"
            };

            var files = new FormFileCollection { file };

            var result = await service.UploadFilesAsync(files, "Doe", "intake");

            Assert.False(result.Success);
            Assert.Empty(result.UploadedFilePaths);
            Assert.Equal(0, result.ScanNotScannedCount);
            Assert.Equal(0, result.ScanCleanCount);
            Assert.Equal(1, result.InfectedRejectedCount);
            Assert.Single(result.Errors);
            Assert.Contains("File rejected.", result.Errors[0], StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                Directory.Delete(workRoot, recursive: true);
            }
            catch
            {
            }
        }
    }

    [Fact]
    public void File_token_service_rejects_paths_outside_storage_root()
    {
        var dataProtectionProvider = DataProtectionProvider.Create("SecureFileUpload.Core.Tests");

        var configuration = new ConfigurationBuilder().Build();
        var tokenService = new FileAccessTokenService(
            NullLogger<FileAccessTokenService>.Instance,
            dataProtectionProvider,
            configuration,
            new StubFileUploadService());

        string outsidePath = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "outside.pdf"));

        Assert.Throws<InvalidOperationException>(() => tokenService.CreateToken(outsidePath));
    }

    [Fact]
    public async Task Clamav_unavailable_log_states_not_scanned_instead_of_rejected()
    {
        var sink = new TestLogSink();
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(new TestLoggerProvider(sink)));

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VirusScan:ClamAv:Host"] = "missing-clamd.invalid",
                ["VirusScan:ClamAv:Port"] = "1",
                ["VirusScan:ClamAv:TimeoutSeconds"] = "1",
            })
            .Build();

        var service = new ClamAvScanService(loggerFactory.CreateLogger<ClamAvScanService>(), configuration);
        await service.ScanStreamAsync(new MemoryStream(Encoding.ASCII.GetBytes("pdf bytes")), "test.pdf");

        string message = Assert.Single(sink.Messages, m => m.Contains("CLAMAV_UNAVAILABLE", StringComparison.Ordinal));
        Assert.Contains("accepted as NotScanned", message, StringComparison.Ordinal);
        Assert.DoesNotContain("REJECTED (fail-closed)", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Defender_startup_log_states_not_scanned_instead_of_rejected()
    {
        var sink = new TestLogSink();
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(new TestLoggerProvider(sink)));

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["VirusScan:WindowsDefender:MpCmdRunPath"] = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "MpCmdRun.exe"),
                ["VirusScan:WindowsDefender:TempScanPath"] = Path.Combine(Path.GetTempPath(), "sfu-defender-" + Guid.NewGuid().ToString("N")),
            })
            .Build();

        _ = new WindowsDefenderScanService(loggerFactory.CreateLogger<WindowsDefenderScanService>(), configuration);

        string message = Assert.Single(sink.Messages, m => m.Contains("Windows Defender scanner NOT available", StringComparison.Ordinal));
        Assert.Contains("accepted as NotScanned", message, StringComparison.Ordinal);
        Assert.DoesNotContain("Scans will be rejected", message, StringComparison.Ordinal);
    }

    private static async Task<IHost> CreateDownloadHostAsync()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder.UseTestServer();
                webBuilder.ConfigureServices(services =>
                {
                    services
                        .AddAuthentication(TestAuthHandler.SchemeName)
                        .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });

                    services.AddAuthorization();
                    services.AddDataProtection();
                    services.AddSingleton<IFileUploadService>(new StubFileUploadService());
                    services.AddSingleton<IFileAccessTokenService, FileAccessTokenService>();
                    services.AddControllers().AddApplicationPart(typeof(SecureFileDownloadController).Assembly);
                });

                webBuilder.Configure(app =>
                {
                    app.UseRouting();
                    app.UseAuthentication();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints => endpoints.MapControllers());
                });
            })
            .StartAsync();

        return host;
    }

    private sealed class StubFileUploadService : IFileUploadService
    {
        public static string StorageRootPath => Path.Combine(Path.GetTempPath(), "secure-file-upload-tests");

        public string StorageRoot => StorageRootPath;

        public Task<(Stream? Stream, string ContentType)> GetDecryptedFileStreamAsync(string filePath)
        {
            Stream stream = new MemoryStream(Encoding.UTF8.GetBytes("secure pdf payload"));
            return Task.FromResult<(Stream? Stream, string ContentType)>((stream, "application/pdf"));
        }

        public bool IsValidFileType(IFormFile file) => true;

        public Task<FileUploadResult> UploadFilesAsync(IFormFileCollection files, string lastName, string formType) =>
            Task.FromResult(new FileUploadResult { Success = true });

        public (bool IsValid, string? ErrorMessage) ValidateFile(IFormFile file) => (true, null);
    }

    private sealed class UnavailableVirusScanService : IVirusScanService
    {
        public string ScannerName => "test-unavailable";

        public Task<bool> IsHealthyAsync() => Task.FromResult(false);

        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult
            {
                IsClean = false,
                ScanSuccessful = false,
                Message = "scanner unavailable",
                ScannerUsed = ScannerName
            });

        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult
            {
                IsClean = false,
                ScanSuccessful = false,
                Message = "scanner unavailable",
                ScannerUsed = ScannerName
            });
    }

    private sealed class InfectedVirusScanService : IVirusScanService
    {
        public string ScannerName => "test-infected";

        public Task<bool> IsHealthyAsync() => Task.FromResult(true);

        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult
            {
                IsClean = false,
                ScanSuccessful = true,
                ThreatName = "Unit.Test.Eicar",
                Message = "Threat detected",
                ScannerUsed = ScannerName
            });

        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult
            {
                IsClean = false,
                ScanSuccessful = true,
                ThreatName = "Unit.Test.Eicar",
                Message = "Threat detected",
                ScannerUsed = ScannerName
            });
    }

    private sealed class StubWebHostEnvironment : IWebHostEnvironment
    {
        public StubWebHostEnvironment(string contentRootPath, string webRootPath)
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

    private sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public const string SchemeName = "Test";

        public TestAuthHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder)
            : base(options, logger, encoder)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (Request.Headers.Authorization.Count == 0)
                return Task.FromResult(AuthenticateResult.NoResult());

            var identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Name, "staff-user") },
                SchemeName);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }

    private sealed class TestLogSink
    {
        public ConcurrentQueue<string> Messages { get; } = new();
    }

    private sealed class TestLoggerProvider : ILoggerProvider
    {
        private readonly TestLogSink _sink;

        public TestLoggerProvider(TestLogSink sink)
        {
            _sink = sink;
        }

        public ILogger CreateLogger(string categoryName) => new TestLogger(_sink);

        public void Dispose()
        {
        }
    }

    private sealed class TestLogger : ILogger
    {
        private readonly TestLogSink _sink;

        public TestLogger(TestLogSink sink)
        {
            _sink = sink;
        }

        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _sink.Messages.Enqueue(formatter(state, exception));
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}