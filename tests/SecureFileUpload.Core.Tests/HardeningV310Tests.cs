using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.Security.Claims;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// Regression tests for the 3.1.0 hardening pass:
///   • Recompress failure fails closed by default (Gap 1 mitigation can no
///     longer be bypassed by a file that parses shallowly but fails full decode),
///     with the legacy fallback still available behind
///     FileUpload:RejectOnRecompressFailure=false.
///   • Attacker-controlled filenames echoed into FileUploadResult.Errors carry
///     no HTML-active characters.
///   • Download tokens optionally bound to the issuing user
///     (FileDownload:BindTokensToUser) — wrong-user replay fails
///     cryptographically, anonymous issuance is refused, and the unbound
///     default remains a drop-in no-op.
/// </summary>
public sealed class HardeningV310Tests
{
    // ── Recompress failure: fail-closed by default ────────────────────────

    [Fact]
    public async Task Image_that_fails_full_decode_is_rejected_by_default()
    {
        // A PNG whose header (IHDR) is valid — passes Image.Identify and the
        // structural chunk walk — but whose IDAT payload is invalid deflate,
        // so the sanitizing full decode in Layer 8 throws. This is exactly the
        // shape of a crafted polyglot; with RejectOnRecompressFailure at its
        // default (true) the upload must be rejected, not stored as-is.
        using var env = new UploadTestEnvironment(new Dictionary<string, string?>
        {
            ["FileUpload:EncryptionEnabled"] = "false",
            ["VirusScan:Enabled"] = "false",
            // RecompressImages and RejectOnRecompressFailure deliberately omitted — defaults.
        });

        byte[] png = BuildPngWithCorruptIdat();
        IFormFile file = MakeFormFile(png, "photo.png", "image/png");

        var result = await env.Service.UploadFilesAsync(
            new FormFileCollection { file }, "Doe", "intake");

        Assert.False(result.Success);
        Assert.Empty(result.UploadedFilePaths);
        Assert.Single(result.Errors);
        Assert.Contains("could not be safely processed", result.Errors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Image_that_fails_full_decode_is_stored_when_fallback_configured()
    {
        // Pre-3.1.0 behavior remains available as an explicit opt-out.
        using var env = new UploadTestEnvironment(new Dictionary<string, string?>
        {
            ["FileUpload:EncryptionEnabled"] = "false",
            ["FileUpload:RejectOnRecompressFailure"] = "false",
            ["VirusScan:Enabled"] = "false",
        });

        byte[] png = BuildPngWithCorruptIdat();
        IFormFile file = MakeFormFile(png, "photo.png", "image/png");

        var result = await env.Service.UploadFilesAsync(
            new FormFileCollection { file }, "Doe", "intake");

        Assert.True(result.Success);
        Assert.Single(result.UploadedFilePaths);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task Healthy_image_still_recompresses_and_uploads()
    {
        // Guard against over-rejection: a genuinely valid image must still pass
        // through the sanitizing re-encode with the new default in place.
        using var env = new UploadTestEnvironment(new Dictionary<string, string?>
        {
            ["FileUpload:EncryptionEnabled"] = "false",
            ["VirusScan:Enabled"] = "false",
        });

        byte[] png = BuildValidPng();
        IFormFile file = MakeFormFile(png, "photo.png", "image/png");

        var result = await env.Service.UploadFilesAsync(
            new FormFileCollection { file }, "Doe", "intake");

        Assert.True(result.Success, string.Join("; ", result.Errors));
        Assert.Single(result.UploadedFilePaths);
    }

    // ── Error messages: HTML-active characters neutralized ────────────────

    [Fact]
    public async Task Rejection_errors_do_not_echo_html_from_attacker_filenames()
    {
        using var env = new UploadTestEnvironment(new Dictionary<string, string?>
        {
            ["FileUpload:EncryptionEnabled"] = "false",
            ["VirusScan:Enabled"] = "false",
        });

        byte[] bytes = Encoding.ASCII.GetBytes("not a real file");
        IFormFile file = MakeFormFile(bytes, "<svg onload=alert(1)>.exe", "application/pdf");

        var result = await env.Service.UploadFilesAsync(
            new FormFileCollection { file }, "Doe", "intake");

        Assert.False(result.Success);
        string error = Assert.Single(result.Errors);
        Assert.DoesNotContain("<", error, StringComparison.Ordinal);
        Assert.DoesNotContain(">", error, StringComparison.Ordinal);
        Assert.DoesNotContain("\"", error, StringComparison.Ordinal);
    }

    // ── Download token user binding ───────────────────────────────────────

    [Fact]
    public void Bound_token_resolves_for_issuing_user_and_fails_for_another()
    {
        var accessor = new HttpContextAccessor();
        var tokenService = CreateBoundTokenService(accessor);

        accessor.HttpContext = ContextForUser("staff-a");
        string storedPath = Path.Combine(V310StubFileUploadService.StorageRootPath, "submission", "doc.pdf");
        string token = tokenService.CreateToken(storedPath);

        // Same user resolves successfully.
        Assert.True(tokenService.TryResolveStoredFilePath(token, out string? resolved));
        Assert.Equal(Path.GetFullPath(storedPath), resolved);

        // A different authenticated user cannot replay the token — the Data
        // Protection purpose chain differs, so unprotect fails cryptographically.
        accessor.HttpContext = ContextForUser("staff-b");
        Assert.False(tokenService.TryResolveStoredFilePath(token, out _));
    }

    [Fact]
    public void Bound_mode_refuses_to_issue_token_for_anonymous_request()
    {
        var accessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext() // unauthenticated principal
        };
        var tokenService = CreateBoundTokenService(accessor);

        string storedPath = Path.Combine(V310StubFileUploadService.StorageRootPath, "submission", "doc.pdf");
        Assert.Throws<InvalidOperationException>(() => tokenService.CreateToken(storedPath));
    }

    [Fact]
    public void Bound_mode_requires_http_context_accessor_at_construction()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileDownload:BindTokensToUser"] = "true",
            })
            .Build();

        Assert.Throws<InvalidOperationException>(() => new FileAccessTokenService(
            NullLogger<FileAccessTokenService>.Instance,
            DataProtectionProvider.Create("SecureFileUpload.Core.Tests.V310"),
            configuration,
            new V310StubFileUploadService()));
    }

    [Fact]
    public void Unbound_default_round_trip_still_works()
    {
        // BindTokensToUser absent → prior behavior, no HttpContext needed.
        var tokenService = new FileAccessTokenService(
            NullLogger<FileAccessTokenService>.Instance,
            DataProtectionProvider.Create("SecureFileUpload.Core.Tests.V310"),
            new ConfigurationBuilder().Build(),
            new V310StubFileUploadService());

        string storedPath = Path.Combine(V310StubFileUploadService.StorageRootPath, "submission", "doc.pdf");
        string token = tokenService.CreateToken(storedPath);

        Assert.True(tokenService.TryResolveStoredFilePath(token, out string? resolved));
        Assert.Equal(Path.GetFullPath(storedPath), resolved);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static FileAccessTokenService CreateBoundTokenService(IHttpContextAccessor accessor)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["FileDownload:BindTokensToUser"] = "true",
            })
            .Build();

        return new FileAccessTokenService(
            NullLogger<FileAccessTokenService>.Instance,
            DataProtectionProvider.Create("SecureFileUpload.Core.Tests.V310"),
            configuration,
            new V310StubFileUploadService(),
            accessor);
    }

    private static DefaultHttpContext ContextForUser(string nameIdentifier) => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity(
            new[] { new Claim(ClaimTypes.NameIdentifier, nameIdentifier) },
            authenticationType: "test"))
    };

    private static IFormFile MakeFormFile(byte[] bytes, string fileName, string contentType) =>
        new FormFile(new MemoryStream(bytes, writable: false), 0, bytes.Length, "file", fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType
        };

    /// <summary>
    /// Builds a PNG whose IHDR is valid (4x4, RGBA8, correct CRC — passes
    /// Image.Identify and the structural chunk walk) but whose IDAT payload is
    /// deliberately invalid deflate (BTYPE=11, reserved), so any full pixel
    /// decode must throw.
    /// </summary>
    private static byte[] BuildPngWithCorruptIdat() =>
        BuildPng(idatData: new byte[] { 0x78, 0x9C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });

    /// <summary>
    /// Builds a minimal fully valid 4x4 RGBA PNG (zlib "stored" blocks carrying
    /// filter-byte-prefixed scanlines) that both identifies and decodes cleanly.
    /// </summary>
    private static byte[] BuildValidPng()
    {
        // Raw PNG scanline data: 4 rows × (1 filter byte + 4 px × 4 bytes) = 68 bytes.
        byte[] raw = new byte[4 * (1 + 4 * 4)];
        for (int i = 0; i < raw.Length; i++)
            raw[i] = 0; // filter 0 + black transparent pixels

        // Wrap in a zlib stream using a single stored (uncompressed) deflate block.
        using var zlib = new MemoryStream();
        zlib.WriteByte(0x78); zlib.WriteByte(0x01);            // zlib header (no preset dict)
        zlib.WriteByte(0x01);                                   // BFINAL=1, BTYPE=00 (stored)
        zlib.WriteByte((byte)(raw.Length & 0xFF));              // LEN (little-endian)
        zlib.WriteByte((byte)(raw.Length >> 8));
        zlib.WriteByte((byte)(~raw.Length & 0xFF));             // NLEN = ~LEN
        zlib.WriteByte((byte)((~raw.Length >> 8) & 0xFF));
        zlib.Write(raw);
        uint adler = Adler32(raw);
        zlib.WriteByte((byte)(adler >> 24)); zlib.WriteByte((byte)(adler >> 16));
        zlib.WriteByte((byte)(adler >> 8));  zlib.WriteByte((byte)adler);

        return BuildPng(idatData: zlib.ToArray());
    }

    private static byte[] BuildPng(byte[] idatData)
    {
        using var ms = new MemoryStream();
        ms.Write(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A });

        // IHDR: width=4, height=4, bit depth 8, color type 6 (RGBA).
        byte[] ihdr =
        {
            0x00, 0x00, 0x00, 0x04,   // width
            0x00, 0x00, 0x00, 0x04,   // height
            0x08,                     // bit depth
            0x06,                     // color type RGBA
            0x00, 0x00, 0x00          // compression / filter / interlace
        };
        WriteChunk(ms, "IHDR", ihdr);
        WriteChunk(ms, "IDAT", idatData);
        WriteChunk(ms, "IEND", Array.Empty<byte>());
        return ms.ToArray();
    }

    private static void WriteChunk(MemoryStream ms, string type, byte[] data)
    {
        Span<byte> len = stackalloc byte[4];
        len[0] = (byte)(data.Length >> 24); len[1] = (byte)(data.Length >> 16);
        len[2] = (byte)(data.Length >> 8);  len[3] = (byte)data.Length;
        ms.Write(len);

        byte[] typeBytes = Encoding.ASCII.GetBytes(type);
        ms.Write(typeBytes);
        ms.Write(data);

        uint crc = Crc32(typeBytes, data);
        Span<byte> crcBytes = stackalloc byte[4];
        crcBytes[0] = (byte)(crc >> 24); crcBytes[1] = (byte)(crc >> 16);
        crcBytes[2] = (byte)(crc >> 8);  crcBytes[3] = (byte)crc;
        ms.Write(crcBytes);
    }

    private static uint Crc32(byte[] first, byte[] second)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte[] part in new[] { first, second })
        {
            foreach (byte b in part)
            {
                crc ^= b;
                for (int i = 0; i < 8; i++)
                    crc = (crc >> 1) ^ (0xEDB88320 & (uint)(-(crc & 1)));
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    private static uint Adler32(byte[] data)
    {
        const uint Mod = 65521;
        uint a = 1, b = 0;
        foreach (byte d in data)
        {
            a = (a + d) % Mod;
            b = (b + a) % Mod;
        }
        return (b << 16) | a;
    }

    // ── Test infrastructure ───────────────────────────────────────────────

    /// <summary>
    /// Disposable scaffold that stands up a FileUploadService against a temp
    /// storage root and tears the directories down afterwards.
    /// </summary>
    private sealed class UploadTestEnvironment : IDisposable
    {
        private readonly string _workRoot;

        public FileUploadService Service { get; }

        public UploadTestEnvironment(Dictionary<string, string?> settings)
        {
            _workRoot = Path.Combine(Path.GetTempPath(), "sfu-tests-" + Guid.NewGuid().ToString("N"));
            string contentRoot = Path.Combine(_workRoot, "content");
            string webRoot = Path.Combine(contentRoot, "wwwroot");
            string storageRoot = Path.Combine(_workRoot, "uploads");
            Directory.CreateDirectory(webRoot);
            Directory.CreateDirectory(storageRoot);

            settings["FileUpload:StorageRoot"] = storageRoot;

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(settings)
                .Build();

            var validator = new FileContentValidator(
                NullLogger<FileContentValidator>.Instance,
                Options.Create(new FileContentValidatorOptions()));

            Service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new V310StubWebHostEnvironment(contentRoot, webRoot),
                validator,
                new V310NeverCalledScanService());
        }

        public void Dispose()
        {
            try { Directory.Delete(_workRoot, recursive: true); } catch { }
        }
    }

    private sealed class V310StubFileUploadService : IFileUploadService
    {
        public static string StorageRootPath => Path.Combine(Path.GetTempPath(), "sfu-v310-token-tests");

        public string StorageRoot => StorageRootPath;

        public Task<(Stream? Stream, string ContentType)> GetDecryptedFileStreamAsync(string filePath) =>
            Task.FromResult<(Stream? Stream, string ContentType)>((null, "application/octet-stream"));

        public bool IsValidFileType(IFormFile file) => true;

        public Task<FileUploadResult> UploadFilesAsync(IFormFileCollection files, string lastName, string formType) =>
            Task.FromResult(new FileUploadResult());

        public (bool IsValid, string? ErrorMessage) ValidateFile(IFormFile file) => (true, null);
    }

    private sealed class V310NeverCalledScanService : IVirusScanService
    {
        public string ScannerName => "test-disabled";

        public Task<bool> IsHealthyAsync() => Task.FromResult(true);

        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            throw new InvalidOperationException("Scanner must not be invoked when VirusScan:Enabled=false.");

        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            throw new InvalidOperationException("Scanner must not be invoked when VirusScan:Enabled=false.");
    }

    private sealed class V310StubWebHostEnvironment : IWebHostEnvironment
    {
        public V310StubWebHostEnvironment(string contentRootPath, string webRootPath)
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
}
