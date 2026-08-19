using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// HEIC/HEIF uploads are rejected with an actionable message rather than the generic
/// "corrupted or malicious" wording.
///
/// HEIC is what iPhones and iPads capture by default, and the files are routinely renamed
/// or shared as .jpg. Reporting that as possible malware is both wrong and harmful: it
/// trains people to ignore the warning in the case that actually matters. The format is
/// still refused — only the explanation changes, and the event is logged at Information
/// rather than as a SECURITY_EVENT so it does not pollute the security signal.
/// </summary>
public sealed class HeicUploadRejectionTests
{
    [Theory]
    [InlineData("heic")]
    [InlineData("heix")]
    [InlineData("mif1")]
    [InlineData("heif")]
    public async Task Heic_disguised_as_jpg_is_rejected_with_conversion_guidance(string brand)
    {
        var result = await UploadAsync(BuildHeifFile(brand), "photo.jpg", "image/jpeg");

        Assert.False(result.Success);
        Assert.Single(result.Errors);

        string error = result.Errors[0];
        Assert.Contains("HEIC", error, StringComparison.OrdinalIgnoreCase);
        // The actionable part: what to do next.
        Assert.Contains("JPG", error, StringComparison.OrdinalIgnoreCase);
        // And it must NOT accuse the user of uploading malware.
        Assert.DoesNotContain("malicious", error, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("corrupted", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Non_heif_ftyp_container_still_gets_the_generic_mismatch_message()
    {
        // "qt  " is a QuickTime movie, not HEIF. It must not be swept into the HEIC branch —
        // that branch exists for a specific, benign compatibility case, not for every ftyp box.
        var result = await UploadAsync(BuildHeifFile("qt  "), "photo.jpg", "image/jpeg");

        Assert.False(result.Success);
        Assert.Single(result.Errors);
        Assert.DoesNotContain("HEIC", result.Errors[0], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// ISO-BMFF header: [4-byte box size]["ftyp"][4-byte major brand], then filler so the
    /// file clears the minimum-size gates ahead of the magic-byte check.
    /// </summary>
    private static byte[] BuildHeifFile(string majorBrand)
    {
        var bytes = new List<byte> { 0x00, 0x00, 0x00, 0x20 };
        bytes.AddRange(Encoding.ASCII.GetBytes("ftyp"));
        bytes.AddRange(Encoding.ASCII.GetBytes(majorBrand));
        bytes.AddRange(Encoding.ASCII.GetBytes("mif1heic"));
        bytes.AddRange(new byte[4096]);
        return bytes.ToArray();
    }

    private static async Task<FileUploadResult> UploadAsync(
        byte[] bytes, string fileName, string contentType)
    {
        string root = Path.Combine(Path.GetTempPath(), "sfu-heic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["FileUpload:StorageRoot"] = root,
                    ["FileUpload:EncryptionEnabled"] = "false",
                    ["FileUpload:RecompressImages"] = "false",
                    ["VirusScan:Enabled"] = "false",
                })
                .Build();

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new HeicStubWebHostEnvironment(root),
                new FileContentValidator(
                    NullLogger<FileContentValidator>.Instance,
                    Options.Create(new FileContentValidatorOptions())),
                new HeicCleanScanService());

            var stream = new MemoryStream(bytes, writable: false);
            IFormFile file = new FormFile(stream, 0, bytes.Length, "file", fileName)
            {
                Headers = new HeaderDictionary(),
                ContentType = contentType,
            };

            return await service.UploadFilesAsync(new FormFileCollection { file }, "Doe", "intake");
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* best effort */ }
        }
    }

    private sealed class HeicStubWebHostEnvironment : IWebHostEnvironment
    {
        public HeicStubWebHostEnvironment(string rootPath)
        {
            ContentRootPath = rootPath;
            WebRootPath = rootPath;
            ContentRootFileProvider = new PhysicalFileProvider(rootPath);
            WebRootFileProvider = new PhysicalFileProvider(rootPath);
        }

        public string ApplicationName { get; set; } = "SecureFileUpload.Core.Tests";
        public IFileProvider ContentRootFileProvider { get; set; }
        public string ContentRootPath { get; set; }
        public string EnvironmentName { get; set; } = "Testing";
        public IFileProvider WebRootFileProvider { get; set; }
        public string WebRootPath { get; set; }
    }

    private sealed class HeicCleanScanService : IVirusScanService
    {
        public string ScannerName => "test-clean";
        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
    }
}
