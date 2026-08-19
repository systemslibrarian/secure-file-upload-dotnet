using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// The sanitizing re-encode decodes every accepted image, and its only bound was the deep
/// validator's MaxImagePixels — 300,000,000 by default. That is a structural sanity limit,
/// not a memory limit: at roughly 4 bytes per pixel a 300 MP image is a ~1.2 GB bitmap, and
/// a PNG declaring those dimensions compresses to a few hundred kilobytes. One upload could
/// therefore cost a gigabyte of RAM, and nothing bounded how many ran at once.
///
/// The caps are enforced from Image.Identify — headers only — so an over-cap file is refused
/// before any pixels are materialized. That ordering is the point: the bomb is cheap to send
/// and expensive to decode, so the check has to land on the cheap side.
///
/// These tests drive the gate by LOWERING the cap rather than building a real over-cap image:
/// allocating a genuine 32 MP bitmap to prove a memory guard works risks the very exhaustion
/// it guards against, and CI runners are small.
/// </summary>
public sealed class ImageDecodeCapTests
{
    [Fact]
    public async Task Png_above_the_non_jpeg_decode_cap_is_refused()
    {
        var result = await UploadAsync(
            SmallPng(), "scan.png", "image/png",
            extraConfig: new() { ["FileUpload:MaxNonJpegDecodePixels"] = "100" });

        Assert.False(result.Success);
        Assert.Single(result.Errors);
        Assert.Contains("could not be safely processed", result.Errors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Png_within_the_default_cap_is_accepted()
    {
        var result = await UploadAsync(SmallPng(), "scan.png", "image/png");

        Assert.True(result.Success, result.Errors.Count > 0 ? result.Errors[0] : "no error reported");
        Assert.Single(result.UploadedFilePaths);
    }

    [Fact]
    public async Task Jpeg_uses_its_own_higher_cap_not_the_non_jpeg_one()
    {
        // The non-JPEG cap is set below the image's size; the JPEG cap is not. A JPEG must be
        // judged by the JPEG cap — otherwise legitimate high-resolution phone photos, which
        // are exactly the files this package exists to accept, would be refused.
        var result = await UploadAsync(
            SmallJpeg(), "photo.jpg", "image/jpeg",
            extraConfig: new()
            {
                ["FileUpload:MaxNonJpegDecodePixels"] = "100",
                ["FileUpload:MaxReencodeDecodePixels"] = "10000000",
            });

        Assert.True(result.Success, result.Errors.Count > 0 ? result.Errors[0] : "no error reported");
    }

    [Fact]
    public async Task Over_cap_respects_RejectOnRecompressFailure_when_it_is_disabled()
    {
        // An over-cap image is the same situation RejectOnRecompressFailure governs: we
        // cannot sanitize it. With the flag off the operator has asked for the original to
        // be stored rather than the upload refused. The memory bound still holds either way,
        // because no decode happens in either branch — the flag only decides storage.
        var result = await UploadAsync(
            SmallPng(), "scan.png", "image/png",
            extraConfig: new()
            {
                ["FileUpload:MaxNonJpegDecodePixels"] = "100",
                ["FileUpload:RejectOnRecompressFailure"] = "false",
            });

        Assert.True(result.Success, result.Errors.Count > 0 ? result.Errors[0] : "no error reported");
        Assert.Single(result.UploadedFilePaths);
    }

    [Fact]
    public async Task Animated_png_is_declined_before_decoding()
    {
        // A pixel cap read from the canvas does not bound a multi-frame decode: Image.LoadAsync
        // materializes every frame, so peak memory is canvas x frames. A modest canvas with a
        // hundred frames sits under the cap and still decodes to gigabytes. Detection is from
        // the acTL container chunk, so no decode happens to find out.
        var result = await UploadAsync(ApngBytes(), "anim.png", "image/png");

        Assert.False(result.Success);
        Assert.Single(result.Errors);
        Assert.Contains("could not be safely processed", result.Errors[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Still_png_is_not_mistaken_for_an_animation()
    {
        // Guard against the detection firing on ordinary PNGs — that would reject most uploads.
        var result = await UploadAsync(SmallPng(), "still.png", "image/png");

        Assert.True(result.Success, result.Errors.Count > 0 ? result.Errors[0] : "no error reported");
    }

    /// <summary>
    /// A still PNG with an acTL animation-control chunk spliced in ahead of IDAT — the marker
    /// that makes a PNG an APNG.
    /// </summary>
    private static byte[] ApngBytes()
    {
        byte[] png = SmallPng();
        int idat = IndexOf(png, "IDAT");
        Assert.True(idat > 0, "test PNG has no IDAT chunk");

        // Chunk layout: 4-byte length, 4-byte type, data, 4-byte CRC. The validator and the
        // detector both read structure, not CRCs, so a structurally-placed chunk suffices.
        var actl = new List<byte> { 0, 0, 0, 8 };
        actl.AddRange(Encoding.ASCII.GetBytes("acTL"));
        actl.AddRange(new byte[] { 0, 0, 0, 100, 0, 0, 0, 0 });   // 100 frames, infinite loops
        actl.AddRange(new byte[] { 0, 0, 0, 0 });                  // CRC placeholder

        int insertAt = idat - 4;   // before IDAT's length field
        var outBytes = new List<byte>(png.Length + actl.Count);
        outBytes.AddRange(png[..insertAt]);
        outBytes.AddRange(actl);
        outBytes.AddRange(png[insertAt..]);
        return outBytes.ToArray();
    }

    private static int IndexOf(byte[] haystack, string needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != (byte)needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static byte[] SmallPng()
    {
        using var image = new Image<Rgba32>(50, 50);
        using var ms = new MemoryStream();
        image.SaveAsPng(ms);
        return ms.ToArray();
    }

    private static byte[] SmallJpeg()
    {
        using var image = new Image<Rgba32>(50, 50);
        using var ms = new MemoryStream();
        image.SaveAsJpeg(ms);
        return ms.ToArray();
    }

    private static async Task<FileUploadResult> UploadAsync(
        byte[] bytes, string fileName, string contentType,
        Dictionary<string, string?>? extraConfig = null)
    {
        // StorageRoot must NOT sit under wwwroot — the service refuses that outright, since
        // uploads under the web root would be directly servable. Mirror the real layout:
        // content/wwwroot for the host, a sibling "uploads" directory for storage.
        string workRoot = Path.Combine(Path.GetTempPath(), "sfu-cap-" + Guid.NewGuid().ToString("N"));
        string contentRoot = Path.Combine(workRoot, "content");
        string webRoot = Path.Combine(contentRoot, "wwwroot");
        string root = Path.Combine(workRoot, "uploads");
        Directory.CreateDirectory(webRoot);
        Directory.CreateDirectory(root);
        try
        {
            var settings = new Dictionary<string, string?>
            {
                ["FileUpload:StorageRoot"] = root,
                ["FileUpload:EncryptionEnabled"] = "false",
                ["FileUpload:RecompressImages"] = "true",
                ["VirusScan:Enabled"] = "false",
            };
            if (extraConfig is not null)
            {
                foreach (var kv in extraConfig) settings[kv.Key] = kv.Value;
            }

            var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

            var service = new FileUploadService(
                NullLogger<FileUploadService>.Instance,
                configuration,
                new CapStubWebHostEnvironment(contentRoot, webRoot),
                new FileContentValidator(
                    NullLogger<FileContentValidator>.Instance,
                    Options.Create(new FileContentValidatorOptions())),
                new CapCleanScanService());

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
            try { Directory.Delete(workRoot, recursive: true); } catch { /* best effort */ }
        }
    }

    private sealed class CapStubWebHostEnvironment : IWebHostEnvironment
    {
        public CapStubWebHostEnvironment(string contentRootPath, string webRootPath)
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

    private sealed class CapCleanScanService : IVirusScanService
    {
        public string ScannerName => "test-clean";
        public Task<bool> IsHealthyAsync() => Task.FromResult(true);
        public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
        public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
            Task.FromResult(new VirusScanResult { IsClean = true, ScanSuccessful = true, Message = "clean", ScannerUsed = ScannerName });
    }
}
