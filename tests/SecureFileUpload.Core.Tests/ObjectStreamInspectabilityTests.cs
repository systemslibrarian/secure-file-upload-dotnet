using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// PDF object streams are accepted by default (RejectPdfObjectStreams = false) on the
/// stated grounds that their contents are inflated and scanned. That promise silently
/// failed for any object stream the inflater could not read: the scan loop caught the
/// failure and moved on, so the payload inside was never examined and the file was
/// accepted. An attacker did not need to defeat the scanner — only to declare a filter
/// it cannot process.
///
/// Two shapes cause it, and only one of them throws:
///   • a non-Flate filter (LZWDecode, ASCII85Decode, a Crypt filter, …) fails to inflate;
///   • FlateDecode with a non-identity /Predictor inflates successfully and yields
///     predictor-encoded bytes, which are then scanned as meaningless noise.
/// Both are now rejected before inflation is attempted.
///
/// Scope is deliberately narrow: only /Type /ObjStm is gated. Ordinary content streams
/// that fail to inflate are still skipped, because rejecting those would fail large
/// numbers of legitimate documents for no security gain.
/// </summary>
public sealed class ObjectStreamInspectabilityTests
{
    private const string UninspectableValidationType = "PDF-ObjectStreamUninspectable";

    [Theory]
    [InlineData("/Type /ObjStm /N 1 /First 4 /Filter /LZWDecode")]
    [InlineData("/Type /ObjStm /N 1 /First 4 /Filter /ASCII85Decode")]
    [InlineData("/Type /ObjStm /N 1 /First 4 /Filter /Crypt")]
    public async Task Object_stream_with_a_filter_we_cannot_inflate_is_rejected(string dict)
    {
        var result = await Validate(BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))));

        Assert.False(result.IsValid);
        Assert.Equal(UninspectableValidationType, result.ValidationType);
    }

    [Fact]
    public async Task Object_stream_with_flate_and_a_non_identity_predictor_is_rejected()
    {
        // This one INFLATES FINE. Without the pre-inflation gate it sails through and the
        // predictor-encoded output is scanned as noise — the quieter half of the hole.
        string dict = "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>";
        var result = await Validate(BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))));

        Assert.False(result.IsValid);
        Assert.Equal(UninspectableValidationType, result.ValidationType);
    }

    [Fact]
    public async Task Ordinary_flate_object_stream_is_not_rejected_by_this_gate()
    {
        string dict = "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode";
        var result = await Validate(BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))));

        // May still fail other gates; it must not fail THIS one.
        Assert.NotEqual(UninspectableValidationType, result.ValidationType);
    }

    [Fact]
    public async Task Identity_predictor_is_treated_as_inspectable()
    {
        string dict = "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms << /Predictor 1 >>";
        var result = await Validate(BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))));

        Assert.NotEqual(UninspectableValidationType, result.ValidationType);
    }

    [Fact]
    public async Task Non_object_stream_with_an_uninflatable_filter_is_left_alone()
    {
        // Scoping guard: an ordinary content stream with LZWDecode is common enough in old
        // documents that rejecting it would be a false-positive machine. Only ObjStm is gated.
        string dict = "/Length 512 /Filter /LZWDecode";
        var result = await Validate(BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))));

        Assert.NotEqual(UninspectableValidationType, result.ValidationType);
    }

    [Fact]
    public async Task Gate_can_be_disabled_for_producers_that_need_it()
    {
        string dict = "/Type /ObjStm /N 1 /First 4 /Filter /LZWDecode";
        var options = new FileContentValidatorOptions { RejectUninspectableObjectStreams = false };
        var result = await Validate(
            BuildPdf(dict, DeflateCompress(Encoding.ASCII.GetBytes(new string('a', 512)))), options);

        Assert.NotEqual(UninspectableValidationType, result.ValidationType);
    }

    private static byte[] BuildPdf(string dictBody, byte[] streamData)
    {
        string header = $"%PDF-1.5\n1 0 obj\n<< {dictBody} /Length {streamData.Length} >>\nstream\n";
        string footer = "\nendstream\nendobj\ntrailer\n<<>>\n%%EOF\n";

        byte[] h = Encoding.Latin1.GetBytes(header);
        byte[] f = Encoding.Latin1.GetBytes(footer);
        var pdf = new byte[h.Length + streamData.Length + f.Length];
        Buffer.BlockCopy(h, 0, pdf, 0, h.Length);
        Buffer.BlockCopy(streamData, 0, pdf, h.Length, streamData.Length);
        Buffer.BlockCopy(f, 0, pdf, h.Length + streamData.Length, f.Length);
        return pdf;
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

    private static async Task<ContentValidationResult> Validate(
        byte[] pdf, FileContentValidatorOptions? options = null)
    {
        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(options ?? new FileContentValidatorOptions()));

        var stream = new MemoryStream(pdf, writable: false);
        IFormFile file = new FormFile(stream, 0, pdf.Length, "file", "doc.pdf")
        {
            Headers = new HeaderDictionary(),
            ContentType = "application/pdf",
        };

        return await validator.ValidateAsync(file);
    }
}
