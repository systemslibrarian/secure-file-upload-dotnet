using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.IO.Compression;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// PDF object streams are accepted by default on the stated grounds that their contents are
/// inflated and scanned. The gate enforcing that promise is written against the OUTCOME —
/// were the contents actually read? — rather than against the dictionary's declaration.
///
/// The first version of this gate trusted the declaration and was bypassable four ways, all
/// covered below: declare /FlateDecode over bytes that are not deflate; park decoy streams
/// ahead of the payload to exhaust the scan budget; omit /Filter entirely; or pad the
/// dictionary past the lookback window. Each returns "not uninspectable" under a
/// declaration-trusting check while leaving the payload unread.
/// </summary>
public sealed class ObjectStreamInspectabilityTests
{
    private const string Uninspectable = "PDF-ObjectStreamUninspectable";

    // ── Declared-filter cases ────────────────────────────────────────────────
    [Theory]
    [InlineData("/Filter /LZWDecode")]
    [InlineData("/Filter /ASCII85Decode")]
    [InlineData("/Filter /Crypt")]
    [InlineData("/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 4 >>")]
    public async Task Object_stream_we_cannot_read_is_rejected(string filter)
    {
        var result = await Validate(BuildPdf($"/Type /ObjStm /N 1 /First 4 {filter}", Deflate(Filler())));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Indirect_DecodeParms_cannot_hide_a_predictor()
    {
        // "/DecodeParms 99 0 R" puts the predictor in another object. Resolving it means
        // walking the object graph, so an unresolvable DecodeParms counts as unreadable
        // rather than being waved through because the literal text "/Predictor" is absent.
        var result = await Validate(BuildPdf(
            "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms 99 0 R", Deflate(Filler())));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    // ── Outcome cases: the declaration looks fine, the bytes do not cooperate ──
    [Fact]
    public async Task Declaring_FlateDecode_over_bytes_that_do_not_inflate_is_rejected()
    {
        // The cheapest bypass of a declaration-trusting gate: claim the filter we CAN read,
        // then supply bytes we cannot. Inflation throws, and skipping on that leaves the
        // payload unexamined while the file is accepted.
        // 0xFF bytes: the low three bits give BFINAL=1, BTYPE=11, which is the reserved
        // block type, so the inflater rejects this immediately. Also not zlib-framed.
        var notDeflate = new byte[600];
        Array.Fill(notDeflate, (byte)0xFF);
        var result = await Validate(BuildPdf("/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", notDeflate));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Decoy_streams_cannot_starve_the_object_stream_scan()
    {
        // MaxCompressedStreamsToInspect defaults to 64. Sharing one budget let an attacker
        // park 64 tiny valid streams ahead of the payload so the loop broke before the object
        // stream was reached. Object streams now get their own pass, ahead of the queue.
        var sb = new StringBuilder("%PDF-1.5\n");
        byte[] decoy = Deflate(Encoding.ASCII.GetBytes("harmless"));
        for (int i = 0; i < 80; i++)
        {
            sb.Append($"{i + 1} 0 obj\n<< /Length {decoy.Length} /Filter /FlateDecode >>\nstream\n");
            sb.Append(Encoding.Latin1.GetString(decoy));
            sb.Append("\nendstream\nendobj\n");
        }
        byte[] payload = Deflate(Filler());
        sb.Append($"999 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /LZWDecode /Length {payload.Length} >>\nstream\n");
        sb.Append(Encoding.Latin1.GetString(payload));
        sb.Append("\nendstream\nendobj\ntrailer\n<<>>\n%%EOF\n");

        var result = await Validate(Encoding.Latin1.GetBytes(sb.ToString()));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Unfiltered_object_stream_contents_are_actually_read()
    {
        // No /Filter means the payload is stored literally. Attempting deflate on it throws,
        // so a gate that only watches inflation would report "unreadable" while a gate that
        // waves through "no filter declared" would never look. The bytes ARE the content and
        // must be scanned — this one hides a /Launch action in plain sight.
        byte[] literal = Encoding.ASCII.GetBytes(
            "1 0 2 40 << /Type /Action /S /Launch /F (calc.exe) >> " + new string(' ', 400));
        var result = await Validate(BuildPdf("/Type /ObjStm /N 2 /First 20", literal));

        Assert.False(result.IsValid);
        Assert.NotEqual("PDF-DeepScan", result.ValidationType);
    }

    [Fact]
    public async Task Padding_the_dictionary_past_the_lookback_window_does_not_disarm_the_gate()
    {
        // If the dictionary cannot be located, the stream is treated strictly rather than as
        // ordinary — otherwise adding filler to a dictionary would switch the gate off, and
        // the source ships with the package so the window size is not a secret.
        string padding = new string('P', 70_000);
        var result = await Validate(BuildPdf(
            $"/Type /ObjStm /N 1 /First 4 /Filter /LZWDecode /Producer ({padding})", Deflate(Filler())));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Angle_brackets_inside_a_literal_string_do_not_confuse_the_dictionary_reader()
    {
        // ">>" inside /Title would mis-pair a raw backwards brace scan, either disarming the
        // gate or attributing a neighbouring object's dictionary. Reading from the surface
        // with strings already blanked makes that impossible.
        var result = await Validate(BuildPdf(
            "/Type /ObjStm /N 1 /First 4 /Title (a>>b) /Filter /LZWDecode", Deflate(Filler())));

        Assert.False(result.IsValid);
        Assert.Equal(Uninspectable, result.ValidationType);
    }

    // ── Negative cases: the gate must not fire on ordinary documents ─────────
    [Fact]
    public async Task Ordinary_flate_object_stream_passes()
    {
        var result = await Validate(BuildPdf("/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", Deflate(Filler())));

        Assert.NotEqual(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Identity_predictor_passes()
    {
        var result = await Validate(BuildPdf(
            "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /DecodeParms << /Predictor 1 >>", Deflate(Filler())));

        Assert.NotEqual(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Non_object_stream_with_an_uninflatable_filter_is_left_alone()
    {
        // Scoping guard. DCTDecode and LZWDecode content streams are ordinary in real PDFs;
        // gating those would reject huge numbers of legitimate documents for no gain.
        var result = await Validate(BuildPdf("/Length 512 /Filter /DCTDecode", Deflate(Filler())));

        Assert.NotEqual(Uninspectable, result.ValidationType);
    }

    [Fact]
    public async Task Gate_can_be_disabled_for_producers_that_need_it()
    {
        var options = new FileContentValidatorOptions { RejectUninspectableObjectStreams = false };
        var result = await Validate(
            BuildPdf("/Type /ObjStm /N 1 /First 4 /Filter /LZWDecode", Deflate(Filler())), options);

        Assert.NotEqual(Uninspectable, result.ValidationType);
    }

    private static byte[] Filler() => Encoding.ASCII.GetBytes(new string('a', 512));

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

    private static byte[] Deflate(byte[] input)
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
