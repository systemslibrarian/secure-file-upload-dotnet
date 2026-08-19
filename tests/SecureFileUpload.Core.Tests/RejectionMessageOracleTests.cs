using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureFileUpload.Services;
using System.Linq;
using System.Text;
using Xunit;

namespace SecureFileUpload.Core.Tests;

/// <summary>
/// Regression tests for the rejection-message oracle closed in 3.3.0.
///
/// Structural and policy rejections used to copy the validator's internal reason
/// string into <see cref="ContentValidationResult.ErrorMessage"/> — verbatim for
/// policy, prefixed for structural. Because callers surface ErrorMessage to whoever
/// uploaded the file, that turned every rejection into a labeled oracle: an attacker
/// could learn which specific gate blocked a payload ("Missing %%EOF trailer",
/// "Embedded ZIP detected at offset 1234") and tune the next attempt around it.
///
/// The property under test is INDISTINGUISHABILITY, not merely "the message is nice":
/// two different unactionable gates must produce byte-identical ErrorMessage values,
/// and no ErrorMessage may echo file-derived detail. Detection detail must still reach
/// ThreatDescription, which is for logs and is documented as unsafe to display.
/// </summary>
public sealed class RejectionMessageOracleTests
{
    [Fact]
    public async Task Structural_rejection_does_not_leak_the_internal_reason()
    {
        // A PDF header with no %%EOF trailer — internally "Missing %%EOF trailer."
        byte[] pdf = Encoding.ASCII.GetBytes("%PDF-1.4\nnot a real pdf body\n");

        var result = await Validate(pdf, "doc.pdf", "application/pdf");

        Assert.False(result.IsValid);
        Assert.NotNull(result.ErrorMessage);
        // The curated set is closed: whatever fired, the message is one of these.
        Assert.Contains(result.ErrorMessage!, CuratedMessages);
        // And it must not carry the gate's own wording.
        Assert.DoesNotContain("EOF", result.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("trailer", result.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("header", result.ErrorMessage!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Detection_detail_still_reaches_ThreatDescription()
    {
        byte[] pdf = Encoding.ASCII.GetBytes("%PDF-1.4\nnot a real pdf body\n");

        var result = await Validate(pdf, "doc.pdf", "application/pdf");

        // The fix must not blind the security log: the reason still has to be present
        // somewhere, just not in the user-facing field.
        Assert.False(string.IsNullOrWhiteSpace(result.ThreatDescription));
        Assert.NotEqual(result.ErrorMessage, result.ThreatDescription);
    }

    [Fact]
    public async Task Two_distinct_pdf_gates_are_indistinguishable_to_the_uploader()
    {
        // Gate A: malformed version header. Gate B: missing %%EOF trailer.
        // Different internal reasons, different ValidationType — same user-facing text.
        var a = await Validate(Encoding.ASCII.GetBytes("%PDF-x.4\nbody\n"), "a.pdf", "application/pdf");
        var b = await Validate(Encoding.ASCII.GetBytes("%PDF-1.4\nbody\n"), "b.pdf", "application/pdf");

        Assert.False(a.IsValid);
        Assert.False(b.IsValid);
        Assert.NotEqual(a.ThreatDescription, b.ThreatDescription);   // genuinely different gates
        Assert.Equal(a.ErrorMessage, b.ErrorMessage);                // yet identical to the uploader
    }

    [Fact]
    public void Every_curated_message_is_a_compile_time_constant_not_file_derived()
    {
        // Resolve must be total: an out-of-range key falls back to the shared generic
        // rather than returning null and tempting a caller into using the reason string.
        Assert.Equal(
            UploadRejectionMessages.FileRejectedGeneric,
            UploadRejectionMessages.Resolve((UploadRejectionMessageKey)9999));

        foreach (UploadRejectionMessageKey key in Enum.GetValues<UploadRejectionMessageKey>())
        {
            string message = UploadRejectionMessages.Resolve(key);
            Assert.False(string.IsNullOrWhiteSpace(message));
            Assert.Contains(message, CuratedMessages);
        }

        // Adding an enum member without adding its string here would otherwise weaken every
        // other test in this file, since they assert membership of CuratedMessages.
        Assert.Equal(
            Enum.GetValues<UploadRejectionMessageKey>().Length,
            CuratedMessages.Distinct().Count());
    }

    private static readonly string[] CuratedMessages =
    {
        UploadRejectionMessages.FileRejectedGeneric,
        UploadRejectionMessages.PdfSecurityUploadImageInstead,
        UploadRejectionMessages.PdfUnreadableUploadImage,
        UploadRejectionMessages.PdfEncryptedRemovePassword,
        UploadRejectionMessages.ImageTooLargeUploadSmaller,
        UploadRejectionMessages.ImageUnreadableRetake,
        UploadRejectionMessages.ImageRejectedGeneric,
        UploadRejectionMessages.FileTooLargeUploadSmaller,
        UploadRejectionMessages.FileEmpty,
    };

    private static async Task<ContentValidationResult> Validate(
        byte[] bytes, string fileName, string contentType)
    {
        var validator = new FileContentValidator(
            NullLogger<FileContentValidator>.Instance,
            Options.Create(new FileContentValidatorOptions()));

        var stream = new MemoryStream(bytes, writable: false);
        IFormFile file = new FormFile(stream, 0, bytes.Length, "file", fileName)
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType,
        };

        return await validator.ValidateAsync(file);
    }
}
