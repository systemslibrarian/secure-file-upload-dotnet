using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SixLabors.ImageSharp;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    public sealed class FileContentValidatorOptions
    {
        /// <summary>
        /// Hard ceiling on how many bytes of a file are buffered and deep-scanned.
        ///
        /// NOTE: this is INDEPENDENT of the pipeline's per-file size limit
        /// (FileUpload:MaxFileSizeBytes, default 10 MB), which FileUploadService enforces
        /// earlier (Layer 1). Through the upload pipeline a file larger than that limit
        /// never reaches deep validation, so this cap only takes effect when the validator
        /// is invoked directly (e.g. in tests) or if the pipeline limit is raised above it.
        /// Keep MaxDeepScanBytes &gt;= FileUpload:MaxFileSizeBytes so a file the pipeline
        /// accepts is never silently truncated by the scanner.
        /// </summary>
        public int MaxDeepScanBytes { get; set; } = 20 * 1024 * 1024;

        public bool RejectEncryptedPdfs { get; set; } = true;
        public bool UseImageSharpForImages { get; set; } = true;

        // NOTE: These caps exist to reject decompression "pixel bombs," not to
        // limit ordinary patron photos. Modern smartphones commonly produce
        // 48/50/108/200 MP images (e.g. a 50 MP photo is ~8160x6120 = 50 M pixels,
        // a 200 MP photo is ~16320x12240). The previous caps (10000 px / 40 MP)
        // false-rejected these legitimate uploads. The per-file byte-size limit
        // (FileUpload:MaxFileSizeBytes) remains the primary abuse guard.
        public int MaxImageWidth { get; set; } = 30000;
        public int MaxImageHeight { get; set; } = 30000;
        public long MaxImagePixels { get; set; } = 300_000_000;

        /// <summary>
        /// If true, form-like PDFs (/AcroForm) are rejected even without active JavaScript.
        /// </summary>
        public bool RejectInteractivePdfs { get; set; } = false;

        /// <summary>
        /// When true, PDFs containing object streams (/ObjStm) are rejected: the dictionaries
        /// compressed inside an object stream cannot be walked by the current scanner, so
        /// active-content tokens (/JS, /Launch, /OpenAction) hidden there go uninspected.
        ///
        /// DEFAULT IS FALSE, deliberately. Object streams are standard in PDF 1.5+, which is
        /// what Word, Acrobat, Chrome/Edge "Print to PDF", and every mainstream phone scanner
        /// app (Adobe Scan, Apple Notes, Genius Scan) emit by default. Rejecting them
        /// unconditionally false-rejects the large majority of PDFs a patron can produce from
        /// a phone — the same class of problem the /Encrypt case had before
        /// <see cref="RejectEncryptedPdfs"/> was made configurable.
        ///
        /// Setting this false is NOT an exposure in this library. Stream payloads are stripped
        /// before token scanning (see StripPdfStreamPayloads), but the stripped ranges are then
        /// handed to <see cref="InspectCompressedPdfStreams"/>, which inflates them and runs the
        /// same name-object extraction over the decompressed dictionaries. Everything OUTSIDE the
        /// object stream is fully inspected as well: name objects, embedded-executable
        /// signatures, and the shell/script text scans all run as normal, with antivirus
        /// (Layer 7) as a further compensating control.
        ///
        /// Operators running a stricter policy — one where every patron PDF is known to come
        /// from a controlled producer — can set this true in configuration
        /// (FileUpload:ContentValidation:RejectPdfObjectStreams). Expect false rejections of
        /// ordinary modern PDFs if you do.
        /// </summary>
        public bool RejectPdfObjectStreams { get; set; } = false;

        /// <summary>
        /// When true, inflate the <c>stream … endstream</c> payloads that
        /// StripPdfStreamPayloads removed and re-run name-object extraction plus the dangerous
        /// pattern scan against the decompressed bytes. This is what makes
        /// <see cref="RejectPdfObjectStreams"/> safe to leave false: compressed PDF streams are
        /// otherwise opaque to a byte-level scanner.
        ///
        /// The stream ranges come from the PDF lexer rather than a substring search, so a name
        /// such as <c>/upstream</c>, or the word "stream" inside a comment or literal string,
        /// cannot misdirect the walk.
        /// </summary>
        public bool InspectCompressedPdfStreams { get; set; } = true;

        /// <summary>
        /// Maximum number of compressed PDF streams to inspect per file. Caps the cost
        /// of decompressing a maliciously crafted PDF with thousands of tiny streams.
        /// </summary>
        public int MaxCompressedStreamsToInspect { get; set; } = 64;

        /// <summary>
        /// Maximum total decompressed bytes inspected per file (across all streams).
        /// Prevents zip-bomb style decompression amplification attacks.
        /// </summary>
        public int MaxDecompressedStreamBytes { get; set; } = 16 * 1024 * 1024;

        /// <summary>
        /// Maximum total wall-clock milliseconds the FlateDecode stream scan may
        /// run per file. Bounds CPU under adversarially slow or pathological
        /// inflation even when the count and byte caps would otherwise permit
        /// continuation. Default 2000 ms.
        /// </summary>
        public int MaxPdfStreamScanMilliseconds { get; set; } = 2000;

        /// <summary>
        /// Maximum allowed per-stream decompression ratio (inflated / compressed).
        /// A stream expanding beyond this is treated as a decompression bomb and
        /// the file is rejected as <see cref="ValidationDisposition.RejectedMalicious"/>.
        /// Default 200x.
        /// </summary>
        public int MaxDecompressionRatio { get; set; } = 200;

        /// <summary>
        /// Maximum nesting depth when an inflated PDF stream itself contains
        /// recognisable Flate-wrapped sub-content (common with PDF object streams,
        /// <c>/ObjStm</c>). Depth 0 is the outer file body; depth 1 is the first
        /// inflated layer. Default 2 — enough for object streams, bounded for safety.
        /// </summary>
        public int MaxPdfStreamRecursionDepth { get; set; } = 2;

        /// <summary>
        /// Maximum filename length recorded in security logs.
        /// Longer names are truncated to prevent log-poisoning and storage abuse.
        /// </summary>
        public int MaxLogFileNameLength { get; set; } = 128;
    }

    public enum ValidationDisposition
    {
        Allowed,
        RejectedStructural,
        RejectedPolicy,
        RejectedMalicious,

        /// <summary>
        /// The file's binary signature does not match the claimed extension.
        /// This is a strong abuse signal distinct from pure structural invalidity.
        /// </summary>
        RejectedTypeMismatch
    }

    /// <summary>
    /// Signature-first file type classifier.
    /// Infers the actual format from magic bytes before any extension-based dispatch.
    /// </summary>
    internal enum DetectedFileType
    {
        Unknown,
        Pdf,
        Jpeg,
        Png,
        Webp,
        Gif,
        Bmp
    }

    internal enum MetadataExtractionStatus
    {
        Complete,
        Malformed,
        LimitExceeded
    }

    public sealed class ContentValidationResult
    {
        public bool IsValid { get; init; }
        public ValidationDisposition Disposition { get; init; }
        public string? ErrorMessage { get; init; }
        public string? ThreatDescription { get; init; }
        public bool IsSuspicious { get; init; }
        public string ValidationType { get; init; } = string.Empty;

        public static ContentValidationResult Allow(string validationType) =>
            new()
            {
                IsValid = true,
                Disposition = ValidationDisposition.Allowed,
                ValidationType = validationType
            };
    }

    /// <summary>
    /// Deep content validator — Layer 6 of the secure upload pipeline.
    ///
    /// Design principles:
    ///   • Fail-closed: unknown types and exceptions always reject.
    ///   • Signature-first format classification: content determines the real type,
    ///     compared against the claimed extension before dispatch.
    ///   • File.Length pre-check rejects oversized uploads before any buffering.
    ///   • Bounded buffered read with ArrayPool; buffer zeroed on return.
    ///   • fileBytes zeroed after validation to minimize patron document exposure.
    ///   • Image.Identify() only — avoids full pixel decode and greatly reduces
    ///     memory-amplification risk compared with loading the image.
    ///   • Single Latin1 decode per file shared across all threat-pattern checks.
    ///   • All pattern arrays are static readonly — allocated once at class load.
    ///   • Zero LINQ in hot paths.
    ///   • Four-way disposition: Structural / Policy / Malicious / TypeMismatch.
    ///   • /Encrypt handled by config only — not duplicated in DangerousPdfNames.
    ///   • /OpenAction and /AA only hard-blocked when JavaScript is also present.
    ///   • Name objects are extracted by the lexer, so /JSON never reads as /JS, and the
    ///     /J#53 hex-escape spelling of /JS is decoded rather than missed.
    ///   • Compressed stream payloads are inflated and re-scanned with the same name
    ///     extraction, so object-stream interiors are not a blind spot.
    ///   • JPEG segment walker validates marker types and segment lengths.
    ///   • JPEG EOI verified by backward scan — tolerates camera-appended trailing
    ///     data (Samsung, Xiaomi, older Canon) that follows a valid FF D9.
    ///   • PNG chunk layout fully walked with zero-allocation big-endian reads.
    ///   • WebP RIFF chunk tree fully walked and validated.
    ///   • GIF block walker validates logical screen descriptor, color tables, and sub-blocks.
    ///   • BMP planes, bits-per-pixel, and compression fields validated.
    ///   • Embedded executables and embedded containers separated into Malicious vs Policy.
    ///   • Filenames sanitized before logging to prevent log-poisoning.
    ///   • Buffer zeroed on ArrayPool return — prevents cross-request data leakage.
    ///   • Common threat scans (shell, script, executable, container) consolidated
    ///     into RunCommonThreatScans — single maintenance point for all format validators.
    /// </summary>
    public class FileContentValidator
    {
        private readonly ILogger<FileContentValidator> _logger;
        private readonly FileContentValidatorOptions _options;

        // ── PDF pattern tables ────────────────────────────────────────────────────

        // Hard-reject: active execution primitives with no legitimate use
        // in patron-submitted documents.
        private static readonly string[] DangerousPdfNames =
        {
            "JS", "JavaScript",
            "Launch",
            "EmbeddedFile",
            "RichMedia",
            "XFA",
            "JBIG2Decode",
            "3D",
            "Sound",
            "Movie"
            // /XObject omitted: present in virtually every scanned PDF (image XObjects).
            // /Encrypt and /ObjStm are handled as explicit policy decisions below.
        };

        // Suspicious or conditionally dangerous — logged and selectively blocked.
        private static readonly string[] SuspiciousPdfNames =
        {
            "URI",
            "SubmitForm",
            "GoToR",
            "OpenAction",
            "AA",
            "AcroForm"
        };

        // ── Embedded executable signatures (truly dangerous — always Malicious) ───

        private static readonly (byte[] Signature, string Description)[] DangerousExecutableSignatures =
        {
            (new byte[] { 0x4D, 0x5A },                               "PE executable (MZ)"),
            (new byte[] { 0x7F, 0x45, 0x4C, 0x46 },                   "ELF executable"),
            (new byte[] { 0xCA, 0xFE, 0xBA, 0xBE },                   "Java class / Mach-O fat binary"),
            (new byte[] { 0xFE, 0xED, 0xFA, 0xCE },                   "Mach-O 32-bit"),
            (new byte[] { 0xFE, 0xED, 0xFA, 0xCF },                   "Mach-O 64-bit"),
            (new byte[] { 0xCF, 0xFA, 0xED, 0xFE },                   "Mach-O 64-bit (reversed)"),
            (new byte[] { 0xD0, 0xCF, 0x11, 0xE0 },                   "OLE compound document (Office macro)"),
        };

        // ── Embedded archive/container signatures (policy concern — not inherently malicious) ─

        private static readonly (byte[] Signature, string Description)[] PolicyContainerSignatures =
        {
            (new byte[] { 0x50, 0x4B, 0x03, 0x04 },                   "ZIP / JAR / DOCX / APK container"),
            (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 },       "RAR archive"),
            (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C },       "7-Zip archive"),
            (new byte[] { 0x1F, 0x8B, 0x08 },                         "GZIP archive"),
        };

        // ── Image structural tables ───────────────────────────────────────────────

        // All valid JPEG marker types for the byte immediately following FF D8 FF.
        // Includes RST0-RST7 (0xD0-0xD7).
        private static readonly HashSet<byte> ValidJpegMarkerTypes = new()
        {
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,   // SOF0-SOF7
            0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,   // SOF8-SOF15
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,   // RST0-RST7
            0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,          // SOI/EOI/SOS/DQT/DNL/DRI/DHP
            0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,   // APP0-APP7
            0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,   // APP8-APP15
            0xFE                                                 // COM
        };

        // Standalone JPEG markers (no length field follows).
        private static readonly HashSet<byte> StandaloneJpegMarkers = new()
        {
            0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,   // RST0-RST7
            0xD8,                                                 // SOI
            0xD9,                                                 // EOI
            0x01                                                  // TEM
        };

        private static readonly byte[] PngSignature =
        {
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        };

        private static readonly HashSet<uint> ValidBmpDibSizes = new()
        {
            12, 40, 52, 56, 64, 108, 124
        };

        private static readonly HashSet<ushort> ValidBmpBitsPerPixel = new()
        {
            1, 4, 8, 16, 24, 32
        };

        // ── Threat pattern tables (static readonly — allocated once at class load) ─

        // NOTE: The ambiguous PHP short-open tags "<?=" and "<? " were intentionally
        // removed. They require `short_open_tag` to be enabled and occur by pure chance
        // inside legitimate JPEG EXIF/XMP metadata (e.g. XMP's "<?xpacket ...?>" wrapper
        // and embedded EXIF thumbnails), which false-rejected ordinary phone-camera
        // photos (Pixel PXL_*.jpg, iPhone screenshots). Genuine PHP webshells contain the
        // unambiguous "<?php" opener plus a dangerous function call (system(, eval(,
        // passthru(, base64_decode(, ...), all of which remain below — so real shells are
        // still detected without blocking valid patron uploads.
        //
        // Additionally removed for the same class of reason (ordinary prose / vendor
        // strings, not code):
        //   "system("    - OCR'd text layers in scanned documents ("filing system(s)")
        //   "exec("      - substring; also matches "...exec(" inside ordinary words
        //   "assert("    - technical prose in a document being scanned
        //   "import os"  - substring; matches "import osmotic..." and similar prose
        //   "powershell" - appears in scanner/driver EXIF software-agent strings
        //   "cmd.exe"    - same
        // The retained entries are either PHP-specific function names that do not occur
        // in English text, or explicit interpreter shebangs. A real webshell needs the
        // "<?php" opener, which remains, and PHP-only calls such as shell_exec(/eval(,
        // which also remain.
        private static readonly string[] PhpShellPatterns =
        {
            "<?php",
            "passthru(", "shell_exec(",
            "popen(", "proc_open(", "eval(",
            "base64_decode(", "gzinflate(", "gzuncompress(", "str_rot13(",
            "cmd /c",
            "import subprocess", "os.system(",
            "#!/usr/bin/perl", "#!/usr/bin/python", "#!/usr/bin/env python",
            "#!/bin/bash", "#!/bin/sh"
        };

        // NOTE ON FALSE POSITIVES (see also PhpShellPatterns above):
        // The text scan runs against image METADATA segments (JPEG APPn/COM, PNG
        // tEXt/iTXt/zTXt, WebP EXIF/XMP). That region is, by definition, one long run of
        // printable text — so IsTextContext() cannot filter anything there; every match
        // trivially clears the printable-run floor. Pattern selection is therefore the
        // ONLY defense against false positives in this path, and each pattern must be
        // unambiguous on its own.
        //
        // The following were removed because they are ordinary XML/English fragments that
        // occur in legitimate camera/scanner/editor metadata:
        //   "<meta "      - scanner XMP emits <meta name="generator" content="HP Scan"/>
        //   "<base "      - matches any XMP element/attribute beginning "base"
        //                   (Adobe Camera Raw crs: blocks)
        //   "<link "      - matches xmpMM:linkForm / linkCategory elements
        //   "expression(" - ordinary English in a caption or keyword field
        //   "@import"     - occurs in embedded ICC/comment text
        // These five defend against an HTML/CSS injection delivery path this application
        // does not have: uploads are stored encrypted OUTSIDE wwwroot, are never
        // web-served, and are streamed to authenticated staff with an explicit
        // Content-Type. Removing them costs no real detection.
        //
        // The unambiguous markup/script tokens below remain and are matched as before.
        private static readonly string[] ScriptContentPatterns =
        {
            "<script", "javascript:", "vbscript:", "data:text/html",
            "<svg", "<iframe", "<object", "<embed",
            "<form "
        };

        // Inline event handlers are matched SEPARATELY from the list above because the
        // bare token ("onload=") is a substring that occurs inside longer, harmless XMP
        // attribute names and in free-text caption fields. A genuine handler only has
        // meaning inside a tag, so these require an opening '<' within a short preceding
        // window (see ContainsInlineEventHandler). This mirrors the reasoning that
        // replaced the ambiguous "<?" / "<?=" short-open tags with the explicit "<?php".
        private static readonly string[] InlineEventHandlerPatterns =
        {
            "onerror=", "onload=", "onclick=", "onmouseover="
        };

        /// <summary>
        /// How far back an inline event handler match may look for an opening '&lt;'
        /// before it is treated as coincidental text rather than markup.
        /// </summary>
        private const int InlineHandlerTagLookbehind = 512;

        // ── Extension-to-detected-type mapping ────────────────────────────────────

        private static readonly Dictionary<string, DetectedFileType> ExtensionToExpectedType =
            new(StringComparer.OrdinalIgnoreCase)
            {
                { ".pdf",  DetectedFileType.Pdf  },
                { ".jpg",  DetectedFileType.Jpeg },
                { ".jpeg", DetectedFileType.Jpeg },
                { ".png",  DetectedFileType.Png  },
                { ".webp", DetectedFileType.Webp },
                { ".gif",  DetectedFileType.Gif  },
                { ".bmp",  DetectedFileType.Bmp  },
            };

        // Detected types that are safe, supported images. Used to permit image↔image
        // extension mislabeling (e.g. a JPEG saved as ".png" by a phone/screenshot tool)
        // while still rejecting any mismatch involving PDF or unsupported content.
        private static readonly HashSet<DetectedFileType> AllowedImageTypes = new()
        {
            DetectedFileType.Jpeg,
            DetectedFileType.Png,
            DetectedFileType.Webp,
        };

        /// <summary>
        /// The extensions corresponding to <c>AllowedImageTypes</c> — the single source of
        /// truth for which extensions may be cross-matched against one another when a file
        /// is mislabeled. FileUploadService consumes this for its Layer 4 magic-byte
        /// cross-match so the two layers cannot drift apart.
        ///
        /// PDF is deliberately absent: a document or executable must never be silently
        /// accepted through an image extension, or vice versa.
        ///
        /// GIF and BMP are also absent. They are detected and deep-validated when correctly
        /// labeled, but are not part of the mislabeling tolerance, because the observed
        /// real-world mislabeling (phone screenshots, iOS share sheets) only ever produces
        /// JPEG/PNG/WebP confusion. Add them here — not in a second list — if that changes.
        /// </summary>
        public static readonly IReadOnlySet<string> CrossMatchableImageExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".jpg", ".jpeg", ".png", ".webp"
            };

        // ─────────────────────────────────────────────────────────────────────────

        public FileContentValidator(
            ILogger<FileContentValidator> logger)
            : this(logger, Options.Create(new FileContentValidatorOptions()))
        {
        }

        public FileContentValidator(
            ILogger<FileContentValidator> logger,
            IOptions<FileContentValidatorOptions> options)
        {
            _logger  = logger  ?? throw new ArgumentNullException(nameof(logger));
            _options = options?.Value ?? throw new ArgumentNullException(nameof(options));
        }

        // ── Entry point ───────────────────────────────────────────────────────────

        public async Task<ContentValidationResult> ValidateAsync(
            IFormFile file,
            CancellationToken cancellationToken = default)
        {
            if (file is null)
                return RejectStructural("(null)", "INPUT", "No file was provided.", "Input-Null");

            if (file.Length <= 0)
                return RejectStructural(SanitizeFileName(file.FileName), "INPUT", "The file is empty.", "Input-Empty");

            string safeFileName = SanitizeFileName(file.FileName);

            // Reject before opening any stream — no buffering for obviously oversized files.
            if (file.Length > _options.MaxDeepScanBytes)
                return RejectPolicy(
                    safeFileName,
                    "INPUT",
                    $"File exceeds deep-scan limit of {_options.MaxDeepScanBytes:N0} bytes.",
                    "FailClosed-SizeLimit");

            string extension = Path.GetExtension(file.FileName)?.ToLowerInvariant() ?? string.Empty;

            byte[]? fileBytes = null;
            try
            {
                fileBytes = await ReadBoundedBytesAsync(file, safeFileName, cancellationToken)
                    .ConfigureAwait(false);

                // ── Signature-first classification ────────────────────────────────
                // Infer the real type from content, then compare to extension.
                // Mismatches (evil.php → .jpg, payload.pdf → .png) are rejected
                // before any format-specific parsing runs.

                DetectedFileType detectedType = DetectFileType(fileBytes);
                DetectedFileType expectedType = ExtensionToExpectedType.GetValueOrDefault(extension, DetectedFileType.Unknown);

                if (expectedType == DetectedFileType.Unknown)
                    return FailClosedUnknown(safeFileName, extension);

                if (detectedType == DetectedFileType.Unknown)
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | SIGNATURE_UNRECOGNIZED | Extension: {Ext} | FileName: {FileName}",
                        extension, safeFileName);
                    return RejectStructural(
                        safeFileName, extension.TrimStart('.').ToUpperInvariant(),
                        "File content signature could not be recognized.",
                        "SignatureUnrecognized");
                }

                if (detectedType != expectedType)
                {
                    // Allow image↔image mislabeling. Phones/browsers frequently swap image
                    // extensions (e.g. an iOS screenshot named ".png" that is really a JPEG,
                    // header FFD8FF). Both types are safe, supported images and are validated
                    // by their DETECTED type below, so this is not a security-relevant mismatch.
                    // Any mismatch involving PDF (or an unsupported type) still fails closed,
                    // preventing a document/executable disguised as an image and vice versa.
                    bool bothAreImages =
                        AllowedImageTypes.Contains(detectedType) &&
                        AllowedImageTypes.Contains(expectedType);

                    if (!bothAreImages)
                    {
                    _logger.LogWarning(
                        "SECURITY_EVENT | TYPE_MISMATCH | Extension: {Ext} | Detected: {Detected} | FileName: {FileName}",
                        extension, detectedType, safeFileName);
                    return RejectTypeMismatch(
                        safeFileName,
                        extension.TrimStart('.').ToUpperInvariant(),
                        $"Extension claims {expectedType} but content signature is {detectedType}.",
                        "SignatureExtensionMismatch");
                    }

                    _logger.LogInformation(
                        "IMAGE_TYPE_CROSS_MATCH | Extension: {Ext} | Detected: {Detected} | FileName: {FileName} | " +
                        "Accepted mislabeled but valid image; validating as detected type",
                        extension, detectedType, safeFileName);
                }

                // ── Format-specific deep validation ───────────────────────────────

                // Deep validation is the expensive, fully synchronous part of this method.
                // Check for cancellation before entering it so every file type honours the
                // token regardless of its shape — the per-stream checks inside the PDF
                // compressed-stream scanner only fire for PDFs that actually carry streams.
                // The caller's buffer is released by the finally block either way.
                cancellationToken.ThrowIfCancellationRequested();

                return detectedType switch
                {
                    DetectedFileType.Pdf  => ValidatePdf(fileBytes, safeFileName, cancellationToken),
                    DetectedFileType.Jpeg => ValidateJpeg(fileBytes, safeFileName),
                    DetectedFileType.Png  => ValidatePng(fileBytes, safeFileName),
                    DetectedFileType.Webp => ValidateWebp(fileBytes, safeFileName),
                    DetectedFileType.Gif  => ValidateGif(fileBytes, safeFileName),
                    DetectedFileType.Bmp  => ValidateBmp(fileBytes, safeFileName),
                    _                     => FailClosedUnknown(safeFileName, extension)
                };
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | VALIDATION_CANCELLED | FileName: {FileName}",
                    safeFileName);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "SECURITY_EVENT | DEEP_VALIDATION_EXCEPTION | FileName: {FileName}",
                    safeFileName);
                return RejectStructural(
                    safeFileName,
                    "INPUT",
                    "File content could not be validated. The file may be malformed or corrupted.",
                    "Exception");
            }
            finally
            {
                // Zero patron document bytes as soon as validation completes.
                // Not a guarantee (GC may have intermediate copies) but reduces
                // the window, consistent with encryption-side zeroing in FileUploadService.
                if (fileBytes != null)
                    CryptographicOperations.ZeroMemory(fileBytes);
            }
        }

        // ── Signature-first format classifier ─────────────────────────────────────

        /// <summary>
        /// Infers the actual file type from the first bytes of content.
        /// Checked before extension dispatch to catch renamed / mislabeled files.
        /// </summary>
        private static DetectedFileType DetectFileType(byte[] bytes)
        {
            if (bytes.Length < 2) return DetectedFileType.Unknown;

            // PDF: %PDF-
            if (bytes.Length >= 5 && AsciiEquals(bytes, 0, "%PDF-"))
                return DetectedFileType.Pdf;

            // JPEG: FF D8 FF
            if (bytes.Length >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF)
                return DetectedFileType.Jpeg;

            // PNG: 8-byte signature
            if (bytes.Length >= 8 && SignaturesMatch(bytes, PngSignature))
                return DetectedFileType.Png;

            // WebP: RIFF....WEBP (check both RIFF at 0 and WEBP at 8)
            if (bytes.Length >= 12 && AsciiEquals(bytes, 0, "RIFF") && AsciiEquals(bytes, 8, "WEBP"))
                return DetectedFileType.Webp;

            // GIF: GIF87a or GIF89a
            if (bytes.Length >= 6)
            {
                if (AsciiEquals(bytes, 0, "GIF87a") || AsciiEquals(bytes, 0, "GIF89a"))
                    return DetectedFileType.Gif;
            }

            // BMP: BM
            if (bytes[0] == 0x42 && bytes[1] == 0x4D)
                return DetectedFileType.Bmp;

            return DetectedFileType.Unknown;
        }

        // ── Bounded stream reader ─────────────────────────────────────────────────

        private async Task<byte[]> ReadBoundedBytesAsync(
            IFormFile file,
            string safeFileName,
            CancellationToken cancellationToken)
        {
            int max = _options.MaxDeepScanBytes;
            await using Stream input = file.OpenReadStream();
            using var ms = new MemoryStream((int)Math.Min(file.Length, max));

            byte[] buffer = ArrayPool<byte>.Shared.Rent(81_920);
            try
            {
                long totalRead = 0;
                int  read;
                while ((read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false)) > 0)
                {
                    totalRead += read;
                    if (totalRead > max)
                    {
                        _logger.LogWarning(
                            "SECURITY_EVENT | DEEP_SCAN_SIZE_LIMIT | FileName: {FileName} | Limit: {Limit:N0}",
                            safeFileName, max);
                        throw new InvalidOperationException("Deep scan size limit exceeded.");
                    }
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
            finally
            {
                // clearArray: true — zeroes buffer before returning to pool,
                // preventing upload data from one request leaking into the next.
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }

        // ── PDF ───────────────────────────────────────────────────────────────────

        /// <summary>
        /// Returns a copy of the raw PDF text with the bytes between each
        /// <c>stream</c>/<c>endstream</c> pair removed. PDF name-object tokens
        /// (/3D, /JS, /Launch, …) are only structurally meaningful inside object
        /// dictionaries — never inside compressed stream payloads — so removing
        /// stream bodies before token scanning eliminates false positives caused
        /// by those byte sequences appearing incidentally in FlateDecode-compressed
        /// image data, while still detecting tokens declared in dictionaries.
        ///
        /// SECURITY — this recognizes <c>stream</c> as a PDF LEXICAL TOKEN, not as a
        /// substring. A plain IndexOf("stream") is exploitable: the word occurs inside
        /// comments (<c>% stream</c>), inside literal strings, and inside longer names such
        /// as <c>/upstream</c>. Any of those caused the stripper to discard the remainder of
        /// the document, hiding every dangerous token that followed from the scanner. A
        /// crafted PDF could therefore declare /OpenAction and /JavaScript after a decoy
        /// occurrence and pass validation completely.
        ///
        /// The rules enforced here:
        ///   • Comments (<c>%</c> to end-of-line) are skipped and never yield tokens.
        ///   • Literal strings <c>( … )</c> are skipped, honoring backslash escapes and
        ///     nesting, so a "stream" inside string data is inert.
        ///   • <c>stream</c> must be a standalone token: the preceding character must not be
        ///     alphanumeric (rejecting <c>/upstream</c>) and it must be followed by CRLF or
        ///     LF as the PDF specification requires.
        ///   • A <c>stream</c> with no matching <c>endstream</c>, or an <c>endstream</c>
        ///     with no opener, sets <paramref name="malformed"/>. The caller MUST fail
        ///     closed on that flag rather than scanning a truncated result.
        ///
        /// Stripped payloads are not simply discarded: the overload taking a stream-range
        /// collector records the source offsets of each stream's data, so
        /// ScanCompressedPdfStreams can inflate exactly those ranges and scan the decompressed
        /// dictionaries. Because the ranges come from this lexer rather than a substring search,
        /// the scan cannot be misdirected by a "stream" occurring inside a name, comment, or
        /// literal string.
        /// </summary>
        private static string StripPdfStreamPayloads(string content, out bool malformed)
            => StripPdfStreamPayloads(content, out malformed, streamRanges: null);

        /// <summary>
        /// As <see cref="StripPdfStreamPayloads(string, out bool)"/>, additionally recording the
        /// <c>[start, end)</c> source offsets of each stream's data into
        /// <paramref name="streamRanges"/>. Offsets index the Latin1-decoded content, which is a
        /// 1:1 byte mapping, so they apply unchanged to the original byte buffer.
        /// </summary>
        private static string StripPdfStreamPayloads(
            string content, out bool malformed, List<(int Start, int End)>? streamRanges)
        {
            const string streamKeyword = "stream";
            const string endStreamKeyword = "endstream";

            malformed = false;

            var sb = new StringBuilder(content.Length);
            int i = 0;

            while (i < content.Length)
            {
                char c = content[i];

                // ── Comments: % through end of line. Never contain tokens. ──────────
                if (c == '%')
                {
                    int lineEnd = i;
                    while (lineEnd < content.Length && content[lineEnd] != '\n' && content[lineEnd] != '\r')
                        lineEnd++;
                    sb.Append(' ', lineEnd - i);
                    i = lineEnd;
                    continue;
                }

                // ── Literal strings: ( … ) with escapes and nesting. ─────────────────
                if (c == '(')
                {
                    int start = i;
                    int depth = 0;
                    while (i < content.Length)
                    {
                        char s = content[i];
                        if (s == '\\') { i += 2; continue; }
                        if (s == '(') depth++;
                        else if (s == ')')
                        {
                            depth--;
                            if (depth == 0) { i++; break; }
                        }
                        i++;
                    }
                    sb.Append(' ', Math.Min(i, content.Length) - start);
                    continue;
                }

                // ── "endstream" without a matching opener: malformed. ───────────────
                if (c == 'e' && MatchesTokenAt(content, i, endStreamKeyword))
                {
                    malformed = true;
                    sb.Append(content, i, endStreamKeyword.Length);
                    i += endStreamKeyword.Length;
                    continue;
                }

                // ── "stream" as a standalone token, per PDF lexical rules. ──────────
                if (c == 's' && MatchesTokenAt(content, i, streamKeyword) &&
                    IsPdfStreamKeywordStart(content, i, streamKeyword.Length, out int dataStart))
                {
                    sb.Append(content, i, streamKeyword.Length);

                    // Prefer the /Length value declared in the preceding dictionary. It is
                    // the authoritative statement of where the stream data ends. Searching
                    // for the "endstream" keyword instead is unreliable: compressed bytes
                    // can contain that word on a token boundary, which closes the stream
                    // early, makes the real endstream look unmatched, and leaks the
                    // remaining binary data into the text being token-scanned.
                    int endStreamStart = -1;

                    if (TryGetDeclaredStreamLength(content, i, out int declaredLength))
                    {
                        long dataEnd = (long)dataStart + declaredLength;
                        if (dataEnd <= content.Length)
                        {
                            // Confirm endstream appears where /Length says it should
                            // (allowing the EOL that may precede it).
                            int probe = (int)dataEnd;
                            while (probe < content.Length &&
                                   (content[probe] == '\r' || content[probe] == '\n' || content[probe] == ' '))
                                probe++;

                            if (MatchesTokenAt(content, probe, endStreamKeyword))
                                endStreamStart = probe;
                        }
                    }

                    // /Length absent, indirect, or inconsistent with the actual layout:
                    // fall back to locating the keyword.
                    if (endStreamStart < 0)
                        endStreamStart = FindPdfToken(content, dataStart, endStreamKeyword);

                    if (endStreamStart < 0)
                    {
                        // Unterminated stream: the remainder cannot be scanned. Signal the
                        // caller to reject rather than silently truncating the scan.
                        malformed = true;
                        sb.Append(endStreamKeyword);
                        break;
                    }

                    // Record the stream's data extent for the compressed-stream scanner.
                    // Trim the EOL that conventionally precedes `endstream` so the range
                    // holds only payload bytes.
                    if (streamRanges is not null)
                    {
                        int dataEnd = endStreamStart;
                        if (dataEnd > dataStart && content[dataEnd - 1] == '\n') dataEnd--;
                        if (dataEnd > dataStart && content[dataEnd - 1] == '\r') dataEnd--;
                        if (dataEnd > dataStart)
                            streamRanges.Add((dataStart, dataEnd));
                    }

                    // Preserve source offsets so subsequent text-context checks still map
                    // to the original byte buffer, but replace stream bytes with whitespace.
                    int strippedStart = i + streamKeyword.Length;
                    sb.Append(' ', endStreamStart - strippedStart);
                    sb.Append(endStreamKeyword);
                    i = endStreamStart + endStreamKeyword.Length;
                    continue;
                }

                sb.Append(c);
                i++;
            }

            return sb.ToString();
        }

        /// <summary>
        /// True when <paramref name="token"/> occurs at <paramref name="offset"/> and is not
        /// glued to an adjacent alphanumeric character — i.e. it is a standalone PDF token
        /// rather than part of a longer name such as <c>/upstream</c>.
        ///
        /// SECURITY — a preceding <c>/</c> also disqualifies the match. PDF name objects
        /// begin with a solidus, so <c>/stream</c> is a NAME, not the stream keyword.
        /// Accepting it let a crafted dictionary declare <c>/stream</c>, have the following
        /// dangerous entries treated as stream data and stripped, and close the false stream
        /// with an <c>endstream</c> hidden inside a literal string.
        /// </summary>
        private static bool MatchesTokenAt(string content, int offset, string token)
        {
            if (offset + token.Length > content.Length) return false;
            if (string.CompareOrdinal(content, offset, token, 0, token.Length) != 0) return false;

            if (offset > 0)
            {
                char before = content[offset - 1];
                if (char.IsLetterOrDigit(before)) return false;
                if (before == '/') return false;   // PDF name object, not a keyword
            }

            int after = offset + token.Length;
            if (after < content.Length && char.IsLetterOrDigit(content[after])) return false;

            return true;
        }

        /// <summary>
        /// Determines whether a <c>stream</c> keyword at <paramref name="offset"/> is a real
        /// stream opener, and reports where the stream DATA begins.
        ///
        /// PDF 32000-1 §7.3.8.1 requires CRLF or a single LF after the keyword. A bare CR is
        /// non-conformant, but some legacy producers emit it — and treating those files as
        /// "not a stream" is actively harmful: the binary payload would then never be
        /// stripped and would instead be token-scanned as dictionary text, reviving exactly
        /// the false-positive class this stripper exists to prevent. A bare CR is therefore
        /// accepted as an opener so the data is still bounded and removed.
        /// </summary>
        private static bool IsPdfStreamKeywordStart(
            string content, int offset, int keywordLength, out int dataStart)
        {
            dataStart = -1;

            int after = offset + keywordLength;
            if (after >= content.Length) return false;

            if (content[after] == '\n')
            {
                dataStart = after + 1;
                return true;
            }

            if (content[after] == '\r')
            {
                dataStart = (after + 1 < content.Length && content[after + 1] == '\n')
                    ? after + 2   // conformant CRLF
                    : after + 1;  // tolerated bare CR
                return true;
            }

            return false;
        }

        /// <summary>
        /// Reads the <c>/Length</c> value from the dictionary immediately preceding a
        /// <c>stream</c> keyword. Returns false when the value is absent or is an indirect
        /// reference (<c>/Length 5 0 R</c>), which cannot be resolved without full object
        /// parsing — the caller then falls back to keyword search.
        /// </summary>
        private static bool TryGetDeclaredStreamLength(string content, int streamOffset, out int length)
        {
            length = 0;

            if (streamOffset <= 0) return false;

            // Look back a bounded distance for the dictionary that opens this stream.
            int windowStart = Math.Max(0, streamOffset - PdfLengthLookbehind);
            int found = content.LastIndexOf(
                "/Length", Math.Max(windowStart, streamOffset - 1), streamOffset - windowStart, StringComparison.Ordinal);

            if (found < 0) return false;

            int p = found + "/Length".Length;
            while (p < streamOffset && (content[p] == ' ' || content[p] == '\r' || content[p] == '\n' || content[p] == '\t'))
                p++;

            int digitStart = p;
            while (p < streamOffset && char.IsDigit(content[p])) p++;
            if (p == digitStart) return false;

            // Indirect reference: "/Length 5 0 R" — the number is an object id, not a size.
            int q = p;
            while (q < streamOffset && (content[q] == ' ' || content[q] == '\r' || content[q] == '\n')) q++;
            if (q < streamOffset && char.IsDigit(content[q]))
            {
                while (q < streamOffset && char.IsDigit(content[q])) q++;
                while (q < streamOffset && (content[q] == ' ' || content[q] == '\r' || content[q] == '\n')) q++;
                if (q < streamOffset && content[q] == 'R') return false;
            }

            return int.TryParse(
                content.AsSpan(digitStart, p - digitStart),
                out length) && length >= 0;
        }

        /// <summary>
        /// Finds the next standalone <c>endstream</c> token inside a stream's DATA region.
        /// Used only when <c>/Length</c> is absent, indirect, or inconsistent with the layout.
        ///
        /// FALSE-POSITIVE NOTE — this deliberately performs NO comment or literal-string
        /// skipping. The region being searched is raw stream data, most often FlateDecode
        /// output, where <c>(</c> and <c>%</c> are ordinary bytes and carry no lexical
        /// meaning. Treating them as a string opener or a comment made the search run past
        /// the real <c>endstream</c>, which set <c>malformed</c> and structurally rejected
        /// ordinary PDFs whose producer writes an indirect length (<c>/Length 6 0 R</c> —
        /// Ghostscript, many MFP scanner firmwares, PDF/A converters). The token-boundary
        /// rules in <see cref="MatchesTokenAt"/> remain the guard against partial matches.
        ///
        /// A crafted <c>endstream</c> planted inside stream data closes the strip early,
        /// which exposes MORE bytes to the token scan, not fewer — and leaves the genuine
        /// <c>endstream</c> unmatched, which fails closed via <c>malformed</c>.
        /// </summary>
        private static int FindPdfToken(string content, int startIndex, string token)
        {
            for (int i = startIndex; i < content.Length; i++)
            {
                if (content[i] == token[0] && MatchesTokenAt(content, i, token))
                    return i;
            }
            return -1;
        }

        /// <summary>
        /// Extracts exact PDF name objects from a stream-free lexical surface and decodes
        /// hexadecimal <c>#xx</c> escapes. Returns false for malformed escapes so callers
        /// can fail closed rather than scanning an attacker-controlled alternate spelling.
        /// </summary>
        private static bool TryExtractPdfNames(string content, out HashSet<string> names)
        {
            names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = 0; i < content.Length; i++)
            {
                if (content[i] != '/') continue;

                var name = new StringBuilder();
                int cursor = i + 1;
                while (cursor < content.Length &&
                       !IsPdfWhitespace(content[cursor]) &&
                       !IsPdfDelimiter(content[cursor]))
                {
                    if (content[cursor] == '#')
                    {
                        if (cursor + 2 >= content.Length ||
                            !TryHexValue(content[cursor + 1], out int high) ||
                            !TryHexValue(content[cursor + 2], out int low))
                        {
                            return false;
                        }

                        name.Append((char)((high << 4) | low));
                        cursor += 3;
                        continue;
                    }

                    name.Append(content[cursor]);
                    cursor++;
                }

                if (name.Length > 0)
                    names.Add(name.ToString());

                i = cursor - 1;
            }

            return true;
        }

        private static bool IsPdfWhitespace(char value) =>
            value is '\0' or '\t' or '\n' or '\f' or '\r' or ' ';

        private static bool IsPdfDelimiter(char value) =>
            value is '(' or ')' or '<' or '>' or '[' or ']' or '{' or '}' or '/' or '%';

        private static bool TryHexValue(char value, out int result)
        {
            if (value >= '0' && value <= '9')
            {
                result = value - '0';
                return true;
            }

            if (value >= 'A' && value <= 'F')
            {
                result = value - 'A' + 10;
                return true;
            }

            if (value >= 'a' && value <= 'f')
            {
                result = value - 'a' + 10;
                return true;
            }

            result = 0;
            return false;
        }

        private ContentValidationResult ValidatePdf(
            byte[] bytes, string fileName, CancellationToken cancellationToken)
        {
            if (bytes.Length < 8)
                return RejectStructural(fileName, "PDF", "File too small to be a valid PDF.", "PDF-StructuralCheck");

            if (!AsciiEquals(bytes, 0, "%PDF-"))
                return RejectStructural(fileName, "PDF", "Invalid or missing PDF header.", "PDF-StructuralCheck");

            if (!char.IsDigit((char)bytes[5]))
                return RejectStructural(fileName, "PDF", "Malformed PDF version header.", "PDF-StructuralCheck");

            // Single decode — reused for all pattern checks below.
            string content = Encoding.Latin1.GetString(bytes);

            int eofIndex = content.LastIndexOf("%%EOF", StringComparison.Ordinal);
            if (eofIndex < 0)
                return RejectStructural(fileName, "PDF", "Missing %%EOF trailer.", "PDF-StructuralCheck");

            // Whitespace-aware trailing check — rejects appended payloads while
            // allowing legitimately padded PDFs.
            if (!HasOnlyTrailingPdfWhitespace(content, eofIndex + 5))
            {
                _logger.LogWarning("SECURITY_EVENT | PDF_APPENDED_DATA | FileName: {FileName}", fileName);
                return RejectMalicious(
                    fileName, "PDF",
                    "Data found after final %%EOF — possible polyglot or appended payload.",
                    "PDF-AppendedData");
            }

            // Name-object tokens like /3D, /JS, /Launch are only meaningful when they
            // appear in PDF object dictionaries — NEVER inside the compressed bytes of a
            // stream…endstream blob. Scanning the raw file for these produced false
            // positives when the FlateDecode-compressed content of an ordinary scanned
            // document happened to contain the byte sequence (e.g. a scanned driver's
            // license whose compressed image data contained "/3D"). We therefore run the
            // token scans against a copy with stream payloads removed, which preserves
            // detection of tokens declared in dictionaries while eliminating incidental
            // matches inside compressed data.
            // Collect the stripped stream ranges so the compressed-stream scanner below can
            // inflate them. Only allocate the list when that scan is enabled.
            List<(int Start, int End)>? streamRanges =
                _options.InspectCompressedPdfStreams ? new List<(int, int)>() : null;

            string dictContent = StripPdfStreamPayloads(content, out bool malformedStreams, streamRanges);

            // Malformed stream structure (unmatched stream/endstream) means part of the
            // document was discarded above and CANNOT be token-scanned. Rejecting closes
            // the bypass where a crafted PDF uses a decoy or unterminated stream so that a
            // /Launch or /JS declared afterwards is never seen. No legitimate producer emits
            // unbalanced stream keywords, so this fails closed at no false-positive cost.
            if (malformedStreams)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | PDF_MALFORMED_STREAM | FileName: {FileName} | " +
                    "Unbalanced stream/endstream; document not fully scannable — rejected",
                    fileName);
                return RejectStructural(
                    fileName, "PDF",
                    "Malformed PDF: unbalanced stream/endstream structure.",
                    "PDF-MalformedStream");
            }

            if (!TryExtractPdfNames(dictContent, out HashSet<string> pdfNames))
            {
                return RejectStructural(
                    fileName, "PDF",
                    "Malformed hexadecimal escape in PDF name object.",
                    "PDF-MalformedName");
            }

            if (_options.RejectEncryptedPdfs && pdfNames.Contains("Encrypt"))
                return RejectPolicy(
                    fileName, "PDF",
                    "Encrypted PDFs are not permitted by security policy.",
                    "PDF-EncryptedRejected");

            // Object streams hide dictionaries inside compressed stream payloads. Modern PDF
            // producers (PDF 1.5+) emit them routinely, so they are accepted by default and
            // their contents are inflated and scanned by ScanCompressedPdfStreams below.
            // RejectPdfObjectStreams remains available for operators who want them refused
            // outright; see the option's documentation for the tradeoff.
            if (pdfNames.Contains("ObjStm"))
            {
                if (_options.RejectPdfObjectStreams)
                    return RejectPolicy(
                        fileName, "PDF",
                        "PDF object streams are not permitted by security policy.",
                        "PDF-ObjectStreamRejected");

                if (_options.InspectCompressedPdfStreams)
                    _logger.LogDebug(
                        "PDF_OBJECT_STREAM_PRESENT | FileName: {FileName} | " +
                        "Contents will be inflated and scanned (InspectCompressedPdfStreams=true)",
                        fileName);
                else
                    _logger.LogWarning(
                        "SECURITY_EVENT | PDF_OBJECT_STREAM_ALLOWED | FileName: {FileName} | " +
                        "RejectPdfObjectStreams=false and InspectCompressedPdfStreams=false — " +
                        "object-stream contents are NOT deep-scanned; antivirus (Layer 7) is the " +
                        "compensating control",
                        fileName);
            }

            foreach (string name in DangerousPdfNames)
            {
                if (!pdfNames.Contains(name)) continue;

                string pattern = "/" + name;
                LogWithHexSnippet("SECURITY_EVENT | PDF_DANGEROUS_PATTERN", fileName, pattern, bytes);
                return RejectMalicious(
                    fileName, "PDF",
                    $"Dangerous PDF pattern detected: {pattern}",
                    "PDF-DangerousPattern");
            }

            bool hasJavaScript = pdfNames.Contains("JS") || pdfNames.Contains("JavaScript");

            foreach (string name in SuspiciousPdfNames)
            {
                if (!pdfNames.Contains(name)) continue;

                _logger.LogWarning(
                    "SECURITY_EVENT | PDF_SUSPICIOUS_PATTERN | FileName: {FileName} | Pattern: {Pattern}",
                    fileName, "/" + name);

                // /OpenAction and /AA only become hard blocks when JS is also present.
                bool isTriggerAction =
                    name.Equals("OpenAction", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("AA", StringComparison.OrdinalIgnoreCase);

                if (isTriggerAction && hasJavaScript)
                    return RejectMalicious(
                        fileName, "PDF",
                        $"Dangerous PDF trigger action with JavaScript: /{name}",
                        "PDF-TriggerWithJavaScript");

                if (_options.RejectInteractivePdfs &&
                    name.Equals("AcroForm", StringComparison.OrdinalIgnoreCase))
                    return RejectPolicy(
                        fileName, "PDF",
                        "Interactive form PDFs are not permitted by policy.",
                        "PDF-InteractiveRejected");
            }

            if (ContainsNullByteSequence(bytes, 10))
                _logger.LogDebug("PDF_NULL_BYTES_DETECTED | FileName: {FileName} | Non-blocking", fileName);

            // Use the same stream/string/comment-free surface for generic text patterns.
            // Its length matches the source so text-context offsets still map to `bytes`.
            if (ContainsPhpShell(bytes, dictContent, fileName))
                return EmbeddedShellReject(fileName, "PDF");

            if (ContainsScriptContent(bytes, dictContent, fileName))
                return EmbeddedScriptReject(fileName, "PDF");

            // Keep only the strongly confirmed MZ + PE\0\0 check over the full PDF.
            // Four-byte ELF/ZIP/GZIP-style signatures routinely occur inside compressed
            // streams and are not evidence of an embedded executable on their own.
            if (ContainsEmbeddedExecutable(
                    bytes, fileName, "PDF", requireStructuralConfirmation: true) is { } exeResult)
                return exeResult;

            // Everything above scanned the surface with stream payloads stripped. Now inflate
            // those payloads and apply the same name-object extraction to their contents, so a
            // /JavaScript or /Launch declared inside a compressed object stream is still found.
            if (streamRanges is { Count: > 0 })
            {
                if (ScanCompressedPdfStreams(
                        bytes, streamRanges, fileName, cancellationToken) is { } streamThreat)
                    return streamThreat;
            }

            _logger.LogDebug("PDF deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("PDF-DeepScan");
        }

        // ── Compressed PDF stream scanner ─────────────────────────────────────────
        //
        // StripPdfStreamPayloads removes stream data before token scanning, so that the
        // compressed bytes of an ordinary scanned document cannot produce incidental name
        // matches. That leaves the interior of every stream unexamined — including PDF
        // object streams (/ObjStm), which is exactly where real dictionaries live in any
        // PDF 1.5+ file. This scanner closes that gap: it inflates the ranges the lexer
        // identified and runs the same name-object extraction over the decompressed bytes,
        // so /JavaScript or /Launch declared inside a compressed object stream is still
        // found, and the /J#53 hex-escape spelling is decoded rather than missed.
        //
        // The ranges are produced by the PDF lexer, not by a substring search for
        // "stream". A name such as /upstream, or the word appearing inside a comment or
        // literal string, therefore cannot misdirect the walk — the defect that a plain
        // IndexOf-driven version of this scanner had.
        //
        // Hard caps (all configurable):
        //   • MaxCompressedStreamsToInspect — bounds total CPU per file
        //   • MaxDecompressedStreamBytes    — bounds memory (zip-bomb defence)
        //   • MaxDecompressionRatio         — per-stream bomb ratio cap
        //   • MaxPdfStreamScanMilliseconds  — per-file wall-clock cap
        //   • MaxPdfStreamRecursionDepth    — nested /ObjStm walk depth
        //
        // Per stream, inflation failure is fail-open: a malformed, encrypted, or non-Flate
        // stream holds nothing this scanner can read, and the outer scans plus antivirus
        // still apply. The file as a whole fails closed if a decompressed dictionary yields
        // a dangerous name, a stream exceeds the ratio cap, the time budget is exceeded, or
        // cancellation is requested.
        private sealed class PdfStreamScanState
        {
            public int TotalDecompressed;
            public int StreamsInspected;
            public Stopwatch Deadline = new();
            public int TimeoutMs;
            public int RatioCap;
            public int MaxStreams;
            public int MaxDecompressedBytes;
        }

        private ContentValidationResult? ScanCompressedPdfStreams(
            byte[] bytes,
            List<(int Start, int End)> streamRanges,
            string fileName,
            CancellationToken cancellationToken)
        {
            var state = new PdfStreamScanState
            {
                TimeoutMs            = _options.MaxPdfStreamScanMilliseconds,
                RatioCap             = _options.MaxDecompressionRatio,
                MaxStreams           = _options.MaxCompressedStreamsToInspect,
                MaxDecompressedBytes = _options.MaxDecompressedStreamBytes,
            };
            state.Deadline.Start();

            var result = ScanCompressedPdfStreamsCore(
                bytes, streamRanges, fileName, depth: 0, state, cancellationToken);

            if (state.StreamsInspected > 0)
                _logger.LogDebug(
                    "PDF_COMPRESSED_STREAMS_SCANNED | FileName: {FileName} | Streams: {Count} | " +
                    "DecompressedBytes: {Bytes} | ElapsedMs: {Ms}",
                    fileName, state.StreamsInspected, state.TotalDecompressed,
                    state.Deadline.ElapsedMilliseconds);

            return result;
        }

        private ContentValidationResult? ScanCompressedPdfStreamsCore(
            byte[] bytes,
            List<(int Start, int End)> streamRanges,
            string fileName,
            int depth,
            PdfStreamScanState state,
            CancellationToken cancellationToken)
        {
            if (depth > _options.MaxPdfStreamRecursionDepth)
                return null;

            foreach ((int start, int end) in streamRanges)
            {
                if (state.StreamsInspected >= state.MaxStreams) break;
                if (state.TotalDecompressed >= state.MaxDecompressedBytes) break;

                cancellationToken.ThrowIfCancellationRequested();

                if (state.Deadline.ElapsedMilliseconds > state.TimeoutMs)
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | PDF_STREAM_SCAN_TIMEOUT | FileName: {FileName} | " +
                        "ElapsedMs: {Ms} | Cap: {Cap}",
                        fileName, state.Deadline.ElapsedMilliseconds, state.TimeoutMs);
                    return RejectStructural(
                        fileName, "PDF",
                        "PDF compressed-stream scan exceeded the configured time budget.",
                        "PDF-CompressedStreamTimeout");
                }

                // Offsets come from a Latin1 decode of these same bytes, so they map 1:1.
                // Clamp defensively anyway rather than trusting the invariant.
                if (start < 0 || end > bytes.Length || end - start <= 2) continue;
                int rawLen = end - start;

                state.StreamsInspected++;

                // PDF FlateDecode is zlib-wrapped (RFC 1950) while DeflateStream speaks raw
                // RFC 1951, so skip the 2-byte zlib header when one is present. Streams that
                // are raw deflate (or another filter entirely) are still attempted and simply
                // fail to inflate, which is handled below.
                byte b0 = bytes[start];
                byte b1 = bytes[start + 1];
                bool looksLikeZlib = (b0 & 0x0F) == 0x08 && (((b0 << 8) | b1) % 31 == 0);
                int deflateOffset = looksLikeZlib ? 2 : 0;
                int deflateLen = rawLen - deflateOffset;
                if (deflateLen <= 0) continue;

                int budget = state.MaxDecompressedBytes - state.TotalDecompressed;
                if (budget <= 0) break;

                byte[] inflated;
                try
                {
                    using var src = new MemoryStream(bytes, start + deflateOffset, deflateLen, writable: false);
                    using var inflater = new DeflateStream(src, CompressionMode.Decompress, leaveOpen: false);
                    using var dst = new MemoryStream();
                    var buf = new byte[8192];
                    int read;
                    int written = 0;
                    while ((read = inflater.Read(buf, 0, buf.Length)) > 0)
                    {
                        written += read;
                        if (written > budget)
                        {
                            // Over the per-file budget: keep what fits and stop this stream.
                            dst.Write(buf, 0, read - (written - budget));
                            break;
                        }
                        dst.Write(buf, 0, read);

                        // Re-check the wall-clock and cancellation budgets while streaming —
                        // a single huge inflate must not block past the cap.
                        cancellationToken.ThrowIfCancellationRequested();
                        if (state.Deadline.ElapsedMilliseconds > state.TimeoutMs) break;
                    }
                    inflated = dst.ToArray();
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    // Malformed, encrypted, or non-Flate stream — nothing readable here.
                    continue;
                }

                if (inflated.Length == 0) continue;
                state.TotalDecompressed += inflated.Length;

                // Decompression-ratio bomb check. Legitimate FlateDecode over document
                // content rarely exceeds ~10x.
                int ratio = inflated.Length / Math.Max(deflateLen, 1);
                if (ratio > state.RatioCap)
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | PDF_DECOMPRESSION_BOMB | FileName: {FileName} | " +
                        "Ratio: {Ratio} | Cap: {Cap} | Compressed: {Comp} | Inflated: {Inf}",
                        fileName, ratio, state.RatioCap, deflateLen, inflated.Length);
                    return RejectMalicious(
                        fileName, "PDF",
                        $"Compressed PDF stream expanded {ratio}x (cap {state.RatioCap}x) — decompression-bomb signature.",
                        "PDF-DecompressionBomb");
                }

                // Apply the same lexer to the decompressed layer: strip any nested stream
                // payloads (collecting them for recursion) and extract name objects from
                // what remains.
                string inflatedContent = Encoding.Latin1.GetString(inflated);

                List<(int Start, int End)>? nested =
                    depth < _options.MaxPdfStreamRecursionDepth
                        ? new List<(int, int)>()
                        : null;

                // A malformed nested stream is deliberately not a rejection: this is
                // decompressed interior content, not the document structure that the
                // outer malformedStreams check governs. Whatever was recovered is scanned.
                string inflatedDict = StripPdfStreamPayloads(inflatedContent, out _, nested);

                if (TryExtractPdfNames(inflatedDict, out HashSet<string> names) &&
                    ScanInflatedPdfNames(names, fileName, depth) is { } nameThreat)
                {
                    return nameThreat;
                }

                if (nested is { Count: > 0 })
                {
                    var inner = ScanCompressedPdfStreamsCore(
                        inflated, nested, fileName, depth + 1, state, cancellationToken);
                    if (inner != null) return inner;
                }
            }

            return null;
        }

        /// <summary>
        /// Applies the dangerous/suspicious name policy to names extracted from a decompressed
        /// PDF stream, mirroring the checks <c>ValidatePdf</c> runs against the document surface
        /// so that hiding a declaration inside an object stream gains an attacker nothing.
        /// </summary>
        private ContentValidationResult? ScanInflatedPdfNames(
            HashSet<string> names, string fileName, int depth)
        {
            foreach (string name in DangerousPdfNames)
            {
                if (!names.Contains(name)) continue;

                _logger.LogWarning(
                    "SECURITY_EVENT | PDF_COMPRESSED_STREAM_THREAT | FileName: {FileName} | " +
                    "Pattern: {Pattern} | Depth: {Depth}",
                    fileName, "/" + name, depth);

                return RejectMalicious(
                    fileName, "PDF",
                    $"Dangerous PDF pattern /{name} found inside a compressed stream.",
                    "PDF-CompressedStreamThreat");
            }

            bool hasJavaScript = names.Contains("JS") || names.Contains("JavaScript");

            foreach (string name in SuspiciousPdfNames)
            {
                if (!names.Contains(name)) continue;

                _logger.LogWarning(
                    "SECURITY_EVENT | PDF_COMPRESSED_STREAM_SUSPICIOUS | FileName: {FileName} | " +
                    "Pattern: {Pattern} | Depth: {Depth}",
                    fileName, "/" + name, depth);

                bool isTriggerAction =
                    name.Equals("OpenAction", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("AA", StringComparison.OrdinalIgnoreCase);

                if (isTriggerAction && hasJavaScript)
                    return RejectMalicious(
                        fileName, "PDF",
                        $"Dangerous PDF trigger action with JavaScript inside a compressed stream: /{name}",
                        "PDF-CompressedStreamThreat");

                if (_options.RejectInteractivePdfs &&
                    name.Equals("AcroForm", StringComparison.OrdinalIgnoreCase))
                    return RejectPolicy(
                        fileName, "PDF",
                        "Interactive form PDFs are not permitted by policy.",
                        "PDF-InteractiveRejected");
            }

            return null;
        }

        // ── Images ────────────────────────────────────────────────────────────────
        //
        // Pattern: minimum-length guard → Image.Identify() (header-only, no pixel
        // decode — greatly reduces memory-amplification risk compared with loading
        // the image) → manual structural checks → threat scans.

        private ContentValidationResult ValidateJpeg(byte[] bytes, string fileName)
        {
            if (bytes.Length < 4)
                return RejectStructural(fileName, "JPEG", "File too small to be a valid JPEG.", "JPEG-StructuralCheck");

            if (ValidateImageMetadata(bytes, fileName, "JPEG") is { } metaFail) return metaFail;

            if (bytes[0] != 0xFF || bytes[1] != 0xD8 || bytes[2] != 0xFF || !ValidJpegMarkerTypes.Contains(bytes[3]))
                return RejectStructural(fileName, "JPEG", "Invalid JPEG SOI or marker type.", "JPEG-StructuralCheck");

            // Locate the TRUE end of image by walking segments and the entropy-coded scan
            // (see FindJpegEndOfImage). Any bytes after that point are NOT part of the
            // image and are validated separately below — previously they were never
            // examined at all, which let an appended shell pass validation.
            int endOfImage = FindJpegEndOfImage(bytes);
            if (endOfImage < 0)
                return RejectStructural(fileName, "JPEG", "Missing or invalid JPEG EOI marker.", "JPEG-StructuralCheck");

            // Walk JPEG segments: validate marker types and declared segment lengths.
            // Stops at SOS (0xDA) since entropy-coded data follows and cannot be walked.
            if (!ValidateJpegSegmentLayout(bytes))
                return RejectStructural(fileName, "JPEG", "Invalid JPEG segment structure.", "JPEG-SegmentWalk");

            if (RunImageThreatScans(bytes, fileName, "JPEG") is { } threatResult)
                return threatResult;

            // Trailing data after EOI: legitimate for Motion Photo / Live Photo (an MP4
            // appended by Samsung, Google, and Xiaomi cameras), but also the natural place
            // to hide a payload. Scan it as a non-image region rather than trusting it.
            if (endOfImage < bytes.Length)
            {
                if (ValidateJpegTrailingData(bytes, endOfImage, fileName) is { } trailingResult)
                    return trailingResult;
            }

            _logger.LogDebug("JPEG deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("JPEG-DeepScan");
        }

        private ContentValidationResult ValidatePng(byte[] bytes, string fileName)
        {
            if (bytes.Length < 33)
                return RejectStructural(fileName, "PNG", "File too small to be a valid PNG.", "PNG-StructuralCheck");

            if (ValidateImageMetadata(bytes, fileName, "PNG") is { } metaFail) return metaFail;

            if (!SignaturesMatch(bytes, PngSignature))
                return RejectStructural(fileName, "PNG", "Invalid PNG signature.", "PNG-StructuralCheck");

            if (!AsciiEquals(bytes, 12, "IHDR"))
                return RejectStructural(fileName, "PNG", "Missing IHDR chunk.", "PNG-StructuralCheck");

            if (!ValidatePngChunkLayout(bytes))
                return RejectStructural(fileName, "PNG", "Invalid PNG chunk layout or missing IEND.", "PNG-StructuralCheck");

            if (RunImageThreatScans(bytes, fileName, "PNG") is { } threatResult)
                return threatResult;

            _logger.LogDebug("PNG deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("PNG-DeepScan");
        }

        private ContentValidationResult ValidateWebp(byte[] bytes, string fileName)
        {
            if (bytes.Length < 12)
                return RejectStructural(fileName, "WEBP", "File too small to be a valid WebP.", "WEBP-StructuralCheck");

            if (ValidateImageMetadata(bytes, fileName, "WEBP") is { } metaFail) return metaFail;

            if (!AsciiEquals(bytes, 0, "RIFF") || !AsciiEquals(bytes, 8, "WEBP"))
                return RejectStructural(fileName, "WEBP", "Invalid WebP RIFF/WEBP header.", "WEBP-StructuralCheck");

            // Strict equality: declared payload + 8-byte RIFF header must equal actual file length.
            // Intentionally stricter than the RIFF spec to reject files with appended payloads
            // or trailing padding that could conceal embedded content.
            uint  declaredRiffPayloadSize = BitConverter.ToUInt32(bytes, 4);
            ulong expectedContainerSize   = declaredRiffPayloadSize + 8UL;
            if ((ulong)bytes.Length != expectedContainerSize)
                return RejectStructural(fileName, "WEBP", "WebP file size is inconsistent with RIFF header.", "WEBP-StructuralCheck");

            if (!ValidateWebpChunkLayout(bytes))
                return RejectStructural(fileName, "WEBP", "Invalid WebP chunk layout.", "WEBP-StructuralCheck");

            if (RunImageThreatScans(bytes, fileName, "WEBP") is { } threatResult)
                return threatResult;

            _logger.LogDebug("WEBP deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("WEBP-DeepScan");
        }

        private ContentValidationResult ValidateGif(byte[] bytes, string fileName)
        {
            if (bytes.Length < 13)
                return RejectStructural(fileName, "GIF", "File too small to be a valid GIF.", "GIF-StructuralCheck");

            if (ValidateImageMetadata(bytes, fileName, "GIF") is { } metaFail) return metaFail;

            if (!AsciiEquals(bytes, 0, "GIF87a") && !AsciiEquals(bytes, 0, "GIF89a"))
                return RejectStructural(fileName, "GIF", "Invalid GIF header.", "GIF-StructuralCheck");

            ushort width  = BitConverter.ToUInt16(bytes, 6);
            ushort height = BitConverter.ToUInt16(bytes, 8);
            if (width == 0 || height == 0)
                return RejectStructural(fileName, "GIF", "GIF has zero width or height.", "GIF-StructuralCheck");

            // Verify GIF trailer byte (0x3B).
            if (bytes[^1] != 0x3B)
                return RejectStructural(fileName, "GIF", "Missing GIF trailer byte.", "GIF-StructuralCheck");

            // Walk GIF block structure: logical screen descriptor, global color table,
            // image descriptors, extensions, and sub-block chains.
            if (!ValidateGifBlockLayout(bytes))
                return RejectStructural(fileName, "GIF", "Invalid GIF block structure.", "GIF-BlockWalk");

            if (RunImageThreatScans(bytes, fileName, "GIF") is { } threatResult)
                return threatResult;

            _logger.LogDebug("GIF deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("GIF-DeepScan");
        }

        private ContentValidationResult ValidateBmp(byte[] bytes, string fileName)
        {
            if (bytes.Length < 30)
                return RejectStructural(fileName, "BMP", "File too small to be a valid BMP.", "BMP-StructuralCheck");

            if (ValidateImageMetadata(bytes, fileName, "BMP") is { } metaFail) return metaFail;

            if (bytes[0] != 0x42 || bytes[1] != 0x4D)
                return RejectStructural(fileName, "BMP", "Invalid BMP header.", "BMP-StructuralCheck");

            // BMP spec allows the file-size field to be 0 for BI_RGB bitmaps.
            // Many legitimate editors (GIMP, older Paint versions) produce these.
            // Only reject when the field is non-zero AND inconsistent with actual size.
            uint declaredSize = BitConverter.ToUInt32(bytes, 2);
            if (declaredSize != 0 && declaredSize > bytes.Length)
                return RejectStructural(fileName, "BMP", "BMP file size is inconsistent with header.", "BMP-StructuralCheck");

            uint pixelDataOffset = BitConverter.ToUInt32(bytes, 10);
            if (pixelDataOffset < 14 || pixelDataOffset >= bytes.Length)
                return RejectStructural(fileName, "BMP", "Invalid BMP pixel data offset.", "BMP-StructuralCheck");

            uint dibHeaderSize = BitConverter.ToUInt32(bytes, 14);
            if (!ValidBmpDibSizes.Contains(dibHeaderSize))
                return RejectStructural(fileName, "BMP", $"Invalid BMP DIB header size ({dibHeaderSize}).", "BMP-StructuralCheck");

            // Extended BMP structural checks (BITMAPINFOHEADER and later, dibHeaderSize >= 40).
            if (dibHeaderSize >= 40 && bytes.Length >= 30)
            {
                ushort planes = BitConverter.ToUInt16(bytes, 26);
                if (planes != 1)
                    return RejectStructural(fileName, "BMP", $"Invalid BMP planes value ({planes}); must be 1.", "BMP-StructuralCheck");

                ushort bitsPerPixel = BitConverter.ToUInt16(bytes, 28);
                if (!ValidBmpBitsPerPixel.Contains(bitsPerPixel))
                    return RejectStructural(fileName, "BMP", $"Invalid BMP bits-per-pixel ({bitsPerPixel}).", "BMP-StructuralCheck");

                if (bytes.Length >= 34)
                {
                    uint compression = BitConverter.ToUInt32(bytes, 30);
                    // BI_RGB=0, BI_RLE8=1, BI_RLE4=2, BI_BITFIELDS=3, BI_JPEG=4, BI_PNG=5, BI_ALPHABITFIELDS=6
                    if (compression > 6)
                        return RejectStructural(fileName, "BMP", $"Invalid BMP compression method ({compression}).", "BMP-StructuralCheck");
                }
            }

            if (RunCommonThreatScans(bytes, fileName, "BMP") is { } threatResult)
                return threatResult;

            _logger.LogDebug("BMP deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("BMP-DeepScan");
        }

        // ── Centralized ImageSharp metadata validation ────────────────────────────

        /// <summary>
        /// Image.Identify() only — avoids full pixel decode and greatly reduces
        /// memory-amplification risk compared with loading the image.
        /// Note: metadata-only parsing is far safer than full decode but not
        /// categorically immune to all parser edge cases in malformed files.
        /// </summary>
        private ContentValidationResult? ValidateImageMetadata(byte[] bytes, string fileName, string fileType)
        {
            if (!_options.UseImageSharpForImages) return null;

            try
            {
                using var ms = new MemoryStream(bytes, writable: false);
                ImageInfo? info = Image.Identify(ms);

                if (info is null)
                    return RejectStructural(fileName, fileType, "Image metadata could not be identified.", $"{fileType}-StructuralCheck");

                if (info.Width < 1 || info.Height < 1)
                    return RejectStructural(fileName, fileType, "Invalid image dimensions.", $"{fileType}-StructuralCheck");

                if (info.Width > _options.MaxImageWidth || info.Height > _options.MaxImageHeight)
                    return RejectPolicy(fileName, fileType, "Image dimensions exceed allowed limits.", $"{fileType}-DimensionLimit");

                long pixelCount = (long)info.Width * info.Height;
                if (pixelCount > _options.MaxImagePixels)
                    return RejectPolicy(fileName, fileType, "Image pixel count exceeds allowed limits.", $"{fileType}-PixelLimit");

                return null;
            }
            catch
            {
                return RejectStructural(fileName, fileType, "Image failed structural validation.", $"{fileType}-StructuralCheck");
            }
        }

        // ── Common threat detection ───────────────────────────────────────────────

        /// <summary>
        /// Runs the full shared threat-scan battery: embedded shells, scripts,
        /// executables, and archive containers. Decodes Latin1 internally for
        /// pattern matching. Returns null if no threats are found.
        /// </summary>
        private ContentValidationResult? RunCommonThreatScans(
            byte[] bytes, string fileName, string fileType)
        {
            string content = Encoding.Latin1.GetString(bytes);
            return RunCommonThreatScans(bytes, content, fileName, fileType);
        }

        /// <summary>
        /// Overload accepting a pre-decoded Latin1 string to avoid redundant
        /// decoding when the caller has already produced one (e.g. PDF validator).
        /// </summary>
        private ContentValidationResult? RunCommonThreatScans(
            byte[] bytes, string content, string fileName, string fileType)
        {
            if (ContainsPhpShell(bytes, content, fileName))
                return EmbeddedShellReject(fileName, fileType);

            if (ContainsScriptContent(bytes, content, fileName))
                return EmbeddedScriptReject(fileName, fileType);

            if (ContainsEmbeddedExecutable(bytes, fileName, fileType) is { } exeResult)
                return exeResult;

            if (ContainsEmbeddedContainer(bytes, fileName, fileType) is { } containerResult)
                return containerResult;

            return null;
        }

        /// <summary>
        /// Image-specific threat scan.
        ///
        /// The text-based shell/script patterns are matched ONLY against the image's
        /// metadata/comment segments (JPEG APPn/COM, PNG tEXt/iTXt/zTXt, WebP EXIF/XMP,
        /// GIF comment/application extensions) — never against the entropy-coded pixel
        /// data. Short patterns like "&lt;?=" or "&lt;svg" occur by pure chance inside
        /// compressed pixel streams and previously false-rejected legitimate patron
        /// photos. Genuine "polyglot" payloads live in the metadata segments, so scoping
        /// the text scan there preserves detection while eliminating the false positives.
        ///
        /// Binary signature scans use the same metadata regions. Short signatures such as
        /// ELF, ZIP, and GZIP occur by chance in JPEG entropy, PNG IDAT, WebP image chunks,
        /// and Motion Photo video. Those compressed media regions are not executable
        /// contexts and are covered by the antivirus layer instead.
        /// </summary>
        private ContentValidationResult? RunImageThreatScans(
            byte[] bytes, string fileName, string fileType)
        {
            var extraction = ExtractImageMetadataRegions(bytes, fileType);
            if (extraction.Status == MetadataExtractionStatus.LimitExceeded)
                return RejectPolicy(
                    fileName, fileType,
                    "Compressed image metadata exceeds the safe inspection limit.",
                    $"{fileType}-MetadataLimitExceeded");

            if (extraction.Status == MetadataExtractionStatus.Malformed)
                return RejectStructural(
                    fileName, fileType,
                    "Compressed image metadata is malformed and could not be fully inspected.",
                    $"{fileType}-MetadataMalformed");

            byte[] metadata = extraction.Metadata;
            if (metadata.Length > 0)
            {
                string metaContent = Encoding.Latin1.GetString(metadata);

                if (ContainsPhpShell(metadata, metaContent, fileName))
                    return EmbeddedShellReject(fileName, fileType);

                if (ContainsScriptContent(metadata, metaContent, fileName))
                    return EmbeddedScriptReject(fileName, fileType);

                if (ContainsEmbeddedExecutable(metadata, fileName, fileType, scanStart: 0) is { } exeResult)
                    return exeResult;

                if (ContainsEmbeddedContainer(metadata, fileName, fileType, scanStart: 0) is { } containerResult)
                    return containerResult;
            }

            return null;
        }

        // ── Image metadata/comment region extraction ──────────────────────────────
        //
        // Returns only the bytes of text-bearing metadata segments for an image so the
        // shell/script text scan never inspects entropy-coded pixel data. Formats with
        // no text metadata container (e.g. BMP) return an empty array, which skips the
        // text scan entirely (binary signature scans still run on the full buffer).

        private static (byte[] Metadata, MetadataExtractionStatus Status) ExtractImageMetadataRegions(
            byte[] bytes, string fileType) =>
            fileType switch
            {
                "JPEG" => (ExtractJpegMetadataRegions(bytes), MetadataExtractionStatus.Complete),
                "PNG"  => ExtractPngMetadataRegions(bytes),
                "WEBP" => (ExtractWebpMetadataRegions(bytes), MetadataExtractionStatus.Complete),
                "GIF"  => (ExtractGifMetadataRegions(bytes), MetadataExtractionStatus.Complete),
                _       => (Array.Empty<byte>(), MetadataExtractionStatus.Complete),
            };

        /// <summary>
        /// Collects the payloads of JPEG APPn (0xE0–0xEF) and COM (0xFE) segments.
        /// Stops at SOS (0xDA) or EOI (0xD9) — everything from SOS onward is
        /// entropy-coded pixel data and is never text-scanned.
        /// </summary>
        private static byte[] ExtractJpegMetadataRegions(byte[] bytes)
        {
            using var ms = new MemoryStream();
            int offset = 2; // after SOI (FF D8)

            while (offset + 3 < bytes.Length)
            {
                if (bytes[offset] != 0xFF) break;

                // Skip FF padding before the real marker byte.
                while (offset + 1 < bytes.Length && bytes[offset + 1] == 0xFF)
                    offset++;
                if (offset + 1 >= bytes.Length) break;

                byte marker = bytes[offset + 1];

                if (marker == 0xDA || marker == 0xD9) break; // SOS or EOI

                if (StandaloneJpegMarkers.Contains(marker))
                {
                    offset += 2;
                    continue;
                }

                if (offset + 3 >= bytes.Length) break;

                int segmentLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
                if (segmentLength < 2) break;

                long segmentEnd = (long)offset + 2 + segmentLength;
                if (segmentEnd > bytes.Length) break;

                // APPn (0xE0–0xEF) and COM (0xFE) carry text metadata (EXIF, XMP, comments).
                if ((marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE)
                {
                    int dataStart = offset + 4;
                    int dataLen   = segmentLength - 2;
                    // Each APPn/COM segment is written as its own delimited region so a
                    // pattern cannot be synthesized across two unrelated segments.
                    AppendMetadataRegion(ms, bytes, dataStart, dataLen);
                }

                offset = (int)segmentEnd;
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Collects the text of PNG text chunks (tEXt, iTXt, zTXt). Stops at IEND.
        ///
        /// SECURITY — zTXt is always zlib-compressed and iTXt is compressed when its
        /// compression flag is set. Scanning those raw bytes as Latin-1 can never match a
        /// pattern, so a payload placed in a compressed text chunk was previously invisible
        /// to the threat scan. Compressed chunks are therefore inflated here, with hard
        /// bounds on both per-chunk and total output to prevent a decompression bomb from
        /// turning metadata extraction into a memory-exhaustion vector. The returned status
        /// distinguishes a complete scan from malformed or truncated metadata so callers can
        /// fail closed rather than trusting a partially inspected image.
        ///
        /// Each chunk's text is written as its own region (see AppendMetadataRegion) so a
        /// pattern cannot be synthesized across the boundary between two unrelated chunks.
        /// </summary>
        private static (byte[] Metadata, MetadataExtractionStatus Status) ExtractPngMetadataRegions(
            byte[] bytes)
        {
            using var ms = new MemoryStream();
            int offset = 8; // after PNG signature
            int totalDecompressed = 0;

            while (offset + 12 <= bytes.Length)
            {
                uint chunkLength = ReadUInt32BigEndian(bytes, offset);
                if (chunkLength > int.MaxValue) break;

                int totalChunkSize = (int)chunkLength + 12;
                if (offset + totalChunkSize > bytes.Length) break;

                int dataStart = offset + 8;
                int dataLen = (int)chunkLength;

                if (dataLen > 0)
                {
                    if (AsciiEquals(bytes, offset + 4, "tEXt"))
                    {
                        // Uncompressed: keyword \0 text
                        AppendMetadataRegion(ms, bytes, dataStart, dataLen);
                    }
                    else if (AsciiEquals(bytes, offset + 4, "zTXt"))
                    {
                        // keyword \0 compressionMethod compressedText
                        int sep = IndexOfByte(bytes, 0x00, dataStart, dataLen);
                        int dataEnd = dataStart + dataLen;
                        if (sep <= dataStart || sep - dataStart > 79 ||
                            sep + 2 > dataEnd || bytes[sep + 1] != 0)
                            return (ms.ToArray(), MetadataExtractionStatus.Malformed);

                        int compStart = sep + 2; // skip separator + compression method
                        int compLen = dataEnd - compStart;
                        var status = AppendInflated(
                            ms, bytes, compStart, compLen, ref totalDecompressed);
                        if (status != MetadataExtractionStatus.Complete)
                            return (ms.ToArray(), status);
                    }
                    else if (AsciiEquals(bytes, offset + 4, "iTXt"))
                    {
                        // keyword \0 compressionFlag compressionMethod langTag \0 translatedKeyword \0 text
                        int sep = IndexOfByte(bytes, 0x00, dataStart, dataLen);
                        int dataEnd = dataStart + dataLen;
                        if (sep <= dataStart || sep - dataStart > 79 || sep + 3 > dataEnd)
                            return (ms.ToArray(), MetadataExtractionStatus.Malformed);

                        byte compressionFlag = bytes[sep + 1];
                        byte compressionMethod = bytes[sep + 2];
                        if (compressionFlag > 1 || compressionMethod != 0)
                            return (ms.ToArray(), MetadataExtractionStatus.Malformed);

                        int langStart = sep + 3;
                        int langEnd = IndexOfByte(bytes, 0x00, langStart, dataEnd - langStart);
                        int transEnd = langEnd >= 0
                            ? IndexOfByte(bytes, 0x00, langEnd + 1, dataEnd - langEnd - 1)
                            : -1;

                        if (langEnd < 0 || transEnd < 0)
                            return (ms.ToArray(), MetadataExtractionStatus.Malformed);

                        int textStart = transEnd + 1;
                        int textLen = dataEnd - textStart;
                        if (compressionFlag == 0)
                        {
                            AppendMetadataRegion(ms, bytes, textStart, textLen);
                        }
                        else
                        {
                            var status = AppendInflated(
                                ms, bytes, textStart, textLen, ref totalDecompressed);
                            if (status != MetadataExtractionStatus.Complete)
                                return (ms.ToArray(), status);
                        }
                    }
                }

                if (AsciiEquals(bytes, offset + 4, "IEND")) break;

                offset += totalChunkSize;
            }

            return (ms.ToArray(), MetadataExtractionStatus.Complete);
        }

        /// <summary>
        /// Writes one logical metadata region followed by a non-printable delimiter.
        ///
        /// SECURITY — regions were previously concatenated directly, which allowed a pattern
        /// to be synthesized across the boundary of two unrelated segments: one ending in
        /// "&lt;?" and the next beginning with "php" produced a "&lt;?php" match that exists in
        /// neither. The 0x00 delimiter breaks the printable run, so IsTextContext also sees
        /// the regions as distinct.
        /// </summary>
        private static void AppendMetadataRegion(MemoryStream ms, byte[] source, int offset, int length)
        {
            if (length <= 0) return;
            if (offset < 0 || offset + length > source.Length) return;

            ms.Write(source, offset, length);
            ms.WriteByte(0x00);
        }

        /// <summary>
        /// Inflates a zlib-compressed metadata region with hard output bounds, appending the
        /// result only after the complete stream has been inspected. One additional read at
        /// the budget boundary distinguishes an exact-size stream from truncated scanning.
        /// </summary>
        private static MetadataExtractionStatus AppendInflated(
            MemoryStream ms, byte[] source, int offset, int length, ref int totalDecompressed)
        {
            if (length <= 0 || offset < 0 || (long)offset + length > source.Length)
                return MetadataExtractionStatus.Malformed;

            try
            {
                using var input = new MemoryStream(source, offset, length, writable: false);
                using var inflater = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();

                int budget = Math.Min(
                    MaxDecompressedMetadataBytesPerChunk,
                    MaxTotalDecompressedMetadataBytes - totalDecompressed);

                byte[] buffer = new byte[8192];
                while (output.Length < budget)
                {
                    int requested = Math.Min(buffer.Length, budget - (int)output.Length);
                    int read = inflater.Read(buffer, 0, requested);
                    if (read == 0)
                        break;

                    output.Write(buffer, 0, read);
                }

                if (output.Length == budget && inflater.ReadByte() != -1)
                    return MetadataExtractionStatus.LimitExceeded;

                if (output.Length == 0)
                    return MetadataExtractionStatus.Complete;

                totalDecompressed += (int)output.Length;
                byte[] inflated = output.ToArray();
                ms.Write(inflated, 0, inflated.Length);
                ms.WriteByte(0x00);
                return MetadataExtractionStatus.Complete;
            }
            catch (InvalidDataException)
            {
                return MetadataExtractionStatus.Malformed;
            }
            catch (NotSupportedException)
            {
                return MetadataExtractionStatus.Malformed;
            }
        }

        /// <summary>Returns the index of the first <paramref name="value"/> byte in the range, or -1.</summary>
        private static int IndexOfByte(byte[] bytes, byte value, int start, int count)
        {
            if (start < 0 || count <= 0) return -1;
            int end = Math.Min(bytes.Length, start + count);
            for (int i = start; i < end; i++)
                if (bytes[i] == value) return i;
            return -1;
        }

        /// <summary>
        /// Collects the payloads of WebP EXIF and XMP chunks from the RIFF tree.
        /// </summary>
        private static byte[] ExtractWebpMetadataRegions(byte[] bytes)
        {
            using var ms = new MemoryStream();
            int offset = 12; // after RIFF....WEBP

            while (offset + 8 <= bytes.Length)
            {
                uint chunkSize = BitConverter.ToUInt32(bytes, offset + 4);
                long dataEnd   = offset + 8L + chunkSize;
                if (dataEnd > bytes.Length) break;

                if (AsciiEquals(bytes, offset, "EXIF") || AsciiEquals(bytes, offset, "XMP "))
                {
                    if (chunkSize > 0 && chunkSize <= int.MaxValue)
                        AppendMetadataRegion(ms, bytes, offset + 8, (int)chunkSize);
                }

                offset = (int)dataEnd;
                if ((chunkSize & 1) == 1) offset++; // RIFF odd-byte padding
                if (offset < 0) break;
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Collects the sub-block data of GIF comment (0xFE) and application (0xFF)
        /// extension blocks. Image data and color tables are skipped.
        /// </summary>
        private static byte[] ExtractGifMetadataRegions(byte[] bytes)
        {
            if (bytes.Length < 13) return Array.Empty<byte>();

            using var ms = new MemoryStream();

            byte packed = bytes[10];
            int offset = 13;
            if ((packed & 0x80) != 0)
                offset += 3 * (1 << ((packed & 0x07) + 1)); // global color table

            while (offset < bytes.Length)
            {
                byte introducer = bytes[offset];

                if (introducer == 0x3B) break; // trailer

                if (introducer == 0x2C) // image descriptor
                {
                    if (offset + 10 > bytes.Length) break;
                    byte imgPacked = bytes[offset + 9];
                    offset += 10;
                    if ((imgPacked & 0x80) != 0)
                        offset += 3 * (1 << ((imgPacked & 0x07) + 1)); // local color table
                    if (offset >= bytes.Length) break;
                    offset++; // LZW minimum code size
                    if (!CollectGifSubBlocks(bytes, ref offset, null)) break;
                }
                else if (introducer == 0x21) // extension
                {
                    if (offset + 2 > bytes.Length) break;
                    byte label = bytes[offset + 1];
                    offset += 2;
                    bool isTextExtension = label == 0xFE || label == 0xFF; // comment or application
                    if (!CollectGifSubBlocks(bytes, ref offset, isTextExtension ? ms : null)) break;
                }
                else break;
            }

            return ms.ToArray();
        }

        /// <summary>
        /// Walks a GIF sub-block chain (terminated by a zero-length sub-block),
        /// optionally copying each sub-block's bytes into <paramref name="sink"/>.
        /// Returns false on a malformed/truncated chain.
        /// </summary>
        private static bool CollectGifSubBlocks(byte[] bytes, ref int offset, MemoryStream? sink)
        {
            while (offset < bytes.Length)
            {
                byte blockSize = bytes[offset];
                offset++;
                if (blockSize == 0) return true; // block terminator
                if (offset + blockSize > bytes.Length) return false;
                sink?.Write(bytes, offset, blockSize);
                offset += blockSize;
            }
            return false;
        }

        // ── Per-pattern threat helpers ─────────────────────────────────────────────

        // SECURITY — both scanners below iterate EVERY occurrence of each pattern. Checking
        // only the first was exploitable: a short decoy that fails the printable-run gate
        // (e.g. a bare "<?php" alone in one metadata region) caused the scanner to abandon
        // that pattern entirely, so a real payload in a later region went unexamined. The
        // gate is a coincidence filter, not a verdict — a failed match must advance the
        // search, not end it.

        private bool ContainsPhpShell(byte[] bytes, string content, string fileName)
        {
            foreach (string p in PhpShellPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (IsTextContext(bytes, idx, p.Length))
                    {
                        _logger.LogWarning(
                            "SECURITY_EVENT | EMBEDDED_SHELL | FileName: {FileName} | Pattern: {Pattern}",
                            fileName, p);
                        return true;
                    }

                    LogNearMiss("SHELL", fileName, p, idx);
                    idx += Math.Max(1, p.Length);
                }
            }
            return false;
        }

        private bool ContainsScriptContent(byte[] bytes, string content, string fileName)
        {
            foreach (string p in ScriptContentPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (IsTextContext(bytes, idx, p.Length))
                    {
                        _logger.LogWarning(
                            "SECURITY_EVENT | EMBEDDED_SCRIPT | FileName: {FileName} | Pattern: {Pattern}",
                            fileName, p);
                        return true;
                    }

                    LogNearMiss("SCRIPT", fileName, p, idx);
                    idx += Math.Max(1, p.Length);
                }
            }

            return ContainsInlineEventHandler(bytes, content, fileName);
        }

        /// <summary>
        /// Detects inline event handlers (onload=, onerror=, ...) but only when the match
        /// sits inside what is plausibly a markup tag — i.e. an unclosed '&lt;' appears within
        /// <see cref="InlineHandlerTagLookbehind"/> bytes before it. A bare "onload=" in an
        /// XMP attribute name or a free-text caption is not markup and is not a threat.
        /// </summary>
        private bool ContainsInlineEventHandler(byte[] bytes, string content, string fileName)
        {
            foreach (string p in InlineEventHandlerPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (IsTextContext(bytes, idx, p.Length) && IsInsideMarkupTag(content, idx))
                    {
                        _logger.LogWarning(
                            "SECURITY_EVENT | EMBEDDED_SCRIPT | FileName: {FileName} | Pattern: {Pattern} | " +
                            "Context: inline event handler inside markup tag",
                            fileName, p);
                        return true;
                    }

                    LogNearMiss("HANDLER", fileName, p, idx);
                    idx += p.Length;
                }
            }
            return false;
        }

        /// <summary>
        /// Returns true when the offset appears to sit within an open markup tag: scanning
        /// backwards, a '&lt;' is found before any '&gt;' that would have closed it.
        /// </summary>
        private static bool IsInsideMarkupTag(string content, int offset)
        {
            int start = Math.Max(0, offset - InlineHandlerTagLookbehind);
            for (int i = offset - 1; i >= start; i--)
            {
                char c = content[i];
                if (c == '>') return false; // previous tag already closed
                if (c == '<') return true;  // still inside an open tag
            }
            return false;
        }

        /// <summary>
        /// Records a pattern that matched textually but was rejected by the context gates.
        /// These are logged at Information (not Warning) so they never look like incidents.
        ///
        /// Purpose: every false-positive incident this pipeline has produced began as a
        /// near miss that nobody could see until a patron upload failed. Querying
        /// VALIDATION_NEAR_MISS by Pattern shows which token is trending toward the next
        /// false rejection BEFORE it causes one.
        /// </summary>
        private void LogNearMiss(string scan, string fileName, string pattern, int offset)
        {
            _logger.LogInformation(
                "VALIDATION_NEAR_MISS | Scan: {Scan} | FileName: {FileName} | Pattern: {Pattern} | " +
                "Offset: {Offset} | Matched textually but failed context gate; file NOT rejected",
                scan, fileName, pattern, offset);
        }

        /// <summary>
        /// Scans for embedded executable signatures (PE, ELF, Mach-O, OLE).
        /// These are always classified as Malicious — there is no legitimate reason
        /// for an executable to be embedded inside a patron-submitted image or PDF.
        /// </summary>
        private ContentValidationResult? ContainsEmbeddedExecutable(
            byte[] bytes,
            string fileName,
            string fileType,
            int scanStart = 16,
            bool requireStructuralConfirmation = false)
        {
            foreach ((byte[] sig, string desc) in DangerousExecutableSignatures)
            {
                bool isPeSignature = sig.Length == 2 && sig[0] == 0x4D && sig[1] == 0x5A;
                if (requireStructuralConfirmation && !isPeSignature)
                    continue;

                // Iterate ALL occurrences. Previously only the first was examined: if that
                // one failed its secondary structural check the loop moved to the next
                // signature, so a genuine PE located after a coincidental MZ byte pair was
                // never found. Short signatures occur by chance in compressed data, which
                // makes a decoy first occurrence trivial to arrange.
                int offset = FindBytes(bytes, sig, scanStart);
                while (offset >= scanStart)
                {
                    bool confirmed = true;

                    // MZ (2 bytes) — validate PE\0\0 pointer to avoid false positives.
                    if (isPeSignature)
                        confirmed = IsProbablyPeExecutable(bytes, offset);

                    if (confirmed)
                    {
                        LogWithHexSnippet($"SECURITY_EVENT | EMBEDDED_EXECUTABLE | {fileType}", fileName, desc, bytes, offset);
                        return RejectMalicious(
                            fileName, fileType,
                            $"Embedded {desc} detected at offset {offset}.",
                            $"{fileType}-EmbeddedExecutable");
                    }

                    if (offset + 1 >= bytes.Length) break;
                    offset = FindBytes(bytes, sig, offset + 1);
                }
            }
            return null;
        }

        /// <summary>
        /// Scans for embedded archive/container signatures (ZIP, RAR, 7z, GZIP).
        /// Classified as Policy rejection — these can occasionally appear in legitimate
        /// image metadata or comment areas but are disallowed by upload policy.
        /// </summary>
        private ContentValidationResult? ContainsEmbeddedContainer(
            byte[] bytes, string fileName, string fileType, int scanStart = 16)
        {
            foreach ((byte[] sig, string desc) in PolicyContainerSignatures)
            {
                // Iterate ALL occurrences — see ContainsEmbeddedExecutable. The GZIP check
                // below is only a flags-range test, so a coincidental first hit previously
                // masked any real container later in the buffer.
                int offset = FindBytes(bytes, sig, scanStart);
                while (offset >= scanStart)
                {
                    bool confirmed = true;

                    // GZIP (3 bytes) — validate flags byte is in 0-31 range to reduce false positives.
                    if (sig.Length == 3 && sig[0] == 0x1F && sig[1] == 0x8B)
                        confirmed = offset + 3 < bytes.Length && bytes[offset + 3] <= 0x1F;

                    if (confirmed)
                    {
                        LogWithHexSnippet($"SECURITY_EVENT | EMBEDDED_CONTAINER | {fileType}", fileName, desc, bytes, offset);
                        return RejectPolicy(
                            fileName, fileType,
                            $"Embedded {desc} detected at offset {offset}. Embedded containers are not permitted.",
                            $"{fileType}-EmbeddedContainer");
                    }

                    if (offset + 1 >= bytes.Length) break;
                    offset = FindBytes(bytes, sig, offset + 1);
                }
            }
            return null;
        }

        // ── Format-specific structural validators ─────────────────────────────────

        /// <summary>
        /// Locates the JPEG's TRUE end-of-image by walking the file structurally rather
        /// than searching for the FF D9 byte pair.
        ///
        /// SECURITY — this replaces a backward "is there an FF D9 anywhere" scan. That
        /// earlier check accepted any file containing the byte pair somewhere, which meant
        /// a structurally valid JPEG with an arbitrary payload appended after EOI passed
        /// validation: the segment walker stops at SOS, and the metadata extractor stops at
        /// SOS/EOI, so nothing ever examined the appended bytes. A shell appended after EOI
        /// was therefore invisible to the text scan. Knowing where the image genuinely ends
        /// is what makes the trailing region scannable (see ValidateJpeg).
        ///
        /// Walking the entropy-coded scan requires respecting two JPEG rules:
        ///   • Byte stuffing: a literal 0xFF in compressed data is encoded as FF 00, so
        ///     FF 00 is data and not a marker.
        ///   • Restart markers: FF D0–FF D7 appear inside the scan and are not terminators.
        /// Multi-scan (progressive) JPEGs contain several SOS segments; each is walked in
        /// turn until EOI is reached.
        /// </summary>
        /// <returns>
        /// The offset just past the terminating FF D9, or -1 when no valid EOI is found.
        /// </returns>
        private static int FindJpegEndOfImage(byte[] bytes)
        {
            if (bytes.Length < 4) return -1;
            if (bytes[0] != 0xFF || bytes[1] != 0xD8) return -1;

            int offset = 2;

            while (offset + 1 < bytes.Length)
            {
                if (bytes[offset] != 0xFF) return -1;

                // Skip fill bytes (a marker may be preceded by any number of 0xFF).
                while (offset + 1 < bytes.Length && bytes[offset + 1] == 0xFF)
                    offset++;
                if (offset + 1 >= bytes.Length) return -1;

                byte marker = bytes[offset + 1];

                if (marker == 0xD9)
                    return offset + 2;                    // EOI — true end of image

                if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7))
                {
                    offset += 2;                          // standalone marker, no payload
                    continue;
                }

                if (offset + 3 >= bytes.Length) return -1;

                int segmentLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
                if (segmentLength < 2) return -1;

                long segmentEnd = (long)offset + 2 + segmentLength;
                if (segmentEnd > bytes.Length) return -1;

                if (marker == 0xDA)
                {
                    // Start of Scan: entropy-coded data follows the header. Walk it,
                    // honoring byte stuffing (FF 00) and restart markers (FF D0-FF D7).
                    int scan = (int)segmentEnd;
                    while (scan + 1 < bytes.Length)
                    {
                        if (bytes[scan] != 0xFF) { scan++; continue; }

                        byte next = bytes[scan + 1];

                        if (next == 0x00) { scan += 2; continue; }          // stuffed literal FF
                        if (next == 0xFF) { scan++;    continue; }          // fill byte
                        if (next >= 0xD0 && next <= 0xD7) { scan += 2; continue; } // restart

                        break;                                             // real marker reached
                    }

                    if (scan + 1 >= bytes.Length) return -1;
                    offset = scan;                                         // resume marker walk
                    continue;
                }

                offset = (int)segmentEnd;
            }

            return -1;
        }

        /// <summary>
        /// Validates bytes that follow the JPEG's true EOI.
        ///
        /// EVERY post-EOI byte is scanned. That is the security win here: before the true end
        /// of image was known, appended data was never examined at all, so a shell appended
        /// after EOI passed validation untouched.
        ///
        /// Structural recognition (ISO-BMFF box walk) is used only to classify the trailer for
        /// LOGGING — never to exempt it from inspection, and never as an allowlist gate.
        ///
        /// FALSE-POSITIVE NOTE — an earlier revision rejected any trailer that was not a
        /// byte-exact ISO-BMFF chain. That rejected ordinary phone output: MPF files (a second
        /// full JPEG appended after EOI — Samsung, Sony, Fujifilm), Samsung Motion Photos
        /// (MP4 followed by an SEF footer/index, which the box chain cannot account for), and
        /// plain alignment padding. Those are the most common trailers in the wild, so the
        /// allowlist rejected far more legitimate photos than it could ever have caught
        /// payloads. Detection now comes from scanning the bytes, which is what actually
        /// distinguishes a payload from a video track.
        /// </summary>
        private ContentValidationResult? ValidateJpegTrailingData(byte[] bytes, int endOfImage, string fileName)
        {
            int trailingLength = bytes.Length - endOfImage;
            if (trailingLength <= 0) return null;

            // Tolerate a small run of padding/alignment filler.
            if (trailingLength <= MaxIgnorableJpegTrailingBytes)
            {
                bool onlyFiller = true;
                for (int i = endOfImage; i < bytes.Length; i++)
                {
                    byte b = bytes[i];
                    if (b != 0x00 && b != 0xFF && b != 0x20 && b != 0x0A && b != 0x0D)
                    {
                        onlyFiller = false;
                        break;
                    }
                }
                if (onlyFiller) return null;
            }

            var trailing = new byte[trailingLength];
            Buffer.BlockCopy(bytes, endOfImage, trailing, 0, trailingLength);

            // Classify the trailer for logging only. A valid ISO-BMFF chain (Motion Photo /
            // Live Photo) proves that every byte is ACCOUNTED FOR by a declared box; it says
            // nothing whatsoever about what those bytes contain — a payload fits inside a
            // correctly sized mdat just as well as a video track does. Recognition therefore
            // never short-circuits the scan below, and non-recognition never rejects.
            if (IsValidIsoBmffTrailer(trailing))
            {
                _logger.LogInformation(
                    "JPEG_TRAILING_MOTION_PHOTO | FileName: {FileName} | TrailingBytes: {Bytes} | " +
                    "Structurally valid ISO-BMFF container after EOI; scanning contents",
                    fileName, trailingLength);
            }
            else
            {
                // Unrecognized trailers are routine (MPF second image, Samsung SEF footer,
                // maker notes, padding). Logged so the mix is measurable, then scanned like
                // any other trailer.
                _logger.LogInformation(
                    "JPEG_TRAILING_UNRECOGNIZED | FileName: {FileName} | TrailingBytes: {Bytes} | " +
                    "Data after EOI is not a recognized container; scanning contents",
                    fileName, trailingLength);
            }

            // Scan the trailer regardless of how it was classified.
            string trailingText = Encoding.Latin1.GetString(trailing);

            // A length-proportionate context gate is applied (see HasTrailingTextContext).
            // The metadata gate's Math.Max(MinTextContextRun, pattern.Length + 8) is too
            // strict for this region — a 13-character "#!/bin/bash\nx" would need 19
            // printable characters and slip through — while no gate at all lets the
            // four-byte "<svg" token fire on the effectively-random bytes of MP4 video data.
            if (ContainsTrailingRegionThreatPattern(trailing, trailingText, fileName, out string? matched, out string? scanKind))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | EMBEDDED_{Kind} | FileName: {FileName} | Pattern: {Pattern} | " +
                    "Context: data appended after JPEG EOI",
                    scanKind, fileName, matched);

                return scanKind == "SHELL"
                    ? EmbeddedShellReject(fileName, "JPEG")
                    : EmbeddedScriptReject(fileName, "JPEG");
            }

            return null;
        }

        /// <summary>
        /// Matches shell/script patterns in a JPEG's post-EOI region. Uses a
        /// LENGTH-PROPORTIONATE printable-run gate rather than the
        /// metadata path's Math.Max(MinTextContextRun, pattern.Length + 8).
        ///
        /// Two failure modes are being avoided at once. The metadata gate is too strict
        /// here: it demands 19 printable characters for "#!/bin/bash", so a 13-character
        /// shebang payload appended after EOI would not register. But scanning with no gate
        /// at all is too loose: the shortest pattern, "&lt;svg", is four bytes and matched
        /// roughly one in three thousand 20 KB random binary trailers in testing — Motion
        /// Photo video data is effectively random, so that becomes a recurring false
        /// rejection of ordinary phone photos.
        ///
        /// Requiring a printable run of at least <see cref="MinTrailingTextContextRun"/>
        /// (or the pattern's own length, whichever is greater) separates the two cleanly:
        /// every real payload tested still registers, and the coincidental binary matches
        /// disappear.
        ///
        /// Inline event handlers additionally require markup context, since a bare
        /// "onload=" is ambiguous in any region.
        /// </summary>
        private bool ContainsTrailingRegionThreatPattern(
            byte[] region, string content, string fileName, out string? matchedPattern, out string? scanKind)
        {
            foreach (string p in PhpShellPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (HasTrailingTextContext(region, idx, p.Length))
                    {
                        matchedPattern = p;
                        scanKind = "SHELL";
                        return true;
                    }
                    idx += Math.Max(1, p.Length);
                }
            }

            foreach (string p in ScriptContentPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (HasTrailingTextContext(region, idx, p.Length))
                    {
                        matchedPattern = p;
                        scanKind = "SCRIPT";
                        return true;
                    }
                    idx += Math.Max(1, p.Length);
                }
            }

            foreach (string p in InlineEventHandlerPatterns)
            {
                int idx = 0;
                while ((idx = content.IndexOf(p, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    if (HasTrailingTextContext(region, idx, p.Length) && IsInsideMarkupTag(content, idx))
                    {
                        matchedPattern = p;
                        scanKind = "SCRIPT";
                        return true;
                    }
                    idx += p.Length;
                }
            }

            matchedPattern = null;
            scanKind = null;
            return false;
        }

        /// <summary>
        /// Length-proportionate printable-run check for non-image regions. Unlike
        /// IsTextContext this adds no fixed trailing window, so short interpreter shebangs
        /// still register while four-byte tokens in random binary do not.
        /// </summary>
        private static bool HasTrailingTextContext(byte[] bytes, int offset, int length)
        {
            if (offset < 0 || offset >= bytes.Length) return false;

            int start = offset;
            while (start > 0 && IsPrintableTextByte(bytes[start - 1]))
                start--;

            int end = Math.Min(bytes.Length, offset + length);
            while (end < bytes.Length && IsPrintableTextByte(bytes[end]))
                end++;

            return (end - start) >= Math.Max(MinTrailingTextContextRun, length);
        }

        /// <summary>
        /// Validates that a JPEG trailer is a structurally sound ISO-BMFF (MP4) container, as
        /// produced by Motion Photo / Live Photo cameras.
        ///
        /// The box chain must account for the trailer EXACTLY — the first box must be
        /// <c>ftyp</c>, every box must declare a size that fits within the remaining bytes,
        /// and the walk must finish precisely at the end. Any leftover byte means the
        /// container does not explain the whole trailer, which is the condition an attacker
        /// needs in order to append a payload behind a forged header.
        ///
        /// Box sizes handled:
        ///   • size ≥ 8   normal box
        ///   • size == 1  64-bit extended size in the 8 bytes following the type
        ///   • size == 0  box extends to end of data (valid only as the final box)
        ///   • size &lt; 8 (and not 0/1) is malformed
        ///
        /// This deliberately does not decode video data; it only proves the byte ranges are
        /// accounted for. Verification, not interpretation.
        /// </summary>
        private static bool IsValidIsoBmffTrailer(byte[] trailer)
        {
            const int minBoxHeader = 8;

            if (trailer.Length < 12) return false;

            long offset = 0;
            bool firstBox = true;
            long firstBoxOffset = -1;

            while (offset < trailer.Length)
            {
                if (offset + minBoxHeader > trailer.Length) return false;

                long boxSize = ReadUInt32BigEndian(trailer, (int)offset);
                long headerSize = minBoxHeader;

                // Box type must be four printable ASCII characters. Without this, a size-0
                // box with a null type (00 00 00 00) is treated as "extends to end of data"
                // and silently accounts for an arbitrary payload — reopening the same free
                // space the box walk exists to eliminate.
                if (!IsPlausibleIsoBmffBoxType(trailer, (int)offset + 4)) return false;

                // The first box must be "ftyp" and must be a well-formed file-type box.
                if (firstBox)
                {
                    if (!AsciiEquals(trailer, (int)offset + 4, "ftyp")) return false;

                    // Size-zero ("extends to end of data") is rejected for ftyp: a real
                    // file-type box has a known, small size, and allowing it here lets a
                    // single box legitimately claim the entire trailer as its contents.
                    if (boxSize == 0) return false;

                    // Ordinary ftyp needs 8 header + 4 major brand + 4 minor version.
                    if (boxSize != 1 && boxSize < 16) return false;

                    firstBox = false;
                    firstBoxOffset = offset;
                }

                if (boxSize == 1)
                {
                    // 64-bit extended size follows the box type.
                    if (offset + 16 > trailer.Length) return false;

                    boxSize = 0;
                    for (int i = 0; i < 8; i++)
                        boxSize = (boxSize << 8) | trailer[offset + 8 + i];

                    headerSize = 16;

                    if (boxSize < headerSize) return false;          // malformed / overflow
                }
                else if (boxSize == 0)
                {
                    // Extends to end of data — only legal as the final box.
                    return offset + headerSize <= trailer.Length;
                }
                else if (boxSize < minBoxHeader)
                {
                    return false;                                    // impossible box size
                }

                long boxEnd = offset + boxSize;
                if (boxEnd <= offset) return false;                  // overflow / no progress
                if (boxEnd > trailer.Length) return false;           // extends past trailer

                // ftyp payload after major brand + minor version is a list of 4-byte
                // compatible brands. A remainder that is not a multiple of four means
                // arbitrary data was appended inside an otherwise well-sized box.
                if (firstBoxOffset == offset)
                {
                    long brandArea = boxEnd - (offset + headerSize + 8);
                    if (brandArea < 0 || brandArea % 4 != 0) return false;
                    firstBoxOffset = -1;
                }

                offset = boxEnd;
            }

            // The chain must consume the trailer exactly — no unexplained bytes.
            return offset == trailer.Length;
        }

        /// <summary>
        /// ISO-BMFF box types are four printable ASCII characters (e.g. ftyp, moov, mdat,
        /// free, skip). Requiring that prevents zero-filled or random bytes from being read
        /// as a legitimate box header.
        /// </summary>
        private static bool IsPlausibleIsoBmffBoxType(byte[] bytes, int offset)
        {
            if (offset < 0 || offset + 4 > bytes.Length) return false;

            for (int i = 0; i < 4; i++)
            {
                byte b = bytes[offset + i];
                bool printable = (b >= 0x20 && b <= 0x7E);
                if (!printable) return false;
            }
            return true;
        }

        /// <summary>
        /// Walks JPEG segments from SOI through SOS, validating marker types and
        /// declared segment lengths. Stops at SOS (0xDA) since entropy-coded data
        /// follows and cannot be structurally walked without a full entropy decoder.
        /// Rejects impossible segment structures (zero-length, overlapping, unknown markers).
        /// </summary>
        private static bool ValidateJpegSegmentLayout(byte[] bytes)
        {
            if (bytes.Length < 4) return false;

            // Start after SOI (FF D8) at offset 2.
            int offset = 2;

            while (offset + 1 < bytes.Length)
            {
                // Every segment begins with FF.
                if (bytes[offset] != 0xFF) return false;

                // Skip any FF padding bytes (consecutive 0xFF before a real marker byte).
                while (offset + 1 < bytes.Length && bytes[offset + 1] == 0xFF)
                    offset++;

                if (offset + 1 >= bytes.Length) return false;

                byte marker = bytes[offset + 1];

                // FF 00 is a stuffed byte inside entropy data — should not appear
                // before SOS in a well-formed file, but tolerate gracefully.
                if (marker == 0x00) return false;

                // SOS (0xDA) — entropy-coded data follows; stop walking.
                if (marker == 0xDA) return true;

                // EOI (0xD9) — end of image; valid to encounter.
                if (marker == 0xD9) return true;

                // Standalone markers (RST, SOI, TEM) — no length field.
                if (StandaloneJpegMarkers.Contains(marker))
                {
                    offset += 2;
                    continue;
                }

                // All other markers carry a 2-byte big-endian length (includes the 2 length bytes).
                if (offset + 3 >= bytes.Length) return false;

                int segmentLength = (bytes[offset + 2] << 8) | bytes[offset + 3];

                // Minimum segment length is 2 (the length field itself).
                if (segmentLength < 2) return false;

                // Validate segment doesn't overflow the file.
                long segmentEnd = (long)offset + 2 + segmentLength;
                if (segmentEnd > bytes.Length) return false;

                offset = (int)segmentEnd;
            }

            // Ran out of bytes without finding SOS or EOI — structurally incomplete.
            return false;
        }

        /// <summary>
        /// Walks the PNG chunk tree. Validates IHDR position and length, IEND
        /// terminator, and that all chunk boundaries are internally consistent.
        /// Uses zero-allocation big-endian reads and AsciiEquals comparisons —
        /// no per-chunk string allocations.
        /// </summary>
        private static bool ValidatePngChunkLayout(byte[] bytes)
        {
            int  offset  = 8;
            bool sawIhdr = false;

            while (offset + 12 <= bytes.Length)
            {
                // PNG chunk length is big-endian — zero-allocation read.
                uint chunkLength = ReadUInt32BigEndian(bytes, offset);

                if (chunkLength > int.MaxValue) return false;

                int totalChunkSize = checked((int)chunkLength + 12);
                if (offset + totalChunkSize > bytes.Length) return false;

                // FIX: Use AsciiEquals instead of Encoding.ASCII.GetString to
                // avoid per-chunk string allocations inside the walk loop.
                if (AsciiEquals(bytes, offset + 4, "IHDR"))
                {
                    if (offset != 8 || chunkLength != 13) return false;
                    sawIhdr = true;
                }

                if (AsciiEquals(bytes, offset + 4, "IEND"))
                {
                    if (chunkLength != 0) return false;
                    // IEND must be the final chunk — no bytes may follow it.
                    return offset + totalChunkSize == bytes.Length && sawIhdr;
                }

                offset += totalChunkSize;
            }

            return false; // No IEND found.
        }

        /// <summary>
        /// Walks the WebP RIFF chunk tree from offset 12.
        /// Validates chunk type characters and odd-byte padding alignment.
        /// Uses zero-allocation byte-level checks — no per-chunk string allocations.
        /// </summary>
        private static bool ValidateWebpChunkLayout(byte[] bytes)
        {
            int offset = 12;

            while (offset + 8 <= bytes.Length)
            {
                // FIX: Validate chunk FourCC directly on bytes instead of
                // allocating a string via Encoding.ASCII.GetString.
                if (!IsUpperAsciiAlphaNumOrSpace(bytes, offset)) return false;

                uint chunkSize = BitConverter.ToUInt32(bytes, offset + 4);

                long dataEnd = offset + 8L + chunkSize;
                if (dataEnd > bytes.Length) return false;

                offset = (int)dataEnd;
                if ((chunkSize & 1) == 1) offset++; // RIFF odd-byte padding

                if (offset > bytes.Length) return false;
            }

            return offset == bytes.Length;
        }

        /// <summary>
        /// Walks the GIF block structure after the Logical Screen Descriptor.
        /// Validates global/local color tables, image descriptors, extension blocks,
        /// and sub-block chains. Confirms proper trailer termination.
        /// </summary>
        private static bool ValidateGifBlockLayout(byte[] bytes)
        {
            if (bytes.Length < 13) return false;

            // Logical Screen Descriptor starts at offset 6.
            byte packed = bytes[10];
            bool hasGlobalColorTable = (packed & 0x80) != 0;
            int globalColorTableSize = 0;
            if (hasGlobalColorTable)
            {
                int gctEntryCount = 1 << ((packed & 0x07) + 1);
                globalColorTableSize = gctEntryCount * 3;
            }

            int offset = 13 + globalColorTableSize;
            if (offset > bytes.Length) return false;

            // Walk blocks until trailer (0x3B) or EOF.
            while (offset < bytes.Length)
            {
                byte introducer = bytes[offset];

                switch (introducer)
                {
                    case 0x3B: // Trailer — end of GIF.
                        return offset == bytes.Length - 1;

                    case 0x2C: // Image Descriptor
                    {
                        // Image descriptor is 10 bytes: introducer + 4 position + 2 width + 2 height + packed.
                        if (offset + 10 > bytes.Length) return false;

                        byte imgPacked = bytes[offset + 9];
                        bool hasLocalColorTable = (imgPacked & 0x80) != 0;
                        int localColorTableSize = 0;
                        if (hasLocalColorTable)
                        {
                            int lctEntryCount = 1 << ((imgPacked & 0x07) + 1);
                            localColorTableSize = lctEntryCount * 3;
                        }

                        offset += 10 + localColorTableSize;
                        if (offset >= bytes.Length) return false;

                        // LZW minimum code size byte.
                        offset++;
                        if (offset >= bytes.Length) return false;

                        // Sub-block chain (terminated by zero-length sub-block).
                        if (!SkipGifSubBlocks(bytes, ref offset)) return false;
                        break;
                    }

                    case 0x21: // Extension block
                    {
                        if (offset + 2 > bytes.Length) return false;

                        // byte extensionLabel = bytes[offset + 1]; // Not used for validation.
                        offset += 2;

                        // Sub-block chain (terminated by zero-length sub-block).
                        if (!SkipGifSubBlocks(bytes, ref offset)) return false;
                        break;
                    }

                    default:
                        // Unknown block introducer — structural failure.
                        return false;
                }
            }

            // Ran out of bytes without finding trailer.
            return false;
        }

        /// <summary>
        /// Advances offset past a GIF sub-block chain.
        /// Each sub-block starts with a size byte; 0x00 terminates the chain.
        /// </summary>
        private static bool SkipGifSubBlocks(byte[] bytes, ref int offset)
        {
            while (offset < bytes.Length)
            {
                byte subBlockSize = bytes[offset];
                offset++;

                if (subBlockSize == 0) return true; // End of sub-block chain.

                offset += subBlockSize;
                if (offset > bytes.Length) return false;
            }
            return false; // Ran out of data.
        }

        /// <summary>
        /// Validates that 4 bytes at <paramref name="offset"/> are uppercase ASCII
        /// letters (A-Z), digits (0-9), or space — matching the RIFF FourCC spec.
        /// Operates directly on the byte array without allocating a string.
        /// Named explicitly "Upper" to prevent accidental reuse where lowercase
        /// chunk types would be valid (e.g. PNG ancillary chunks).
        /// </summary>
        private static bool IsUpperAsciiAlphaNumOrSpace(byte[] bytes, int offset)
        {
            if (offset + 4 > bytes.Length) return false;
            for (int i = 0; i < 4; i++)
            {
                byte b = bytes[offset + i];
                if (!((b >= (byte)'A' && b <= (byte)'Z') ||
                      (b >= (byte)'0' && b <= (byte)'9') ||
                      b == (byte)' '))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Returns true when every byte after %%EOF is PDF-legal whitespace.
        /// Replaces the crude offset+20 heuristic.
        /// </summary>
        private static bool HasOnlyTrailingPdfWhitespace(string content, int startIndex)
        {
            for (int i = startIndex; i < content.Length; i++)
            {
                char c = content[i];
                if (c != '\0' && c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '\f')
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Minimum contiguous printable-ASCII run (including the matched pattern)
        /// required for a threat-pattern hit to be treated as real embedded text
        /// rather than a coincidental byte sequence.
        ///
        /// This is a secondary guard: for images the text scan is already scoped to
        /// metadata/comment segments (see RunImageThreatScans), so the primary
        /// false-positive source — coincidental matches in entropy-coded pixel data —
        /// is eliminated before this check runs. The run-length floor therefore only
        /// needs to filter tiny stray matches while still catching genuine short
        /// polyglot payloads such as "&lt;svg onload=alert(1)&gt;" (21 chars).
        /// </summary>
        private const int MinTextContextRun = 12;

        /// <summary>
        /// Printable-run floor for NON-image regions (data after a JPEG's EOI). Lower than
        /// <see cref="MinTextContextRun"/> and with no additive trailing window, so short
        /// interpreter shebangs still register; high enough that four-byte tokens such as
        /// "&lt;svg" do not fire on the effectively-random bytes of a Motion Photo trailer.
        /// </summary>
        private const int MinTrailingTextContextRun = 10;

        /// <summary>
        /// Size of the post-EOI filler run that skips the trailing-region scan outright.
        /// Purely a fast path: a trailer this small consisting only of NUL/FF/space/CR/LF
        /// cannot contain any threat pattern, so scanning it is wasted work. Larger or
        /// non-filler trailers are scanned, never rejected for being unrecognized.
        /// </summary>
        private const int MaxIgnorableJpegTrailingBytes = 256;

        /// <summary>
        /// Hard ceiling on inflated output from a single compressed metadata chunk.
        /// Bounds a decompression bomb hidden in zTXt/iTXt.
        /// </summary>
        private const int MaxDecompressedMetadataBytesPerChunk = 256 * 1024;

        /// <summary>
        /// Hard ceiling on total inflated metadata across all chunks in one file.
        /// </summary>
        private const int MaxTotalDecompressedMetadataBytes = 1024 * 1024;

        /// <summary>
        /// How far back from a <c>stream</c> keyword to search for the dictionary's
        /// <c>/Length</c> entry. Bounded so a pathological file cannot force a long scan.
        /// </summary>
        private const int PdfLengthLookbehind = 2048;

        /// <summary>
        /// Returns true only when a matched threat pattern sits within a substantial
        /// contiguous run of printable ASCII — the signature of genuinely embedded
        /// text rather than a coincidental binary match in compressed image payloads.
        ///
        /// The previous heuristic (75% printable bytes over an ~11-byte window) let
        /// short patterns such as "&lt;?=", "&lt;? " and "&lt;svg" false-positive on
        /// ordinary phone-camera JPEGs, blocking legitimate patron uploads. Measuring
        /// the longest contiguous printable run that spans the match eliminates those
        /// false positives while still catching real embedded scripts and shells.
        /// </summary>
        private static bool IsTextContext(byte[] bytes, int offset, int length, int trailingWindow = 8)
        {
            if (offset < 0 || offset >= bytes.Length) return false;

            // Expand left from the match start while bytes remain printable text.
            int start = offset;
            while (start > 0 && IsPrintableTextByte(bytes[start - 1]))
                start--;

            // Expand right from the match end while bytes remain printable text.
            int end = Math.Min(bytes.Length, offset + length);
            while (end < bytes.Length && IsPrintableTextByte(bytes[end]))
                end++;

            int requiredRun = Math.Max(MinTextContextRun, length + trailingWindow);
            return (end - start) >= requiredRun;
        }

        private static bool IsPrintableTextByte(byte b) =>
            (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D;

        private static bool ContainsNullByteSequence(byte[] bytes, int startOffset, int runLength = 8)
        {
            int consecutive = 0;
            for (int i = startOffset; i < bytes.Length; i++)
            {
                if (bytes[i] == 0x00) { if (++consecutive >= runLength) return true; }
                else                    consecutive = 0;
            }
            return false;
        }

        private static bool IsProbablyPeExecutable(byte[] bytes, int mzOffset)
        {
            if (mzOffset + 0x40 > bytes.Length) return false;
            uint peOffset = BitConverter.ToUInt32(bytes, mzOffset + 0x3C);
            long absPe    = mzOffset + peOffset;
            if (peOffset < 4 || absPe + 4 > bytes.Length) return false;
            return bytes[absPe]     == 0x50 && bytes[absPe + 1] == 0x45 &&
                   bytes[absPe + 2] == 0x00 && bytes[absPe + 3] == 0x00;
        }

        private static bool SignaturesMatch(byte[] bytes, byte[] signature)
        {
            if (bytes.Length < signature.Length) return false;
            for (int i = 0; i < signature.Length; i++)
                if (bytes[i] != signature[i]) return false;
            return true;
        }

        private static int FindBytes(byte[] haystack, byte[] needle, int startOffset = 0)
        {
            for (int i = startOffset; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { found = false; break; }
                if (found) return i;
            }
            return -1;
        }

        /// <summary>
        /// Compares bytes at offset against an ASCII literal without allocating
        /// an intermediate string (unlike Encoding.ASCII.GetString).
        /// </summary>
        private static bool AsciiEquals(byte[] bytes, int offset, string ascii)
        {
            if (offset < 0 || offset + ascii.Length > bytes.Length) return false;
            for (int i = 0; i < ascii.Length; i++)
                if (bytes[offset + i] != (byte)ascii[i]) return false;
            return true;
        }

        /// <summary>
        /// Reads a 4-byte big-endian unsigned integer without allocating a temporary array.
        /// Replaces the per-chunk allocation in PNG chunk-length parsing.
        /// </summary>
        private static uint ReadUInt32BigEndian(byte[] bytes, int offset) =>
            ((uint)bytes[offset] << 24) |
            ((uint)bytes[offset + 1] << 16) |
            ((uint)bytes[offset + 2] << 8) |
            bytes[offset + 3];

        /// <summary>
        /// Sanitizes a user-supplied filename for safe inclusion in structured logs.
        /// Strips control characters and Unicode confusables, truncates to configured
        /// maximum length. The truncation suffix is included within the limit so the
        /// total output never exceeds MaxLogFileNameLength.
        /// The original filename is never modified for storage — only
        /// the value written to security event logs.
        /// </summary>
        private string SanitizeFileName(string? fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return "(empty)";

            int maxLen = _options.MaxLogFileNameLength;
            var sb = new StringBuilder(Math.Min(fileName.Length, maxLen));

            for (int i = 0; i < fileName.Length && sb.Length < maxLen; i++)
            {
                char c = fileName[i];
                // Keep printable ASCII and common international filename characters.
                // Strip control characters, zero-width joiners, and directional overrides.
                if (c >= 0x20 && c <= 0x7E)
                    sb.Append(c);
                else if (char.IsLetterOrDigit(c) || c == '.' || c == '-' || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_'); // Replace suspicious characters.
            }

            // Trim back before appending the suffix so total length stays
            // within MaxLogFileNameLength.
            if (sb.Length < fileName.Length)
            {
                const string truncationSuffix = "...(truncated)";
                int trimTo = Math.Max(0, maxLen - truncationSuffix.Length);
                if (sb.Length > trimTo)
                    sb.Length = trimTo;
                sb.Append(truncationSuffix);
            }

            string sanitized = sb.ToString();
            return sanitized.Length > 0 ? sanitized : "(sanitized-empty)";
        }

        private void LogWithHexSnippet(
            string eventType, string fileName, string detail, byte[] bytes, int offset = 0)
        {
            int    start = Math.Max(0, offset - 16);
            int    len   = Math.Min(64, bytes.Length - start);
            string hex   = BitConverter.ToString(bytes, start, len).Replace("-", " ");
            _logger.LogWarning(
                "{Event} | FileName: {FileName} | Detail: {Detail} | HexSnippet: {Hex} (offset ~{Offset})",
                eventType, fileName, detail, hex, offset);
        }

        // ── Result helpers ────────────────────────────────────────────────────────

        private ContentValidationResult RejectStructural(
            string fileName, string fileType, string reason, string validationType)
        {
            _logger.LogWarning(
                "SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: Structural | FileType: {FileType} | FileName: {FileName} | Reason: {Reason}",
                fileType, fileName, reason);
            return new ContentValidationResult
            {
                IsValid = false, Disposition = ValidationDisposition.RejectedStructural,
                ErrorMessage = $"File validation failed: {reason}", ThreatDescription = reason,
                IsSuspicious = false, ValidationType = validationType
            };
        }

        private ContentValidationResult RejectPolicy(
            string fileName, string fileType, string reason, string validationType)
        {
            _logger.LogWarning(
                "SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: Policy | FileType: {FileType} | FileName: {FileName} | Reason: {Reason}",
                fileType, fileName, reason);
            return new ContentValidationResult
            {
                IsValid = false, Disposition = ValidationDisposition.RejectedPolicy,
                ErrorMessage = reason, ThreatDescription = reason,
                IsSuspicious = true, ValidationType = validationType
            };
        }

        private ContentValidationResult RejectMalicious(
            string fileName, string fileType, string reason, string validationType)
        {
            _logger.LogWarning(
                "SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: Malicious | FileType: {FileType} | FileName: {FileName} | Reason: {Reason}",
                fileType, fileName, reason);
            return new ContentValidationResult
            {
                IsValid = false, Disposition = ValidationDisposition.RejectedMalicious,
                ErrorMessage = "This file contains unsafe content and cannot be accepted.",
                ThreatDescription = reason, IsSuspicious = true, ValidationType = validationType
            };
        }

        private ContentValidationResult RejectTypeMismatch(
            string fileName, string fileType, string reason, string validationType)
        {
            _logger.LogWarning(
                "SECURITY_EVENT | DEEP_VALIDATION_REJECTED | Disposition: TypeMismatch | FileType: {FileType} | FileName: {FileName} | Reason: {Reason}",
                fileType, fileName, reason);
            return new ContentValidationResult
            {
                IsValid = false, Disposition = ValidationDisposition.RejectedTypeMismatch,
                ErrorMessage = "The file content does not match its extension.",
                ThreatDescription = reason, IsSuspicious = true, ValidationType = validationType
            };
        }

        private ContentValidationResult EmbeddedShellReject(string fileName, string fileType) =>
            RejectMalicious(fileName, fileType,
                $"Embedded shell or code content found in {fileType} file.",
                $"{fileType}-EmbeddedShell");

        private ContentValidationResult EmbeddedScriptReject(string fileName, string fileType) =>
            RejectMalicious(fileName, fileType,
                $"Embedded HTML/JavaScript/SVG content found in {fileType} file.",
                $"{fileType}-EmbeddedScript");

        private ContentValidationResult FailClosedUnknown(string fileName, string extension)
        {
            _logger.LogWarning(
                "SECURITY_EVENT | FAIL_CLOSED_UNKNOWN_TYPE | Extension: {Extension} | FileName: {FileName}",
                extension, fileName);
            return new ContentValidationResult
            {
                IsValid = false, Disposition = ValidationDisposition.RejectedPolicy,
                ErrorMessage = "File type is not supported for deep validation.",
                ThreatDescription = $"Unknown extension: {extension}",
                IsSuspicious = false, ValidationType = "FailClosed-UnknownType"
            };
        }
    }
}
