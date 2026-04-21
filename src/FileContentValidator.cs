using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SixLabors.ImageSharp;
using System;
using System.Buffers;
using System.Collections.Generic;
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
        public int MaxDeepScanBytes { get; set; } = 20 * 1024 * 1024;

        public bool RejectEncryptedPdfs { get; set; } = true;
        public bool UseImageSharpForImages { get; set; } = true;

        public int MaxImageWidth { get; set; } = 10000;
        public int MaxImageHeight { get; set; } = 10000;
        public long MaxImagePixels { get; set; } = 40_000_000;

        /// <summary>
        /// If true, form-like PDFs (/AcroForm) are rejected even without active JavaScript.
        /// </summary>
        public bool RejectInteractivePdfs { get; set; } = false;

        /// <summary>
        /// Gap 2 mitigation: when true, locate raw `stream … endstream` blocks in the PDF,
        /// attempt FlateDecode (zlib/deflate) decompression, and re-run the dangerous
        /// pattern scan against the decompressed bytes. Compressed PDF streams are
        /// otherwise opaque to the byte-level pattern scanner.
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
    ///   • /Encrypt handled by config only — not duplicated in DangerousPdfPatterns.
    ///   • /OpenAction and /AA only hard-blocked when JavaScript is also present.
    ///   • hasJs uses exact token set — avoids false positives from /JSON, /JSon, etc.
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
        private static readonly string[] DangerousPdfPatterns =
        {
            "/JS ", "/JS\r", "/JS\n", "/JavaScript",
            "/Launch",
            "/EmbeddedFile",
            "/RichMedia",
            "/XFA",
            "/JBIG2Decode",
            "/3D",
            "/Sound",
            "/Movie"
            // /XObject omitted: present in virtually every scanned PDF (image XObjects).
            // /Encrypt omitted: handled by RejectEncryptedPdfs option below.
        };

        // Suspicious or conditionally dangerous — logged and selectively blocked.
        private static readonly string[] SuspiciousPdfPatterns =
        {
            "/URI",
            "/SubmitForm",
            "/GoToR",
            "/OpenAction",
            "/AA ",
            "/AA\r",
            "/AA\n",
            "/AcroForm"
        };

        // Exact JS trigger tokens — avoids /JSON, /JSon false positives from broad Contains.
        private static readonly string[] JsTriggerPatterns =
        {
            "/JS ", "/JS\r", "/JS\n", "/JavaScript"
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

        private static readonly string[] PhpShellPatterns =
        {
            "<?php", "<?=", "<? ",
            "passthru(", "system(", "exec(", "shell_exec(",
            "popen(", "proc_open(", "eval(", "assert(",
            "base64_decode(", "gzinflate(", "gzuncompress(", "str_rot13(",
            "powershell", "cmd.exe", "cmd /c",
            "import os", "import subprocess",
            "#!/usr/bin/perl", "#!/usr/bin/python", "#!/usr/bin/env python",
            "#!/bin/bash", "#!/bin/sh"
        };

        private static readonly string[] ScriptContentPatterns =
        {
            "<script", "javascript:", "vbscript:", "data:text/html",
            "onerror=", "onload=", "onclick=", "onmouseover=",
            "<svg", "<iframe", "<object", "<embed",
            "<form ", "<meta ", "<base ", "<link ",
            "expression(", "@import"
        };

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
                    _logger.LogWarning(
                        "SECURITY_EVENT | TYPE_MISMATCH | Extension: {Ext} | Detected: {Detected} | FileName: {FileName}",
                        extension, detectedType, safeFileName);
                    return RejectTypeMismatch(
                        safeFileName,
                        extension.TrimStart('.').ToUpperInvariant(),
                        $"Extension claims {expectedType} but content signature is {detectedType}.",
                        "SignatureExtensionMismatch");
                }

                // ── Format-specific deep validation ───────────────────────────────

                return detectedType switch
                {
                    DetectedFileType.Pdf  => ValidatePdf(fileBytes, safeFileName),
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

        private ContentValidationResult ValidatePdf(byte[] bytes, string fileName)
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

            if (_options.RejectEncryptedPdfs && content.Contains("/Encrypt", StringComparison.OrdinalIgnoreCase))
                return RejectPolicy(
                    fileName, "PDF",
                    "Encrypted PDFs are not permitted by security policy.",
                    "PDF-EncryptedRejected");

            foreach (string pattern in DangerousPdfPatterns)
            {
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                LogWithHexSnippet("SECURITY_EVENT | PDF_DANGEROUS_PATTERN", fileName, pattern, bytes);
                return RejectMalicious(
                    fileName, "PDF",
                    $"Dangerous PDF pattern detected: {pattern.Trim()}",
                    "PDF-DangerousPattern");
            }

            // Determine JS presence once using exact token set (avoids /JSON false positives).
            bool hasJavaScript = false;
            foreach (string jsToken in JsTriggerPatterns)
            {
                if (content.Contains(jsToken, StringComparison.OrdinalIgnoreCase))
                {
                    hasJavaScript = true;
                    break;
                }
            }

            foreach (string pattern in SuspiciousPdfPatterns)
            {
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                _logger.LogWarning(
                    "SECURITY_EVENT | PDF_SUSPICIOUS_PATTERN | FileName: {FileName} | Pattern: {Pattern}",
                    fileName, pattern);

                // /OpenAction and /AA only become hard blocks when JS is also present.
                bool isTriggerAction =
                    pattern.Equals("/OpenAction", StringComparison.OrdinalIgnoreCase) ||
                    pattern.StartsWith("/AA", StringComparison.OrdinalIgnoreCase);

                if (isTriggerAction && hasJavaScript)
                    return RejectMalicious(
                        fileName, "PDF",
                        $"Dangerous PDF trigger action with JavaScript: {pattern.Trim()}",
                        "PDF-TriggerWithJavaScript");

                if (_options.RejectInteractivePdfs &&
                    pattern.Equals("/AcroForm", StringComparison.OrdinalIgnoreCase))
                    return RejectPolicy(
                        fileName, "PDF",
                        "Interactive form PDFs are not permitted by policy.",
                        "PDF-InteractiveRejected");
            }

            if (ContainsNullByteSequence(bytes, 10))
                _logger.LogDebug("PDF_NULL_BYTES_DETECTED | FileName: {FileName} | Non-blocking", fileName);

            // Gap 2 mitigation: inspect FlateDecode-compressed streams.
            // Without this, /JavaScript or /Launch hidden inside compressed streams
            // would be invisible to the byte-level pattern scanner above.
            if (_options.InspectCompressedPdfStreams)
            {
                if (ScanCompressedPdfStreams(bytes, fileName) is { } streamThreat)
                    return streamThreat;
            }

            // PDF already has `content` from the Latin1 decode above — pass it
            // directly to avoid a redundant decode inside RunCommonThreatScans.
            if (RunCommonThreatScans(bytes, content, fileName, "PDF") is { } threatResult)
                return threatResult;

            _logger.LogDebug("PDF deep validation PASSED for {FileName}", fileName);
            return ContentValidationResult.Allow("PDF-DeepScan");
        }

        // ── Gap 2: FlateDecode-compressed PDF stream scanner ──────────────────────
        //
        // PDF object streams are commonly Flate (zlib) compressed. Threat tokens
        // such as /JavaScript, /JS, /Launch, /OpenAction can be hidden inside
        // these compressed blobs and are invisible to a plain byte/text scan.
        //
        // This helper walks the raw bytes for `stream` … `endstream` pairs (the
        // PDF spec literal markers) and tries to inflate each block. If inflation
        // succeeds, the decompressed bytes are re-scanned for the same dangerous
        // patterns the outer Layer 6 scan looks for.
        //
        // Hard caps (configurable):
        //   • MaxCompressedStreamsToInspect — bounds CPU per file
        //   • MaxDecompressedStreamBytes    — bounds memory (zip-bomb defence)
        //
        // Failure mode is fail-open per stream (malformed inflate → skip), but
        // fail-closed for the file overall if any decompressed pattern matches.
        private ContentValidationResult? ScanCompressedPdfStreams(byte[] bytes, string fileName)
        {
            ReadOnlySpan<byte> streamMarker = "stream"u8;
            ReadOnlySpan<byte> endMarker = "endstream"u8;

            int totalDecompressed = 0;
            int streamsInspected = 0;
            int searchFrom = 0;

            while (searchFrom < bytes.Length &&
                   streamsInspected < _options.MaxCompressedStreamsToInspect &&
                   totalDecompressed < _options.MaxDecompressedStreamBytes)
            {
                int sIdx = IndexOf(bytes, streamMarker, searchFrom);
                if (sIdx < 0) break;

                // Move past `stream` keyword and the required EOL (LF or CRLF).
                int dataStart = sIdx + streamMarker.Length;
                if (dataStart >= bytes.Length) break;
                if (bytes[dataStart] == (byte)'\r') dataStart++;
                if (dataStart < bytes.Length && bytes[dataStart] == (byte)'\n') dataStart++;

                int eIdx = IndexOf(bytes, endMarker, dataStart);
                if (eIdx < 0) break;

                int dataEnd = eIdx;
                // Trim trailing EOL before `endstream` per PDF spec.
                if (dataEnd > dataStart && bytes[dataEnd - 1] == (byte)'\n') dataEnd--;
                if (dataEnd > dataStart && bytes[dataEnd - 1] == (byte)'\r') dataEnd--;

                int rawLen = dataEnd - dataStart;
                searchFrom = eIdx + endMarker.Length;

                if (rawLen <= 2) continue;
                streamsInspected++;

                // Try to inflate. PDF FlateDecode is zlib-wrapped (RFC 1950), so
                // skip the 2-byte zlib header before feeding to DeflateStream
                // (which speaks raw RFC 1951 deflate).
                byte b0 = bytes[dataStart];
                byte b1 = bytes[dataStart + 1];
                bool looksLikeZlib = (b0 & 0x0F) == 0x08 && (((b0 << 8) | b1) % 31 == 0);
                int deflateOffset = looksLikeZlib ? 2 : 0;
                int deflateLen = rawLen - deflateOffset;
                if (deflateLen <= 0) continue;

                int budget = _options.MaxDecompressedStreamBytes - totalDecompressed;
                if (budget <= 0) break;

                byte[]? inflated;
                try
                {
                    using var src = new MemoryStream(bytes, dataStart + deflateOffset, deflateLen, writable: false);
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
                            // Stop this stream — over the per-file budget. Skip
                            // rather than reject (could be legitimate large image).
                            dst.Write(buf, 0, read - (written - budget));
                            break;
                        }
                        dst.Write(buf, 0, read);
                    }
                    inflated = dst.ToArray();
                }
                catch
                {
                    // Malformed / non-Flate / encrypted stream — silently skip.
                    continue;
                }

                if (inflated.Length == 0) continue;
                totalDecompressed += inflated.Length;

                string decoded = Encoding.Latin1.GetString(inflated);

                foreach (string pattern in DangerousPdfPatterns)
                {
                    if (decoded.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) < 0) continue;

                    // Mirror outer-scan policy nuance: /AcroForm only fails when
                    // interactive PDFs are explicitly rejected.
                    if (pattern.Equals("/AcroForm", StringComparison.OrdinalIgnoreCase) &&
                        !_options.RejectInteractivePdfs)
                        continue;

                    return RejectMalicious(
                        fileName, "PDF",
                        $"Dangerous pattern '{pattern}' found inside FlateDecode-compressed stream.",
                        "PDF-CompressedStreamThreat");
                }

                foreach (string jsToken in JsTriggerPatterns)
                {
                    if (decoded.IndexOf(jsToken, StringComparison.OrdinalIgnoreCase) >= 0)
                        return RejectMalicious(
                            fileName, "PDF",
                            $"JavaScript trigger '{jsToken}' found inside FlateDecode-compressed stream.",
                            "PDF-CompressedStreamThreat");
                }
            }

            if (streamsInspected > 0)
                _logger.LogDebug(
                    "PDF_COMPRESSED_STREAMS_SCANNED | FileName: {FileName} | Streams: {Count} | DecompressedBytes: {Bytes}",
                    fileName, streamsInspected, totalDecompressed);

            return null;
        }

        private static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle, int start)
        {
            if (start < 0) start = 0;
            if (start >= haystack.Length || needle.Length == 0) return -1;
            return haystack.AsSpan(start).IndexOf(needle) is var rel && rel < 0 ? -1 : rel + start;
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

            // Verify JPEG contains an EOI marker (FF D9) by scanning backward.
            // Some cameras (Samsung, Xiaomi, older Canon) and image editors append
            // thumbnail data, maker notes, or padding after EOI. Requiring EOI at
            // the exact last two bytes would false-reject these legitimate photos.
            // A backward scan confirms the file was properly terminated without
            // penalizing trailing camera data.
            if (!ContainsJpegEoi(bytes))
                return RejectStructural(fileName, "JPEG", "Missing JPEG EOI marker.", "JPEG-StructuralCheck");

            // Walk JPEG segments: validate marker types and declared segment lengths.
            // Stops at SOS (0xDA) since entropy-coded data follows and cannot be walked.
            if (!ValidateJpegSegmentLayout(bytes))
                return RejectStructural(fileName, "JPEG", "Invalid JPEG segment structure.", "JPEG-SegmentWalk");

            if (RunCommonThreatScans(bytes, fileName, "JPEG") is { } threatResult)
                return threatResult;

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

            if (RunCommonThreatScans(bytes, fileName, "PNG") is { } threatResult)
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

            if (RunCommonThreatScans(bytes, fileName, "WEBP") is { } threatResult)
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

            if (RunCommonThreatScans(bytes, fileName, "GIF") is { } threatResult)
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

        // ── Per-pattern threat helpers ─────────────────────────────────────────────

        private bool ContainsPhpShell(byte[] bytes, string content, string fileName)
        {
            foreach (string p in PhpShellPatterns)
            {
                int idx = content.IndexOf(p, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0 && IsTextContext(bytes, idx, p.Length))
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | EMBEDDED_SHELL | FileName: {FileName} | Pattern: {Pattern}",
                        fileName, p);
                    return true;
                }
            }
            return false;
        }

        private bool ContainsScriptContent(byte[] bytes, string content, string fileName)
        {
            foreach (string p in ScriptContentPatterns)
            {
                int idx = content.IndexOf(p, StringComparison.OrdinalIgnoreCase);
                if (idx >= 0 && IsTextContext(bytes, idx, p.Length))
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | EMBEDDED_SCRIPT | FileName: {FileName} | Pattern: {Pattern}",
                        fileName, p);
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Scans for embedded executable signatures (PE, ELF, Mach-O, OLE).
        /// These are always classified as Malicious — there is no legitimate reason
        /// for an executable to be embedded inside a patron-submitted image or PDF.
        /// </summary>
        private ContentValidationResult? ContainsEmbeddedExecutable(byte[] bytes, string fileName, string fileType)
        {
            const int scanStart = 16;

            foreach ((byte[] sig, string desc) in DangerousExecutableSignatures)
            {
                int offset = FindBytes(bytes, sig, scanStart);
                if (offset < scanStart) continue;

                // MZ (2 bytes) — validate PE\0\0 pointer to avoid false positives.
                if (sig.Length == 2 && sig[0] == 0x4D && sig[1] == 0x5A && !IsProbablyPeExecutable(bytes, offset))
                    continue;

                LogWithHexSnippet($"SECURITY_EVENT | EMBEDDED_EXECUTABLE | {fileType}", fileName, desc, bytes, offset);
                return RejectMalicious(
                    fileName, fileType,
                    $"Embedded {desc} detected at offset {offset}.",
                    $"{fileType}-EmbeddedExecutable");
            }
            return null;
        }

        /// <summary>
        /// Scans for embedded archive/container signatures (ZIP, RAR, 7z, GZIP).
        /// Classified as Policy rejection — these can occasionally appear in legitimate
        /// image metadata or comment areas but are disallowed by upload policy.
        /// </summary>
        private ContentValidationResult? ContainsEmbeddedContainer(byte[] bytes, string fileName, string fileType)
        {
            const int scanStart = 16;

            foreach ((byte[] sig, string desc) in PolicyContainerSignatures)
            {
                int offset = FindBytes(bytes, sig, scanStart);
                if (offset < scanStart) continue;

                // GZIP (3 bytes) — validate flags byte is in 0-31 range to reduce false positives.
                if (sig.Length == 3 && sig[0] == 0x1F && sig[1] == 0x8B &&
                    (offset + 3 >= bytes.Length || bytes[offset + 3] > 0x1F))
                    continue;

                LogWithHexSnippet($"SECURITY_EVENT | EMBEDDED_CONTAINER | {fileType}", fileName, desc, bytes, offset);
                return RejectPolicy(
                    fileName, fileType,
                    $"Embedded {desc} detected at offset {offset}. Embedded containers are not permitted.",
                    $"{fileType}-EmbeddedContainer");
            }
            return null;
        }

        // ── Format-specific structural validators ─────────────────────────────────

        /// <summary>
        /// Scans backward from the end of the file for a JPEG EOI marker (FF D9).
        /// Returns true if found within the trailing region. This tolerates cameras
        /// and editors that append data (thumbnails, maker notes, padding) after EOI
        /// while still confirming the image stream was properly terminated.
        ///
        /// The scan window is limited to the last 4 KB — any legitimate trailing
        /// data beyond that is abnormal enough to warrant structural rejection.
        /// </summary>
        private static bool ContainsJpegEoi(byte[] bytes)
        {
            if (bytes.Length < 4) return false;

            // Scan backward from the end, up to 4 KB back.
            int scanStart = Math.Max(2, bytes.Length - 4096);
            for (int i = bytes.Length - 1; i > scanStart; i--)
            {
                if (bytes[i] == 0xD9 && bytes[i - 1] == 0xFF)
                    return true;
            }
            return false;
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
        /// Returns true when the bytes at and immediately after a matched pattern
        /// look like printable ASCII rather than coincidental binary data.
        /// Prevents false positives in compressed image payloads.
        /// </summary>
        private static bool IsTextContext(byte[] bytes, int offset, int length, int trailingWindow = 8)
        {
            int end   = Math.Min(bytes.Length, offset + length + trailingWindow);
            int total = end - offset;
            if (total <= 0) return true;

            int printable = 0;
            for (int i = offset; i < end; i++)
            {
                byte b = bytes[i];
                if ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D)
                    printable++;
            }
            return printable * 100 / total >= 75;
        }

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