using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureFileUpload.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Interface for secure file upload operations
    /// </summary>
    public interface IFileUploadService
    {
        Task<FileUploadResult> UploadFilesAsync(IFormFileCollection files, string lastName, string formType);
        (bool IsValid, string? ErrorMessage) ValidateFile(IFormFile file);
        bool IsValidFileType(IFormFile file);

        /// <summary>
        /// The validated, absolute path to the upload storage root directory.
        /// Guaranteed to be outside wwwroot.
        /// </summary>
        string StorageRoot { get; }

        /// <summary>
        /// Returns a decrypted, readable stream for the given file path.
        /// Handles AES-256-GCM encrypted files and unencrypted files transparently.
        /// Caller is responsible for disposing the returned stream.
        /// Returns null stream if the file does not exist or cannot be read.
        /// </summary>
        Task<(Stream? Stream, string ContentType)> GetDecryptedFileStreamAsync(string filePath);
    }

    /// <summary>
    /// Result of a file upload operation
    /// </summary>
    public class FileUploadResult
    {
        public bool Success { get; set; }
        public List<string> UploadedFilePaths { get; set; } = new List<string>();
        public List<string> Errors { get; set; } = new List<string>();
        public string? SubmissionFolder { get; set; }

        // -- Truthful upload counts --------------------------------------
        public int SubmittedCount { get; set; }
        public int SavedCount => UploadedFilePaths.Count;
        public int RejectedCount => SubmittedCount - SavedCount;

        // -- Scan status breakdown ---------------------------------------
        public int ScanCleanCount { get; set; }
        public int ScanNotScannedCount { get; set; }
        public int InfectedRejectedCount { get; set; }

        /// <summary>
        /// Workflow outcome: AllSaved, PartialSaved, AllRejected, or NoFiles.
        /// </summary>
        public string WorkflowOutcome =>
            SubmittedCount == 0 ? "NoFiles" :
            SavedCount == SubmittedCount ? "AllSaved" :
            SavedCount > 0 ? "PartialSaved" :
            "AllRejected";
    }

    /// <summary>
    /// Service for handling secure file uploads for remote registration forms.
    ///
    /// Validation pipeline (per file):
    ///   Layer 1 - Size check
    ///   Layer 2 - Extension allowlist
    ///   Layer 3 - MIME type validation + extension↔MIME cross-check (reject on mismatch)
    ///   Layer 4 - Magic bytes / file signature
    ///   Layer 5 - Suspicious filename patterns (double-extension, Unicode tricks, traversal)
    ///   Layer 6 - Deep content validation (FileContentValidator) — always runs, fail-closed
    ///   Layer 7 - Virus scan (IVirusScanService)                — only when VirusScan:Enabled=true
    ///   Layer 8 - Write to disk (AES-256-GCM authenticated encryption, or plain)
    /// </summary>
    public class FileUploadService : IFileUploadService
    {
        private readonly ILogger<FileUploadService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;
        private readonly FileContentValidator _contentValidator;
        private readonly IVirusScanService _virusScanService;

        /// <summary>
        /// Absolute, canonicalized path to the upload storage root.
        /// Resolved from FileUpload:StorageRoot against ContentRootPath.
        /// Guaranteed to be outside wwwroot at construction time.
        /// </summary>
        private readonly string _storageRoot;
        private readonly long _maxFileSizeBytes;
        private readonly int _maxFileCount;
        private readonly long _maxTotalUploadBytes;
        private readonly long _minStorageFreeBytes;
        private readonly long _minTempFreeBytes;
        private readonly long _lowDiskWarningBytes;
        private readonly bool _encryptionEnabled;
        private readonly byte[]? _encryptionKey;       // 32-byte AES-256 key (PBKDF2-derived)
        private readonly byte[]? _legacyEncryptionKey; // Optional fallback key for legacy PBKDF2 iteration counts
        private readonly bool _virusScanEnabled;       // mirrors VirusScan:Enabled in appsettings

        // ── AES-256-GCM file format constants ────────────────────────────
        //
        // Marker written at the start of every AES-GCM encrypted file.
        // Layout: [8 marker][12 nonce][16 tag][ciphertext]
        private static readonly byte[] GcmEncryptedFileMarker = Encoding.ASCII.GetBytes("ENCGCM\0\x01");
        private static readonly byte[] GcmFormatPrefix = { 0x45, 0x4E, 0x43, 0x47, 0x43, 0x4D, 0x00 }; // "ENCGCM\0"
        private const byte SupportedGcmFormatVersion = 0x01;
        private const int GcmNonceSize  = 12;  // 96-bit nonce — GCM standard recommendation
        private const int GcmTagSize    = 16;  // 128-bit authentication tag
        private const int GcmHeaderSize = 8 + GcmNonceSize + GcmTagSize; // marker + nonce + tag

        // ── Allowlists ───────────────────────────────────────────────────

        private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".jpg", ".jpeg", ".png", ".webp", ".pdf"
        };

        private static readonly HashSet<string> AllowedMimeTypes = new(StringComparer.OrdinalIgnoreCase)
        {
            "image/jpeg",
            "image/jpg",
            "image/png",
            "image/webp",
            "application/pdf"
        };

        /// <summary>
        /// Maps each allowed extension to its acceptable MIME types.
        /// Used for cross-validation: the browser-reported MIME must match the extension.
        /// </summary>
        private static readonly Dictionary<string, HashSet<string>> ExtensionToMimeMap =
            new(StringComparer.OrdinalIgnoreCase)
            {
                { ".jpg",  new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "image/jpeg", "image/jpg" } },
                { ".jpeg", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "image/jpeg", "image/jpg" } },
                { ".png",  new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "image/png" } },
                { ".webp", new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "image/webp" } },
                { ".pdf",  new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "application/pdf" } },
            };

        // Magic bytes for each allowed file type
        private static readonly Dictionary<string, byte[][]> FileSignatures = new()
        {
            { ".jpg",  new byte[][] { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".jpeg", new byte[][] { new byte[] { 0xFF, 0xD8, 0xFF } } },
            { ".png",  new byte[][] { new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } } },
            // WebP: RIFF at offset 0, "WEBP" at offset 8. We check RIFF here;
            // the WEBP fourCC at offset 8 is verified separately to avoid false-matching AVI/WAV.
            { ".webp", new byte[][] { new byte[] { 0x52, 0x49, 0x46, 0x46 } } },
            { ".pdf",  new byte[][] { new byte[] { 0x25, 0x50, 0x44, 0x46 } } }  // %PDF
        };

        // Known dangerous magic bytes — used to identify what a disguised file actually is
        private static readonly Dictionary<string, string> KnownDangerousSignatures = new()
        {
            { "4D5A",             "Windows PE Executable (.exe / .dll)" },
            { "504B0304",         "ZIP archive (could be .docx, .jar, .apk)" },
            { "7F454C46",         "ELF Linux Executable" },
            { "CAFEBABE",         "Java Class or Mach-O binary" },
            { "D0CF11E0",         "Microsoft Office / OLE Compound Document" },
            { "1F8B08",           "GZIP archive" },
            { "377ABCAF",         "7-Zip archive" },
            { "526172211A07",     "RAR archive" },
            { "3C3F706870",       "PHP script (<?php)" },
            { "3C736372697074",   "HTML/JavaScript (<script>)" },
            { "3C73766720",       "SVG element (<svg )" },
            { "23212F",           "Shebang script (#!/)" },
            { "FEEDFACE",         "Mach-O 32-bit" },
            { "FEEDFACF",         "Mach-O 64-bit" },
            { "CFFAEDFE",         "Mach-O 64-bit (reversed)" },
            { "4C00000001140200", "Windows Shortcut (.lnk)" },
            { "EDABEEDB",         "RPM package" },
        };

        /// <summary>
        /// Dangerous extensions that must not appear anywhere in the filename stem,
        /// used to detect double-extension attacks like "photo.pdf.exe" or "doc.php.jpg".
        /// </summary>
        private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".psm1",
            ".psd1",        // PowerShell data file
            ".ps1xml",      // PowerShell XML
            ".vbs", ".vbe", ".js",  ".jse", ".wsh", ".wsf",
            ".jar", ".msi", ".msp", ".mst",
            ".scr", ".com", ".pif", ".hta", ".msc",
            ".php", ".php3", ".php4", ".php5", ".php7",
            ".phtml", ".phar",     // PHP archive
            ".phps",               // PHP source
            ".pht", ".phpt",       // PHP HTML template / test
            ".asp", ".aspx", ".asax", ".ascx", ".asmx", ".axd",
            ".cshtml", ".vbhtml",  // Razor views (can contain C#/VB)
            ".jsp", ".jspx",
            ".cgi", ".pl", ".py", ".pyc", ".pyo",
            ".rb", ".rhtml",
            ".sh", ".bash", ".zsh", ".fish",
            ".svg",          // SVG can contain scripts
            ".html", ".htm", ".xhtml", ".shtml", ".dhtml", ".stm",
            ".swf", ".flv",  // Flash (can contain ActionScript)
            ".ps", ".eps",   // PostScript (can execute code)
            ".lnk", ".reg", ".inf", ".sys", ".drv",  // Windows system files
            ".cpl", ".ocx",  // Control Panel / ActiveX
            ".application", ".appref-ms", ".gadget",  // ClickOnce / gadgets
        };

        /// <summary>
        /// Minimum useful file sizes per format.
        /// Files smaller than this cannot possibly be valid — reject early to save
        /// the cost of the magic-byte and deep-scan layers and to catch truncated
        /// uploads crafted to pass only a partial header check.
        /// </summary>
        private static readonly Dictionary<string, int> MinFileSizeByExtension = new(StringComparer.OrdinalIgnoreCase)
        {
            { ".jpg",  4 },   // SOI (2) + marker (2)
            { ".jpeg", 4 },
            { ".png",  16 },  // 8-byte signature + 4-byte chunk length + "IHDR"
            { ".webp", 12 },  // "RIFF" (4) + size (4) + "WEBP" (4)
            { ".pdf",  5 },   // "%PDF-"
        };

        /// <summary>
        /// Windows reserved device names — NUL, CON, PRN, AUX, COM1-9, LPT1-9.
        /// Static to avoid re-allocating on every filename validation call.
        /// </summary>
        private static readonly HashSet<string> WindowsReservedNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        };

        /// <summary>
        /// Extension-to-content-type mapping. Static dictionary for consistency
        /// with the other lookup tables and to avoid repeated switch evaluation.
        /// </summary>
        private static readonly Dictionary<string, string> ContentTypeMap = new(StringComparer.OrdinalIgnoreCase)
        {
            { ".pdf",  "application/pdf" },
            { ".jpg",  "image/jpeg" },
            { ".jpeg", "image/jpeg" },
            { ".png",  "image/png" },
            { ".webp", "image/webp" },
        };

        // ── Constructor ──────────────────────────────────────────────────

        public FileUploadService(
            ILogger<FileUploadService> logger,
            IConfiguration configuration,
            IWebHostEnvironment environment,
            FileContentValidator contentValidator,
            IVirusScanService virusScanService)
        {
            _logger = logger;
            _configuration = configuration;
            _environment = environment;
            _contentValidator = contentValidator;
            _virusScanService = virusScanService;

            // -- Resolve and validate upload storage root -----------------
            _storageRoot = ResolveAndValidateStorageRoot();

            _maxFileSizeBytes = _configuration.GetValue<long>("FileUpload:MaxFileSizeBytes", 10 * 1024 * 1024);
            _maxFileCount = _configuration.GetValue<int>("FileUpload:MaxFileCount", 5);
            _maxTotalUploadBytes = _configuration.GetValue<long>(
                "FileUpload:MaxTotalUploadBytes",
                checked(_maxFileSizeBytes * _maxFileCount));
            _minStorageFreeBytes = _configuration.GetValue<long>("FileUpload:MinStorageFreeBytes", 512L * 1024 * 1024);
            _minTempFreeBytes = _configuration.GetValue<long>("FileUpload:MinTempFreeBytes", 512L * 1024 * 1024);
            _lowDiskWarningBytes = _configuration.GetValue<long>("FileUpload:LowDiskWarningBytes", 2L * 1024 * 1024 * 1024);

            _virusScanEnabled = _configuration.GetValue<bool>("VirusScan:Enabled", false);

            _encryptionEnabled = _configuration.GetValue<bool>("FileUpload:EncryptionEnabled", false);
            if (_encryptionEnabled)
            {
                var secret = _configuration["FileUpload:EncryptionSecret"];
                if (string.IsNullOrWhiteSpace(secret) ||
                    secret.Contains("CHANGE_THIS", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogCritical(
                        "SECURITY_EVENT | ENCRYPTION_MISCONFIGURED | EncryptionEnabled=true but " +
                        "EncryptionSecret is missing or still set to the placeholder. " +
                        "Application startup blocked to prevent storing unencrypted patron documents.");
                    throw new InvalidOperationException(
                        "FileUpload:EncryptionEnabled is true but FileUpload:EncryptionSecret is missing " +
                        "or still set to the placeholder value. Set a real secret or disable encryption. " +
                        "Refusing to start to prevent unencrypted patron document storage.");
                }

                // Derive a 256-bit key using PBKDF2-SHA256 with a fixed application salt
                // and 600,000 iterations (OWASP 2024 recommendation for PBKDF2-SHA256).
                // The salt is application-specific (not per-file) because all files share
                // one key; the iteration count provides brute-force resistance if the
                // secret is weak or the config store is compromised.
                var salt = Encoding.UTF8.GetBytes("SecureFileUpload.FileUpload.v1");
                var sw = System.Diagnostics.Stopwatch.StartNew();
                _encryptionKey = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(secret),
                    salt,
                    iterations: 600_000,
                    HashAlgorithmName.SHA256,
                    outputLength: 32);
                sw.Stop();
                _logger.LogInformation(
                    "Encryption key derived in {ElapsedMs}ms ({Iterations:N0} PBKDF2-SHA256 iterations)",
                    sw.ElapsedMilliseconds, 600_000);

                // Backward-compatibility fallback for files encrypted under the
                // previous 210,000-iteration count before the OWASP bump.
                _legacyEncryptionKey = Rfc2898DeriveBytes.Pbkdf2(
                    Encoding.UTF8.GetBytes(secret),
                    salt,
                    iterations: 210_000,
                    HashAlgorithmName.SHA256,
                    outputLength: 32);
            }

            _logger.LogInformation(
                "FileUploadService initialized | StorageRoot: {Path} | MaxSize: {Size}MB | MaxCount: {Count} | MaxTotal: {TotalMB}MB | " +
                "MinStorageFree: {MinStorageMB}MB | MinTempFree: {MinTempMB}MB | LowDiskWarn: {WarnMB}MB | " +
                "Encryption: {Enc} | DeepValidation: enabled | VirusScan: {VS} ({Scanner})",
                _storageRoot, _maxFileSizeBytes / 1024 / 1024, _maxFileCount, _maxTotalUploadBytes / 1024 / 1024,
                _minStorageFreeBytes / 1024 / 1024, _minTempFreeBytes / 1024 / 1024, _lowDiskWarningBytes / 1024 / 1024,
                _encryptionEnabled ? "AES-256-GCM" : "disabled",
                _virusScanEnabled ? "enabled" : "disabled",
                _virusScanService.ScannerName);
        }

        // ── Public surface ───────────────────────────────────────────────

        /// <summary>
        /// Exposes the validated, absolute storage root path for use by other
        /// services (e.g. retention, diagnostics, controllers) that need to
        /// locate uploaded files.
        /// </summary>
        public string StorageRoot => _storageRoot;

        /// <summary>
        /// Upload multiple files through the full security validation pipeline.
        ///
        /// Pipeline per file:
        ///   Layers 1–5  ValidateFile()               (extension, MIME, magic bytes, filename)
        ///   Layer  6    FileContentValidator          (deep structural + embedded-code check)
        ///   Layer  7    IVirusScanService             (only when VirusScan:Enabled=true)
        ///   Layer  8    Write to permanent storage    (encrypted or plain)
        /// </summary>
        public async Task<FileUploadResult> UploadFilesAsync(IFormFileCollection files, string lastName, string formType)
        {
            var result = new FileUploadResult();
            int scanClean = 0, scanNotScanned = 0, infectedRejected = 0;

            // -- Entry point --------------------------------------------------
            _logger.LogInformation(
                "UPLOAD_START | Form: {FormType} | FileCount: {Count}",
                formType, files?.Count ?? 0);

            try
            {
                if (files == null || files.Count == 0)
                {
                    result.SubmittedCount = 0;
                    _logger.LogWarning("UPLOAD_REJECTED | Reason: No files received | Form: {FormType}", formType);
                    result.Errors.Add("No files were uploaded.");
                    return result;
                }

                result.SubmittedCount = files.Count;

                if (files.Count > _maxFileCount)
                {
                    _logger.LogWarning(
                        "UPLOAD_REJECTED | Reason: Too many files | Received: {Received} | Allowed: {Allowed} | Form: {FormType}",
                        files.Count, _maxFileCount, formType);
                    result.Errors.Add($"Maximum {_maxFileCount} files allowed. You uploaded {files.Count}.");
                    return result;
                }

                var totalUploadBytes = files.Sum(f => f?.Length ?? 0L);
                if (totalUploadBytes > _maxTotalUploadBytes)
                {
                    _logger.LogWarning(
                        "UPLOAD_REJECTED | Reason: Total upload size exceeded | Total: {Total:N0} bytes | Limit: {Limit:N0} bytes | Files: {Count} | Form: {FormType}",
                        totalUploadBytes, _maxTotalUploadBytes, files.Count, formType);
                    result.Errors.Add("Combined upload size is too large. Please upload fewer or smaller files.");
                    return result;
                }

                var (capacityOk, capacityError) = EnsureCapacityForUpload(totalUploadBytes, formType);
                if (!capacityOk)
                {
                    result.Errors.Add(capacityError ?? "Upload is temporarily unavailable. Please try again later.");
                    return result;
                }

                // Log summary of what arrived before touching any file
                for (int i = 0; i < files.Count; i++)
                {
                    var f = files[i];
                    _logger.LogInformation(
                        "FILE_RECEIVED [{Index}/{Total}] | Size: {Size:N0} bytes ({SizeKB:N1} KB) | ContentType: {ContentType} | Form: {FormType}",
                        i + 1, files.Count, f.Length, f.Length / 1024.0, f.ContentType, formType);
                }

                // Create submission folder
                var sanitizedLastName = SanitizeFileName(lastName);
                var dateStamp = DateTime.Now.ToString("yyyyMMdd");
                var submissionId = GenerateRandomString(8);
                var submissionFolder = $"{sanitizedLastName}{dateStamp}{submissionId}";
                var fullUploadPath = Path.Combine(_storageRoot, submissionFolder);

                // Path traversal check — uses PathHelper.IsPathUnderBase to avoid the
                // StartsWith prefix-confusion bug ("/uploads_evil" matching "/uploads").
                var normalizedPath = Path.GetFullPath(fullUploadPath);
                if (!PathHelper.IsPathUnderBase(normalizedPath, _storageRoot))
                {
                    _logger.LogError(
                        "SECURITY_EVENT | PATH_TRAVERSAL | Requested: {Requested} | Base: {Base} | Form: {FormType}",
                        fullUploadPath, _storageRoot, formType);
                    result.Errors.Add("Invalid upload path.");
                    return result;
                }

                Directory.CreateDirectory(fullUploadPath);
                result.SubmissionFolder = submissionFolder;
                _logger.LogInformation("UPLOAD_FOLDER_CREATED | Path: {Path}", fullUploadPath);

                // -- Per-file processing --------------------------------------
                int fileIndex = 1;
                foreach (var file in files)
                {
                    _logger.LogInformation(
                        "VALIDATING_FILE | Size: {Size:N0} bytes | ContentType: {CT}",
                        file.Length, file.ContentType);

                    // -- Layer 1–5: Basic validation (size, extension, MIME cross-check, magic bytes, filename) --
                    var (isValid, errorMessage) = ValidateFile(file);
                    if (!isValid)
                    {
                        _logger.LogWarning(
                            "FILE_REJECTED | Reason: {Reason} | Form: {FormType}",
                            errorMessage, formType);
                        result.Errors.Add($"File '{file.FileName}': {errorMessage}");
                        continue;
                    }

                    // -- Layer 6: Deep content validation ---------------------
                    var contentResult = await _contentValidator.ValidateAsync(file);
                    if (!contentResult.IsValid)
                    {
                        _logger.LogWarning(
                            "SECURITY_EVENT | DEEP_VALIDATION_FAILED | Type: {Type} | Threat: {Threat} | Form: {FormType}",
                            contentResult.ValidationType, contentResult.ThreatDescription ?? "n/a", formType);
                        // Return a generic message to the user — don't leak internal details
                        result.Errors.Add($"File '{file.FileName}': File failed validation.");
                        continue;
                    }

                    _logger.LogDebug(
                        "DEEP_VALIDATION_PASSED | ValidationType: {Type}",
                        contentResult.ValidationType);

                    // -- Layer 7: Virus scan (only when enabled in config) -----
                    var scanOutcome = await RunVirusScanAsync(file, formType, sanitizedLastName, submissionFolder);

                    switch (scanOutcome)
                    {
                        case VirusScanOutcome.Clean:
                            scanClean++;
                            break;

                        case VirusScanOutcome.Infected:
                            result.Errors.Add($"File '{file.FileName}': File rejected.");
                            infectedRejected++;
                            continue; // skip writing this file

                        case VirusScanOutcome.NotScanned:
                            scanNotScanned++;
                            break;
                    }

                    // -- Layer 8: Generate secure filename and write to disk ---
                    var extension    = Path.GetExtension(file.FileName).ToLowerInvariant();
                    var randomSuffix = GenerateRandomString(8);
                    var newFileName  = $"{sanitizedLastName}{dateStamp}{formType}Doc{fileIndex}{randomSuffix}{extension}";
                    var filePath     = Path.Combine(fullUploadPath, newFileName);

                    // Per-file path traversal check — uses PathHelper to avoid prefix-confusion bug.
                    var normalizedFilePath = Path.GetFullPath(filePath);
                    if (!PathHelper.IsPathUnderBase(normalizedFilePath, normalizedPath))
                    {
                        _logger.LogError(
                            "SECURITY_EVENT | FILE_PATH_TRAVERSAL | ResolvedPath: {Path}",
                            filePath);
                        result.Errors.Add($"Invalid file path for '{file.FileName}'.");
                        continue;
                    }

                    try
                    {
                        await WriteFileToDiskAsync(file, filePath, newFileName, fileIndex);
                        result.UploadedFilePaths.Add(filePath);
                        fileIndex++;
                    }
                    catch (InvalidOperationException opEx)
                    {
                        // Raised by WriteFileToDiskAsync when encryption is misconfigured
                        _logger.LogError(opEx,
                            "FILE_SAVE_BLOCKED | Path: {Path}", filePath);
                        result.Errors.Add("File upload is temporarily unavailable due to a server configuration issue. Please contact the library.");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex,
                            "FILE_SAVE_ERROR | Path: {Path}", filePath);
                        result.Errors.Add($"Failed to save '{file.FileName}'. Please try again.");
                    }
                }

                // -- Final summary --------------------------------------------
                result.Success = result.UploadedFilePaths.Count > 0;
                result.ScanCleanCount = scanClean;
                result.ScanNotScannedCount = scanNotScanned;
                result.InfectedRejectedCount = infectedRejected;

                LogUploadOutcome(result, scanClean, scanNotScanned, infectedRejected,
                    submissionFolder, fullUploadPath, formType);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "UPLOAD_EXCEPTION | Unexpected error | Form: {FormType}", formType);
                result.Errors.Add("An unexpected error occurred during file upload.");
            }

            return result;
        }

        /// <summary>
        /// Validate a single file — logs the specific reason for every rejection.
        /// Covers layers 1–5: size, extension, MIME cross-validation, magic bytes, filename.
        /// </summary>
        public (bool IsValid, string? ErrorMessage) ValidateFile(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                _logger.LogWarning("SECURITY_EVENT | VALIDATION_EMPTY_FILE");
                return (false, "File is empty.");
            }

            // -- Layer 1: Size check (max) ------------------------------------
            if (file.Length > _maxFileSizeBytes)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | VALIDATION_TOO_LARGE | Size: {Size:N0} bytes | Limit: {Limit:N0} bytes",
                    file.Length, _maxFileSizeBytes);
                return (false, $"File exceeds maximum size of {_maxFileSizeBytes / 1024 / 1024}MB.");
            }

            // -- Layer 2: Extension check -------------------------------------
            var extension = Path.GetExtension(file.FileName)?.ToLowerInvariant();
            if (string.IsNullOrEmpty(extension) || !AllowedExtensions.Contains(extension))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | BLOCKED_EXTENSION | Extension: {Ext} | ContentType: {CT}",
                    extension ?? "(none)", file.ContentType);
                return (false, $"File type '{extension}' is not allowed. Allowed types: JPG, JPEG, PNG, WEBP, PDF.");
            }

            // -- Size check (min per format) ----------------------------------
            if (MinFileSizeByExtension.TryGetValue(extension, out int minSize) && file.Length < minSize)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | VALIDATION_TOO_SMALL | Extension: {Ext} | Size: {Size} | MinRequired: {Min}",
                    extension, file.Length, minSize);
                return (false, "File is too small to be a valid document. It may be empty or corrupted.");
            }

            // -- Layer 3: MIME type cross-validation (extension ↔ MIME must agree) --
            if (!AllowedMimeTypes.Contains(file.ContentType))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | BLOCKED_MIME | ClaimedExtension: {Ext} | ReportedMimeType: {CT}",
                    extension, file.ContentType);
                return (false, "File content type does not match an allowed type.");
            }

            if (ExtensionToMimeMap.TryGetValue(extension, out var validMimes) &&
                !validMimes.Contains(file.ContentType))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | MIME_EXTENSION_MISMATCH | Extension: {Ext} | ReportedMime: {CT} | " +
                    "ExpectedMimes: [{Expected}]",
                    extension, file.ContentType, string.Join(", ", validMimes));
                return (false, "File extension does not match its content type.");
            }

            // -- Layer 4: Magic bytes check -----------------------------------
            var (magicOk, actualBytes, detectedAs) = ValidateFileSignatureDetailed(file, extension);
            if (!magicOk)
            {
                if (!string.IsNullOrEmpty(detectedAs))
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | MAGIC_BYTE_MISMATCH | ClaimedExtension: {Ext} | ClaimedMime: {CT} | ActualBytes: {Bytes} | DetectedAs: {Detected} | POSSIBLE_DISGUISED_MALWARE",
                        extension, file.ContentType, actualBytes, detectedAs);
                }
                else
                {
                    _logger.LogWarning(
                        "SECURITY_EVENT | MAGIC_BYTE_MISMATCH | ClaimedExtension: {Ext} | ClaimedMime: {CT} | ActualBytes: {Bytes} | DetectedAs: Unknown",
                        extension, file.ContentType, actualBytes);
                }
                return (false, "File content does not match its extension. File may be corrupted or malicious.");
            }

            _logger.LogDebug("MAGIC_BYTES_OK | Extension: {Ext} | HeaderBytes: {Bytes}",
                extension, actualBytes);

            // -- Layer 5: Suspicious filename check ---------------------------
            var (suspicious, suspiciousReason) = ContainsSuspiciousPatterns(file.FileName);
            if (suspicious)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | SUSPICIOUS_FILENAME | Reason: {Reason}",
                    suspiciousReason);
                return (false, "File name contains invalid characters or patterns.");
            }

            _logger.LogDebug("VALIDATION_PASS | Size: {Size:N0} bytes | Ext: {Ext} | Mime: {CT}",
                file.Length, extension, file.ContentType);

            return (true, null);
        }

        public bool IsValidFileType(IFormFile file)
        {
            if (file == null) return false;
            var extension = Path.GetExtension(file.FileName)?.ToLowerInvariant();
            return !string.IsNullOrEmpty(extension) && AllowedExtensions.Contains(extension);
        }

        /// <summary>
        /// Returns a decrypted MemoryStream for staff file viewing.
        /// Detects AES-256-GCM encrypted files via the ENCGCM marker;
        /// unencrypted files are served as-is.
        /// Caller must dispose the returned stream.
        ///
        /// Uses Span-based slicing to avoid intermediate array allocations
        /// on the decryption hot path.
        /// </summary>
        public async Task<(Stream? Stream, string ContentType)> GetDecryptedFileStreamAsync(string filePath)
        {
            var contentType = GetContentType(filePath);

            if (!File.Exists(filePath))
            {
                _logger.LogWarning("FILE_DECRYPT_NOT_FOUND | File not found at {Path}", filePath);
                return (null, contentType);
            }

            try
            {
                var rawBytes = await File.ReadAllBytesAsync(filePath);

                // Check for the GCM format prefix (ENCGCM\0) to detect versioned encrypted files
                if (rawBytes.Length >= GcmFormatPrefix.Length + 1 &&
                    rawBytes.AsSpan(0, GcmFormatPrefix.Length).SequenceEqual(GcmFormatPrefix))
                {
                    var version = rawBytes[GcmFormatPrefix.Length];
                    if (version != SupportedGcmFormatVersion)
                    {
                        _logger.LogWarning(
                            "FILE_DECRYPT_UNSUPPORTED_VERSION | Path: {Path} | Version: 0x{Version:X2} | Supported: 0x{Supported:X2}",
                            filePath, version, SupportedGcmFormatVersion);
                        return (null, contentType);
                    }
                }

                // Full GCM detection: marker (8) + nonce (12) + tag (16) + at least 0 bytes ciphertext
                bool isGcmEncrypted = rawBytes.Length >= GcmHeaderSize &&
                    rawBytes.AsSpan(0, GcmEncryptedFileMarker.Length).SequenceEqual(GcmEncryptedFileMarker);

                if (isGcmEncrypted)
                {
                    if (_encryptionKey == null)
                    {
                        _logger.LogError("FILE_DECRYPT_NO_KEY | GCM file encrypted but no key configured. Path: {Path}", filePath);
                        return (null, contentType);
                    }

                    // Extract nonce, tag, and ciphertext using Span slicing — zero intermediate allocations.
                    int offset = GcmEncryptedFileMarker.Length;
                    var nonce      = rawBytes.AsSpan(offset, GcmNonceSize).ToArray();
                    offset += GcmNonceSize;
                    var tag        = rawBytes.AsSpan(offset, GcmTagSize).ToArray();
                    offset += GcmTagSize;
                    var ciphertext = rawBytes.AsSpan(offset).ToArray();

                    byte[]? plaintext = TryDecryptGcm(ciphertext, nonce, tag, _encryptionKey);
                    if (plaintext == null && _legacyEncryptionKey != null)
                    {
                        plaintext = TryDecryptGcm(ciphertext, nonce, tag, _legacyEncryptionKey);
                        if (plaintext != null)
                        {
                            _logger.LogInformation(
                                "FILE_DECRYPT_SUCCESS | GCM-LEGACY-KEY | {Path} ({Bytes:N0} plain bytes)",
                                filePath, plaintext.Length);
                        }
                    }

                    if (plaintext == null)
                    {
                        _logger.LogError(
                            "FILE_DECRYPT_ERROR | Authentication failed for all configured keys. Path: {Path}",
                            filePath);
                        return (null, contentType);
                    }

                    var plainMs = new MemoryStream(plaintext);
                    _logger.LogInformation(
                        "FILE_DECRYPT_SUCCESS | GCM | {Path} ({Bytes:N0} plain bytes)",
                        filePath, plaintext.Length);
                    return (plainMs, contentType);
                }
                else
                {
                    _logger.LogInformation(
                        "FILE_DECRYPT_LEGACY | Serving legacy unencrypted file {Path}", filePath);
                    return (new MemoryStream(rawBytes), contentType);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "FILE_DECRYPT_ERROR | Failed to read/decrypt {Path}", filePath);
                return (null, contentType);
            }
        }

        // ── Private helpers ──────────────────────────────────────────────

        /// <summary>
        /// Virus scan outcome — replaces the previous goto-based control flow
        /// with an explicit enum for clarity.
        /// </summary>
        private enum VirusScanOutcome { Clean, Infected, NotScanned }

        /// <summary>
        /// Runs the virus scan pipeline for a single file.
        ///
        /// Scan policy:
        ///   - Scanner says clean            → accept, return Clean
        ///   - Scanner says infected          → return Infected (caller rejects)
        ///   - Scanner unavailable/error      → accept, return NotScanned
        ///     (file already passed all validation layers 1–6)
        ///   - Never map unavailable to Clean
        ///   - Never reject solely because scanner is unavailable
        /// </summary>
        private async Task<VirusScanOutcome> RunVirusScanAsync(
            IFormFile file, string formType, string sanitizedLastName, string submissionFolder)
        {
            if (!_virusScanEnabled)
            {
                _logger.LogDebug("VIRUS_SCAN_NOT_SCANNED | VirusScan:Enabled=false");
                return VirusScanOutcome.NotScanned;
            }

            _logger.LogInformation(
                "VIRUS_SCAN_INITIATED | File: {FileName} | Size: {SizeKB} KB | FormType: {FormType} | PatronLastName: {LastName} | Folder: {Folder}",
                file.FileName, file.Length / 1024, formType, sanitizedLastName, submissionFolder);

            VirusScanResult scanResult;
            try
            {
                scanResult = await _virusScanService.ScanFileAsync(file);
            }
            catch (Exception ex)
            {
                // Scanner threw an exception (timeout, connection refused, crash).
                // File passed all validation — accept but mark as NotScanned.
                _logger.LogWarning(ex,
                    "VIRUS_SCAN_ERROR | Scanner: {Scanner} | File: {FileName} | FormType: {FormType} | " +
                    "File accepted as NotScanned (passed validation layers 1–6). " +
                    "Scanner exception does not block validated uploads.",
                    _virusScanService.ScannerName, file.FileName, formType);
                return VirusScanOutcome.NotScanned;
            }

            if (scanResult.ScanSuccessful && scanResult.IsClean)
            {
                _logger.LogInformation(
                    "VIRUS_SCAN_CLEAN | Scanner: {Scanner} | File: {FileName} | FormType: {FormType} | Duration: {Ms}ms",
                    _virusScanService.ScannerName, file.FileName, formType, scanResult.ScanDurationMs);
                return VirusScanOutcome.Clean;
            }

            if (scanResult.ScanSuccessful && !scanResult.IsClean)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | VIRUS_DETECTED | Scanner: {Scanner} | File: {FileName} | Threat: {Threat} | FormType: {FormType} | PatronLastName: {LastName}",
                    _virusScanService.ScannerName, file.FileName, scanResult.ThreatName ?? "unknown", formType, sanitizedLastName);
                return VirusScanOutcome.Infected;
            }

            // Scanner returned but scan was not successful (unavailable, error, timeout).
            _logger.LogWarning(
                "VIRUS_SCAN_OPERATIONAL_FAILURE | Scanner: {Scanner} | File: {FileName} | Message: {Msg} | FormType: {FormType} | " +
                "File accepted as NotScanned (passed validation layers 1–6).",
                _virusScanService.ScannerName, file.FileName, scanResult.Message, formType);
            return VirusScanOutcome.NotScanned;
        }

        /// <summary>
        /// Write a validated file to permanent storage, optionally encrypting with AES-256-GCM.
        /// Zeroes plaintext buffers after encryption to minimize exposure window in memory.
        /// Throws InvalidOperationException if encryption is enabled but no key is available.
        /// </summary>
        private async Task WriteFileToDiskAsync(IFormFile file, string filePath, string newFileName, int fileIndex)
        {
            if (_encryptionEnabled && _encryptionKey == null)
            {
                _logger.LogError(
                    "SECURITY_EVENT | UPLOAD_BLOCKED_NO_KEY | " +
                    "Encryption is enabled but no valid key is configured. File rejected to prevent unencrypted storage.");
                throw new InvalidOperationException("Encryption enabled but no key configured.");
            }

            if (_encryptionEnabled && _encryptionKey != null)
            {
                using var ms = new MemoryStream();
                await file.CopyToAsync(ms);
                ms.Position = 0;

                // AES-256-GCM: authenticated encryption — any tampering
                // (bit-flip, truncation, substitution) is detected at decrypt
                // time via the 128-bit authentication tag.
                //
                // File layout: [8 marker][12 nonce][16 tag][ciphertext]
                var nonce      = new byte[GcmNonceSize];
                var tag        = new byte[GcmTagSize];
                var plaintext  = ms.ToArray();
                var ciphertext = new byte[plaintext.Length];
                RandomNumberGenerator.Fill(nonce);

                try
                {
                    using (var gcm = new AesGcm(_encryptionKey, GcmTagSize))
                        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

                    using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);
                    await fs.WriteAsync(GcmEncryptedFileMarker);
                    await fs.WriteAsync(nonce);
                    await fs.WriteAsync(tag);
                    await fs.WriteAsync(ciphertext);
                }
                finally
                {
                    // Zero plaintext as soon as possible to minimize exposure in memory.
                    // Not a guarantee (GC may have copies) but reduces the window.
                    CryptographicOperations.ZeroMemory(plaintext);
                }

                _logger.LogInformation(
                    "FILE_ENCRYPT_SUCCESS | SavedAs: {NewName} | Size: {Size:N0} bytes | Index: {Index}",
                    newFileName, file.Length, fileIndex);
            }
            else
            {
                using var stream = new FileStream(filePath, FileMode.Create);
                await file.CopyToAsync(stream);

                _logger.LogInformation(
                    "FILE_SAVED | SavedAs: {NewName} | Size: {Size:N0} bytes | Index: {Index}",
                    newFileName, file.Length, fileIndex);
            }
        }

        /// <summary>
        /// Validates magic bytes and returns the actual header bytes and a human-readable
        /// identification of what the file really is (if it doesn't match the claimed type).
        /// For WebP, additionally validates the WEBP fourCC at offset 8.
        /// </summary>
        private (bool IsValid, string ActualBytesHex, string? DetectedAs) ValidateFileSignatureDetailed(
            IFormFile file, string extension)
        {
            if (!FileSignatures.TryGetValue(extension, out var signatures))
                return (false, string.Empty, "No signature defined — fail closed");

            try
            {
                // NOTE: IFormFile.OpenReadStream() returns a new stream each call,
                // so this does not interfere with the later CopyToAsync in Layer 8.
                using var reader = new BinaryReader(file.OpenReadStream());

                // Read enough bytes for the longest signature check plus WebP fourCC at offset 8
                int readLen = Math.Max(signatures.Max(s => s.Length), 12);
                var headerBytes = reader.ReadBytes(readLen);
                var headerHex   = BitConverter.ToString(headerBytes).Replace("-", "").ToUpperInvariant();

                // Check against allowed signatures
                foreach (var signature in signatures)
                {
                    if (headerBytes.Length >= signature.Length)
                    {
                        bool match = true;
                        for (int i = 0; i < signature.Length; i++)
                        {
                            if (headerBytes[i] != signature[i]) { match = false; break; }
                        }
                        if (match)
                        {
                            // WebP requires additional check: bytes 8–11 must be "WEBP".
                            // Extension is already lowercased, so ordinal comparison is correct.
                            if (extension == ".webp")
                            {
                                if (headerBytes.Length < 12 ||
                                    headerBytes[8]  != 0x57 || headerBytes[9]  != 0x45 ||
                                    headerBytes[10] != 0x42 || headerBytes[11] != 0x50)
                                {
                                    return (false, headerHex, "RIFF container but not WebP (possibly AVI/WAV)");
                                }
                            }
                            return (true, headerHex, null);
                        }
                    }
                }

                // Signature mismatch — try to identify the actual content
                string? detectedAs = null;
                foreach (var (sigHex, description) in KnownDangerousSignatures)
                {
                    if (headerHex.StartsWith(sigHex, StringComparison.OrdinalIgnoreCase))
                    {
                        detectedAs = description;
                        break;
                    }
                }

                return (false, headerHex, detectedAs);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MAGIC_BYTE_READ_ERROR");
                return (false, "ERROR", null);
            }
        }

        /// <summary>
        /// Check for suspicious patterns in file names.
        /// Detects: path traversal, null bytes, Unicode tricks, control characters,
        /// double extensions (e.g. photo.php.jpg), dangerous extensions in the stem,
        /// Windows ADS (alternate data streams), and Windows reserved device names.
        /// </summary>
        private static (bool IsSuspicious, string? Reason) ContainsSuspiciousPatterns(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return (true, "Empty filename");

            if (fileName.Contains(".."))
                return (true, "Path traversal sequence (..)");

            if (fileName.Contains('/') || fileName.Contains('\\'))
                return (true, "Path separator in filename");

            if (fileName.Contains('\0'))
                return (true, "Null byte in filename");

            // Windows NTFS alternate data streams — "file.jpg:payload.exe"
            if (fileName.Contains(':'))
                return (true, "Colon in filename (possible NTFS ADS attack)");

            // Detect Unicode directional override characters (RTL/LTR tricks)
            foreach (var c in fileName)
            {
                if (c == '\u202E' || c == '\u200F' || c == '\u200E' ||   // RTL/LTR overrides
                    c == '\u202A' || c == '\u202B' || c == '\u202C' ||   // Embedding controls
                    c == '\u202D' || c == '\u2066' || c == '\u2067' ||   // Directional isolates
                    c == '\u2068' || c == '\u2069' ||
                    c == '\u200B' || c == '\u200C' || c == '\u200D' ||   // Zero-width joiners
                    c == '\uFEFF' ||                                      // BOM / zero-width no-break space
                    char.IsControl(c))                                    // Any other control chars
                {
                    return (true, "Control or Unicode directional character in filename");
                }
            }

            // Windows reserved device names
            var stem = Path.GetFileNameWithoutExtension(fileName)?.ToUpperInvariant() ?? "";
            if (WindowsReservedNames.Contains(stem))
                return (true, $"Windows reserved device name: {stem}");

            // Double-extension detection: check if ANY dangerous extension appears
            // in the filename stem (the part before the final extension).
            var nameWithoutFinalExt = Path.GetFileNameWithoutExtension(fileName);
            if (!string.IsNullOrEmpty(nameWithoutFinalExt))
            {
                foreach (var dangerousExt in DangerousExtensions)
                {
                    if (nameWithoutFinalExt.EndsWith(dangerousExt, StringComparison.OrdinalIgnoreCase) ||
                        nameWithoutFinalExt.Contains(dangerousExt + ".", StringComparison.OrdinalIgnoreCase))
                    {
                        return (true, $"Double-extension detected: stem contains '{dangerousExt}'");
                    }
                }
            }

            return (false, null);
        }

        private static string SanitizeFileName(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName)) return "unknown";
            fileName = Path.GetFileNameWithoutExtension(fileName);
            var sanitized = new StringBuilder();
            foreach (var c in fileName)
            {
                // Only allow ASCII letters and digits — strip everything else.
                // This eliminates Unicode homoglyphs, CRLF injection, control
                // characters, and non-Latin script issues in one pass.
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
                    sanitized.Append(c);
            }
            var result = sanitized.ToString();
            if (string.IsNullOrWhiteSpace(result)) return "unknown";
            if (result.Length > 50) result = result.Substring(0, 50);
            return result;
        }

        /// <summary>
        /// Generates a cryptographically random alphanumeric string.
        /// Uses RandomNumberGenerator.GetInt32 to eliminate modulo bias
        /// that would occur with raw byte % charsetLength.
        /// </summary>
        private static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var result = new char[length];
            for (int i = 0; i < length; i++)
                result[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
            return new string(result);
        }

        private static byte[]? TryDecryptGcm(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
        {
            try
            {
                var plaintext = new byte[ciphertext.Length];
                using var gcm = new AesGcm(key, GcmTagSize);
                gcm.Decrypt(nonce, ciphertext, tag, plaintext);
                return plaintext;
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        // ── Storage root validation ──────────────────────────────────────

        /// <summary>
        /// Resolves the configured storage root to an absolute, canonical path
        /// and validates it is safe (not under or equal to wwwroot).
        /// Throws InvalidOperationException on misconfiguration — fail closed.
        ///
        /// Traversal check runs on the raw configured value BEFORE resolution,
        /// so ".." sequences cannot be silently canonicalized away.
        /// </summary>
        private string ResolveAndValidateStorageRoot()
        {
            var configured = _configuration["FileUpload:StorageRoot"];

            // Validate BEFORE resolution: reject ".." in the raw config value
            // so traversal can't be silently canonicalized away by Path.GetFullPath.
            if (!string.IsNullOrEmpty(configured) && configured.Contains(".."))
            {
                _logger.LogError(
                    "SECURITY_EVENT | STORAGE_ROOT_TRAVERSAL | Configured: {Configured}",
                    configured);
                throw new InvalidOperationException(
                    $"FileUpload:StorageRoot contains path traversal characters: '{configured}'");
            }

            // Resolve against Storage:DataRoot (or fallback to ContentRootPath/App_Data)
            string resolved = PathHelper.ResolveDataPath(
                configured, _configuration, _environment.ContentRootPath, "UploadedFiles");

            // Validate: must not be under or equal to wwwroot
            var wwwroot = Path.GetFullPath(_environment.WebRootPath);

            if (PathHelper.IsPathUnderBase(resolved, wwwroot) ||
                string.Equals(resolved,
                    wwwroot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError(
                    "SECURITY_EVENT | STORAGE_ROOT_UNDER_WWWROOT | Resolved: {Resolved} | WebRoot: {WebRoot}",
                    resolved, wwwroot);
                throw new InvalidOperationException(
                    $"FileUpload:StorageRoot resolves under wwwroot which is not allowed. " +
                    $"Resolved: '{resolved}', WebRoot: '{wwwroot}'");
            }

            // Ensure the directory exists (create if needed)
            if (!Directory.Exists(resolved))
            {
                try
                {
                    Directory.CreateDirectory(resolved);
                    _logger.LogInformation(
                        "STORAGE_ROOT_CREATED | Path: {Path}", resolved);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex,
                        "SECURITY_EVENT | STORAGE_ROOT_CREATE_FAILED | Path: {Path}", resolved);
                    throw new InvalidOperationException(
                        $"Cannot create FileUpload:StorageRoot directory: '{resolved}'", ex);
                }
            }

            return resolved;
        }

        // ── Capacity management ──────────────────────────────────────────

        private (bool IsOk, string? ErrorMessage) EnsureCapacityForUpload(long incomingBytes, string formType)
        {
            var storageFree = TryGetDriveFreeBytes(_storageRoot);
            var tempFree = TryGetDriveFreeBytes(Path.GetTempPath());

            if (storageFree.HasValue && storageFree.Value < _lowDiskWarningBytes)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | LOW_DISK_WARNING | Location: UploadStorage | FreeBytes: {Free:N0} | WarningThreshold: {Threshold:N0} | Form: {FormType}",
                    storageFree.Value, _lowDiskWarningBytes, formType);
            }

            if (tempFree.HasValue && tempFree.Value < _lowDiskWarningBytes)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | LOW_DISK_WARNING | Location: TempStorage | FreeBytes: {Free:N0} | WarningThreshold: {Threshold:N0} | Form: {FormType}",
                    tempFree.Value, _lowDiskWarningBytes, formType);
            }

            if (storageFree.HasValue && IsBelowRequiredFree(storageFree.Value, incomingBytes, _minStorageFreeBytes))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | UPLOAD_REJECTED_LOW_STORAGE | FreeBytes: {Free:N0} | Incoming: {Incoming:N0} | MinReserve: {Reserve:N0} | Form: {FormType}",
                    storageFree.Value, incomingBytes, _minStorageFreeBytes, formType);
                return (false, "Upload is temporarily unavailable due to server capacity. Please try again later.");
            }

            if (tempFree.HasValue && IsBelowRequiredFree(tempFree.Value, incomingBytes, _minTempFreeBytes))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | UPLOAD_REJECTED_LOW_TEMP_STORAGE | FreeBytes: {Free:N0} | Incoming: {Incoming:N0} | MinReserve: {Reserve:N0} | Form: {FormType}",
                    tempFree.Value, incomingBytes, _minTempFreeBytes, formType);
                return (false, "Upload is temporarily unavailable due to server capacity. Please try again later.");
            }

            return (true, null);
        }

        private static bool IsBelowRequiredFree(long freeBytes, long incomingBytes, long reserveBytes)
        {
            if (freeBytes < incomingBytes)
                return true;

            var remainingAfterIncoming = freeBytes - incomingBytes;
            return remainingAfterIncoming < reserveBytes;
        }

        private long? TryGetDriveFreeBytes(string path)
        {
            try
            {
                var root = Path.GetPathRoot(Path.GetFullPath(path));
                if (string.IsNullOrWhiteSpace(root))
                    return null;

                var drive = new DriveInfo(root);
                return drive.AvailableFreeSpace;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "UPLOAD_STORAGE_CAPACITY_CHECK_FAILED | Path: {Path} | Continuing without capacity guard for this path.",
                    path);
                return null;
            }
        }

        // ── Logging helpers ──────────────────────────────────────────────

        /// <summary>
        /// Logs the final upload outcome and cleans up empty submission folders.
        /// Extracted to keep UploadFilesAsync focused on the pipeline itself.
        /// </summary>
        private void LogUploadOutcome(
            FileUploadResult result,
            int scanClean, int scanNotScanned, int infectedRejected,
            string submissionFolder, string fullUploadPath, string formType)
        {
            if (result.SavedCount == result.SubmittedCount)
            {
                _logger.LogInformation(
                    "UPLOAD_ALL_SAVED | Submitted: {Submitted} | Saved: {Saved} | " +
                    "ScanClean: {Clean} | NotScanned: {NotScanned} | Folder: {Folder} | Form: {FormType}",
                    result.SubmittedCount, result.SavedCount,
                    scanClean, scanNotScanned, submissionFolder, formType);
            }
            else if (result.SavedCount > 0)
            {
                _logger.LogWarning(
                    "UPLOAD_PARTIAL_SAVED | Submitted: {Submitted} | Saved: {Saved} | Rejected: {Rejected} | " +
                    "ScanClean: {Clean} | NotScanned: {NotScanned} | InfectedRejected: {Infected} | " +
                    "Folder: {Folder} | Form: {FormType}",
                    result.SubmittedCount, result.SavedCount, result.RejectedCount,
                    scanClean, scanNotScanned, infectedRejected, submissionFolder, formType);
            }
            else
            {
                _logger.LogWarning(
                    "UPLOAD_ALL_REJECTED | Submitted: {Submitted} | Saved: 0 | " +
                    "InfectedRejected: {Infected} | Errors: {ErrorCount} | Form: {FormType}",
                    result.SubmittedCount, infectedRejected, result.Errors.Count, formType);

                // Clean up the empty submission folder — no files were saved so
                // the folder is just an empty orphan on disk.
                TryRemoveEmptyFolder(fullUploadPath, submissionFolder, formType);
            }
        }

        private void TryRemoveEmptyFolder(string fullUploadPath, string submissionFolder, string formType)
        {
            try
            {
                if (Directory.Exists(fullUploadPath) &&
                    Directory.GetFiles(fullUploadPath, "*", SearchOption.AllDirectories).Length == 0)
                {
                    Directory.Delete(fullUploadPath, recursive: true);
                    _logger.LogInformation(
                        "UPLOAD_EMPTY_FOLDER_REMOVED | Folder: {Folder} | Form: {FormType}",
                        submissionFolder, formType);
                }
            }
            catch (Exception cleanupEx)
            {
                _logger.LogWarning(cleanupEx,
                    "UPLOAD_FOLDER_CLEANUP_FAILED | Folder: {Folder} | Form: {FormType}",
                    submissionFolder, formType);
            }
        }

        private static string GetContentType(string filePath) =>
            ContentTypeMap.TryGetValue(
                Path.GetExtension(filePath).ToLowerInvariant(),
                out var ct)
                ? ct
                : "application/octet-stream";
    }
}