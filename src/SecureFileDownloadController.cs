using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using SecureFileUpload.Utilities;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Reference controller for serving decrypted patron documents back to authenticated staff.
    ///
    /// Why this file exists:
    ///   The 8-layer pipeline protects the file at upload time. Once a staff member
    ///   downloads the decrypted plaintext, the **browser** becomes a new attack
    ///   surface. A PDF rendered inline can run JavaScript via Acrobat plugins.
    ///   An image served with a permissive Content-Type can be sniffed as HTML by
    ///   old browsers. This handler closes those final-mile gaps with strict response
    ///   headers, mandatory attachment download, and a per-request path-traversal
    ///   re-check.
    ///
    /// Threat model (this file only):
    ///   • Compromised staff browser tries to render hostile PDF inline → blocked
    ///     by `Content-Disposition: attachment` + `Content-Security-Policy`.
    ///   • Old browser MIME-sniffs an image as HTML → blocked by `X-Content-Type-Options: nosniff`.
    ///   • Decrypted file embedded in iframe on attacker site → blocked by
    ///     `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
    ///   • Cached decrypted patron documents on shared/proxy server → blocked by
    ///     `Cache-Control: no-store, private`.
    ///   • Path-traversal via `?file=../../etc/passwd` → blocked by `IsPathUnderBase`
    ///     re-check inside the handler (defence-in-depth on top of upload-time check).
    ///   • Filename injection in `Content-Disposition` header (CRLF / quote escape)
    ///     → blocked by RFC 6266 `filename*` UTF-8 encoding via `ContentDispositionHeaderValue`.
    ///
    /// Usage:
    ///   Wire this controller (or an action with an equivalent shape) under an
    ///   authenticated, authorised, MFA-gated staff route. Do NOT expose anonymously.
    /// </summary>
    [ApiController]
    [Route("staff/files")]
    public sealed class SecureFileDownloadController : ControllerBase
    {
        private readonly IFileUploadService _uploadService;
        private readonly ILogger<SecureFileDownloadController> _logger;

        // Only these content types are ever returned. Anything else is forced to
        // application/octet-stream — the browser cannot guess a renderable type.
        private static readonly string[] PermittedExtensions =
            { ".jpg", ".jpeg", ".png", ".webp", ".pdf" };

        public SecureFileDownloadController(
            IFileUploadService uploadService,
            ILogger<SecureFileDownloadController> logger)
        {
            _uploadService = uploadService;
            _logger = logger;
        }

        /// <summary>
        /// Downloads a decrypted file as an attachment with locked-down response headers.
        /// `relativePath` is interpreted relative to the configured StorageRoot and
        /// re-validated inside the handler.
        /// </summary>
        [HttpGet("download")]
        public async Task<IActionResult> Download([FromQuery] string relativePath)
        {
            // ── 1. Reject obviously hostile input before any IO. ────────────────
            if (string.IsNullOrWhiteSpace(relativePath) ||
                relativePath.Contains("..", StringComparison.Ordinal) ||
                relativePath.Contains('\0') ||
                relativePath.Contains('\r') ||
                relativePath.Contains('\n') ||
                Path.IsPathRooted(relativePath))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | DOWNLOAD_REJECTED_BAD_INPUT | RawInput: {Input}",
                    SanitizeForLog(relativePath));
                return BadRequest("Invalid file reference.");
            }

            // ── 2. Resolve and re-check it lands under the validated StorageRoot. ─
            var storageRoot = _uploadService.StorageRoot;
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(Path.Combine(storageRoot, relativePath));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DOWNLOAD_PATH_RESOLVE_FAILED | Input: {Input}", SanitizeForLog(relativePath));
                return BadRequest("Invalid file reference.");
            }

            if (!PathHelper.IsPathUnderBase(fullPath, storageRoot))
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | DOWNLOAD_PATH_TRAVERSAL | Resolved: {Resolved} | Base: {Base}",
                    fullPath, storageRoot);
                return NotFound();
            }

            // ── 3. Extension allowlist — only the upload-allowed types are served. ─
            var extension = Path.GetExtension(fullPath).ToLowerInvariant();
            bool extensionAllowed = false;
            foreach (var allowed in PermittedExtensions)
            {
                if (extension == allowed) { extensionAllowed = true; break; }
            }
            if (!extensionAllowed)
            {
                _logger.LogWarning(
                    "SECURITY_EVENT | DOWNLOAD_REJECTED_BAD_EXTENSION | Ext: {Ext} | Path: {Path}",
                    extension, fullPath);
                return NotFound();
            }

            // ── 4. Decrypt via the upload service (handles v1 + v2 envelope formats). ─
            var (stream, _) = await _uploadService.GetDecryptedFileStreamAsync(fullPath);
            if (stream is null)
            {
                _logger.LogWarning("DOWNLOAD_NOT_FOUND_OR_UNREADABLE | Path: {Path}", fullPath);
                return NotFound();
            }

            // ── 5. Apply hardened response headers. ─────────────────────────────
            //
            // We deliberately serve EVERYTHING as application/octet-stream and force
            // attachment disposition. The browser must never try to render patron
            // documents inline — even legitimate ones — because:
            //   • Inline PDF rendering can execute embedded JavaScript via Acrobat.
            //   • An old browser may sniff an image as HTML and execute embedded scripts.
            //   • An inline display lets an attacker iframe the file from a hostile site.
            //
            // If a viewer UI is needed, it must explicitly fetch the file, perform its
            // own type-safe rendering (e.g. server-side rasterisation), and never expose
            // a URL that returns the decrypted bytes with a renderable Content-Type.
            ApplyHardenedResponseHeaders();

            // RFC 6266 attachment with a UTF-8 safe filename. The original on-disk
            // filename is already randomized (`{lastName}{date}{form}Doc{n}{rand}.ext`)
            // so it carries no attacker input — but we still encode it correctly to
            // defend against any future caller that passes through a less-clean name.
            var downloadName = Path.GetFileName(fullPath);
            var cd = new ContentDispositionHeaderValue("attachment");
            cd.SetHttpFileName(downloadName);
            Response.Headers[HeaderNames.ContentDisposition] = cd.ToString();

            return File(stream, "application/octet-stream", enableRangeProcessing: false);
        }

        /// <summary>
        /// Applies the hardened header set used for every decrypted-file response.
        /// Extracted so the same headers can be applied from other handlers (preview,
        /// thumbnail) that serve any byte derived from a stored upload.
        /// </summary>
        private void ApplyHardenedResponseHeaders()
        {
            var h = Response.Headers;

            // Stop MIME sniffing — browser must trust our Content-Type and only that.
            h["X-Content-Type-Options"] = "nosniff";

            // Block any framing of the response (defence against clickjacking and
            // hostile-page iframing of decrypted patron documents).
            h["X-Frame-Options"] = "DENY";

            // Tightest possible CSP for a binary download response. The download is
            // forced to disk, but if any browser does try to render it, nothing
            // executes and nothing loads.
            h["Content-Security-Policy"] =
                "default-src 'none'; " +
                "script-src 'none'; " +
                "object-src 'none'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'none'; " +
                "form-action 'none'; " +
                "sandbox";

            // Patron documents are PII — never cache anywhere.
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0";
            h["Pragma"] = "no-cache";
            h["Expires"] = "0";

            // Don't leak the staff URL (which contains the storage path) to other origins.
            h["Referrer-Policy"] = "no-referrer";

            // Disable browser features the response has no business using.
            h["Permissions-Policy"] =
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

            // Cross-origin isolation — prevent embedding or read-across-origin.
            h["Cross-Origin-Resource-Policy"] = "same-origin";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Cross-Origin-Embedder-Policy"] = "require-corp";
        }

        private static string SanitizeForLog(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "(empty)";

            const int max = 128;
            var sb = new StringBuilder(Math.Min(value.Length, max));
            foreach (var c in value)
            {
                if (sb.Length >= max) { sb.Append('…'); break; }
                if (c == '\r' || c == '\n' || c == '\t' || c == '\0' ||
                    c == '|'  || c == '{'  || c == '}'  || c == '\u001B' ||
                    char.IsControl(c))
                { sb.Append('?'); continue; }
                sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
