using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureFileUpload.Utilities;
using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Default implementation of <see cref="IFileAccessTokenService"/>.
    /// Uses ASP.NET Core Data Protection to issue opaque, signed download tokens
    /// so staff-facing URLs do not expose storage-relative file paths.
    /// </summary>
    public sealed class FileAccessTokenService : IFileAccessTokenService
    {
        private readonly ILogger<FileAccessTokenService> _logger;
        private readonly IDataProtector _protector;
        private readonly string _storageRoot;
        private readonly TimeSpan _tokenLifetime;

        private const string ProtectorPurpose = "SecureFileUpload.Services.FileAccessToken.v1";
        private const int DefaultTokenLifetimeMinutes = 15;
        private const int MaxTokenLifetimeMinutes = 24 * 60;

        public FileAccessTokenService(
            ILogger<FileAccessTokenService> logger,
            IDataProtectionProvider dataProtectionProvider,
            IConfiguration configuration,
            IFileUploadService uploadService)
        {
            _logger = logger;
            _protector = dataProtectionProvider.CreateProtector(ProtectorPurpose);
            _storageRoot = uploadService.StorageRoot;

            int configuredLifetimeMinutes = configuration.GetValue<int>(
                "FileDownload:TokenLifetimeMinutes",
                DefaultTokenLifetimeMinutes);

            _tokenLifetime = TimeSpan.FromMinutes(Math.Clamp(
                configuredLifetimeMinutes,
                1,
                MaxTokenLifetimeMinutes));
        }

        public string CreateToken(string storedFilePath)
        {
            if (string.IsNullOrWhiteSpace(storedFilePath))
                throw new ArgumentException("Stored file path is required.", nameof(storedFilePath));

            string fullPath = Path.GetFullPath(storedFilePath);
            if (!PathHelper.IsPathUnderBase(fullPath, _storageRoot))
                throw new InvalidOperationException("Stored file path must be under the configured storage root.");

            string relativePath = Path.GetRelativePath(_storageRoot, fullPath)
                .Replace(Path.DirectorySeparatorChar, '/')
                .Replace(Path.AltDirectorySeparatorChar, '/');

            if (!IsSafeRelativePath(relativePath))
                throw new InvalidOperationException("Stored file path cannot be represented as a safe relative token payload.");

            string payload = string.Create(
                CultureInfo.InvariantCulture,
                $"{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}|{relativePath}");

            string protectedPayload = _protector.Protect(payload);
            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(protectedPayload));
        }

        public bool TryResolveStoredFilePath(string token, out string? storedFilePath)
        {
            storedFilePath = null;

            if (string.IsNullOrWhiteSpace(token))
                return false;

            string payload;
            try
            {
                string protectedPayload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                payload = _protector.Unprotect(protectedPayload);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "FILE_TOKEN_INVALID | Token could not be decoded or unprotected.");
                return false;
            }

            int separatorIndex = payload.IndexOf('|');
            if (separatorIndex <= 0 || separatorIndex >= payload.Length - 1)
                return false;

            if (!long.TryParse(payload[..separatorIndex], NumberStyles.None, CultureInfo.InvariantCulture, out long issuedUnix))
                return false;

            DateTimeOffset issuedAt;
            try
            {
                issuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedUnix);
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }

            if (DateTimeOffset.UtcNow - issuedAt > _tokenLifetime)
            {
                _logger.LogWarning(
                    "FILE_TOKEN_EXPIRED | IssuedAtUtc={IssuedAtUtc:o} | LifetimeMinutes={LifetimeMinutes}",
                    issuedAt.UtcDateTime,
                    _tokenLifetime.TotalMinutes);
                return false;
            }

            string relativePath = payload[(separatorIndex + 1)..];
            if (!IsSafeRelativePath(relativePath))
                return false;

            string fullPath = Path.GetFullPath(Path.Combine(_storageRoot, relativePath));
            if (!PathHelper.IsPathUnderBase(fullPath, _storageRoot))
                return false;

            storedFilePath = fullPath;
            return true;
        }

        private static bool IsSafeRelativePath(string relativePath)
        {
            if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
                return false;

            foreach (char c in relativePath)
            {
                if (c == '\0' || c == '\r' || c == '\n' || char.IsControl(c))
                    return false;
            }

            string[] segments = relativePath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0)
                return false;

            foreach (string segment in segments)
            {
                if (segment == "." || segment == "..")
                    return false;
            }

            return true;
        }
    }
}