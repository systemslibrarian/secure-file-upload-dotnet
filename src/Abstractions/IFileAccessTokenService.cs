using System;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Issues and resolves opaque download tokens for stored files.
    /// Tokens are signed and time-limited; callers never need to expose
    /// raw storage-relative paths to browsers or client-side code.
    /// </summary>
    public interface IFileAccessTokenService
    {
        /// <summary>
        /// Creates an opaque download token for a file already stored beneath the
        /// configured upload storage root.
        /// </summary>
        string CreateToken(string storedFilePath);

        /// <summary>
        /// Resolves an opaque download token back to the absolute stored file path.
        /// Returns <see langword="false"/> for malformed, expired, or tampered tokens.
        /// </summary>
        bool TryResolveStoredFilePath(string token, out string? storedFilePath);
    }
}