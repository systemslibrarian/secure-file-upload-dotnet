using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace SecureFileUpload.Utilities
{
    /// <summary>
    /// Path utilities used throughout the upload and storage pipeline.
    /// Centralised here to ensure consistent canonicalization behaviour
    /// and to defend against the StartsWith prefix-confusion bug
    /// ("/uploads_evil" matching "/uploads").
    /// </summary>
    public static class PathHelper
    {
        /// <summary>
        /// Returns <see langword="true"/> if <paramref name="candidatePath"/> is
        /// strictly inside <paramref name="basePath"/>, or is exactly equal to it.
        ///
        /// Both paths are canonicalized with <see cref="Path.GetFullPath(string)"/> before
        /// comparison. The check appends a directory separator to the base before
        /// testing the prefix so that a sibling folder whose name begins with the
        /// same characters cannot match. For example:
        ///
        ///   basePath      = /var/uploads
        ///   /var/uploads/foo     → true  (strictly inside)
        ///   /var/uploads         → true  (equal to base)
        ///   /var/uploads_evil    → false (different directory, same prefix)
        ///   /var                 → false (parent of base)
        ///
        /// Comparison is case-insensitive on Windows, case-sensitive on Linux/macOS
        /// (inheriting the platform's <see cref="StringComparison.OrdinalIgnoreCase"/>
        /// vs. <see cref="StringComparison.Ordinal"/> behaviour).
        /// </summary>
        public static bool IsPathUnderBase(string candidatePath, string basePath)
        {
            if (string.IsNullOrEmpty(candidatePath) || string.IsNullOrEmpty(basePath))
                return false;

            var comparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            var candidate = Path.GetFullPath(candidatePath)
                               .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var baseNorm  = Path.GetFullPath(basePath)
                               .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            // Equal (base itself) counts as "under base" for directory existence checks.
            if (string.Equals(candidate, baseNorm, comparison))
                return true;

            // Must start with base + the platform separator to avoid the prefix-confusion bug.
            return candidate.StartsWith(baseNorm + Path.DirectorySeparatorChar, comparison);
        }

        /// <summary>
        /// Resolves a data-storage root path from application configuration and
        /// the application content root.
        ///
        /// Resolution priority:
        ///   <list type="number">
        ///     <item><paramref name="configuredPath"/> — if non-empty, resolved relative
        ///       to <paramref name="contentRootPath"/> when relative, used as-is when absolute.</item>
        ///     <item><c>Storage:DataRoot</c> entry in <paramref name="configuration"/> — same rules.</item>
        ///     <item>Fallback: <c><paramref name="contentRootPath"/>/<paramref name="defaultFolderName"/></c>.</item>
        ///   </list>
        ///
        /// Always returns a canonicalized absolute path via
        /// <see cref="Path.GetFullPath(string, string)"/>.
        /// </summary>
        public static string ResolveDataPath(
            string? configuredPath,
            IConfiguration configuration,
            string contentRootPath,
            string defaultFolderName)
        {
            if (!string.IsNullOrWhiteSpace(configuredPath))
            {
                return Resolve(configuredPath, contentRootPath);
            }

            var dataRoot = configuration["Storage:DataRoot"];
            if (!string.IsNullOrWhiteSpace(dataRoot))
            {
                return Resolve(dataRoot, contentRootPath);
            }

            return Path.GetFullPath(Path.Combine(contentRootPath, defaultFolderName));
        }

        // ── Private helpers ──────────────────────────────────────────────

        private static string Resolve(string path, string basePath) =>
            Path.IsPathRooted(path)
                ? Path.GetFullPath(path)
                : Path.GetFullPath(Path.Combine(basePath, path));
    }
}
