using Microsoft.AspNetCore.Http;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Abstraction for virus/malware scanning of uploaded files.
    ///
    /// Two implementations are provided:
    ///   <list type="bullet">
    ///     <item><see cref="WindowsDefenderScanService"/> — invokes <c>MpCmdRun.exe</c>.
    ///       Requires Windows. Writes a temp file (zeroed before deletion).</item>
    ///     <item><see cref="ClamAvScanService"/> — streams bytes to <c>clamd</c> over TCP
    ///       using the documented <c>zINSTREAM</c> protocol. Cross-platform. No temp file.</item>
    ///   </list>
    ///
    /// Both implementations return a <see cref="VirusScanResult"/> with two independent flags:
    ///   <list type="bullet">
    ///     <item><see cref="VirusScanResult.ScanSuccessful"/> — did the scan engine complete
    ///       and assess the file? <see langword="false"/> means scanner was unavailable,
    ///       timed out, or threw an unexpected error.</item>
    ///     <item><see cref="VirusScanResult.IsClean"/> — did the engine find no threats?
    ///       Only meaningful when <c>ScanSuccessful</c> is <see langword="true"/>.</item>
    ///   </list>
    ///
    /// <see cref="FileUploadService"/> decides how to handle each combination:
    ///   <list type="bullet">
    ///     <item>Clean + Successful → accept.</item>
    ///     <item>Not Clean + Successful → reject (infected).</item>
    ///     <item>Not Successful (any reason) → accept as <c>NotScanned</c> and count in
    ///       <see cref="FileUploadResult.ScanNotScannedCount"/>. The file already passed
    ///       Layers 1–6; availability failure is fail-open by design. See
    ///       <c>KNOWN-GAPS.md §Gap 9</c>.</item>
    ///   </list>
    /// </summary>
    public interface IVirusScanService
    {
        /// <summary>Human-readable name of the scanner engine, used in logs and results.</summary>
        string ScannerName { get; }

        /// <summary>
        /// Scans a single uploaded <see cref="IFormFile"/> for malware.
        /// The stream is rewound to position 0 before scanning where seekable.
        /// </summary>
        Task<VirusScanResult> ScanFileAsync(IFormFile file);

        /// <summary>
        /// Scans an arbitrary stream for malware.
        /// <paramref name="fileName"/> is used only for logging — it is not
        /// written anywhere or used to influence the scan result.
        /// </summary>
        Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName);

        /// <summary>
        /// Performs a lightweight health-check against the scanner backend.
        /// Does not modify any scanner state or quarantine history.
        /// Returns <see langword="true"/> if the scanner is reachable and responsive.
        /// </summary>
        Task<bool> IsHealthyAsync();
    }

    /// <summary>
    /// Result of a virus scan operation.
    /// </summary>
    public sealed class VirusScanResult
    {
        /// <summary>
        /// <see langword="true"/> if the scanner assessed the file and found no threats.
        /// Only meaningful when <see cref="ScanSuccessful"/> is <see langword="true"/>.
        /// </summary>
        public bool IsClean { get; set; }

        /// <summary>
        /// <see langword="true"/> if the scan engine completed and produced a definitive
        /// clean/infected verdict. <see langword="false"/> indicates an operational failure
        /// (scanner unavailable, timeout, I/O error, unrecognised response).
        /// </summary>
        public bool ScanSuccessful { get; set; }

        /// <summary>
        /// Name of the detected threat, when <see cref="IsClean"/> is <see langword="false"/>
        /// and <see cref="ScanSuccessful"/> is <see langword="true"/>.
        /// </summary>
        public string? ThreatName { get; set; }

        /// <summary>Human-readable summary of the scan outcome.</summary>
        public string? Message { get; set; }

        /// <summary>Name of the scanner engine that produced this result.</summary>
        public string ScannerUsed { get; set; } = string.Empty;

        /// <summary>Wall-clock duration of the scan in milliseconds.</summary>
        public long ScanDurationMs { get; set; }

        /// <summary>
        /// Raw scanner output for audit logging. Not surfaced to end-users.
        /// May contain scanner-specific diagnostic information.
        /// </summary>
        public string? ScanDetails { get; set; }
    }
}
