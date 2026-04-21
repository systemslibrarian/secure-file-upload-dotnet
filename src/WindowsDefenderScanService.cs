using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Windows Defender (Microsoft Defender Antivirus) scanner implementation.
    /// 
    /// Features:
    /// - Free — included with Windows
    /// - Always up-to-date via Windows Update
    /// - Works on Windows Server 2016+ and Azure App Service (Windows)
    /// - Graceful degradation if scanner unavailable
    /// - Proper timeout handling (30 seconds default)
    /// - Comprehensive audit logging for threats
    /// - Temp files zeroed before deletion to protect patron document content
    /// 
    /// Requirements:
    /// - Windows operating system
    /// - Windows Defender enabled
    /// - MpCmdRun.exe available at default location
    /// </summary>
    public class WindowsDefenderScanService : IVirusScanService
    {
        private readonly ILogger<WindowsDefenderScanService> _logger;
        private readonly IConfiguration _configuration;
        private readonly string _mpCmdRunPath;
        private readonly string _tempScanPath;
        private readonly int _timeoutSeconds;

        private const int DefaultTimeoutSeconds = 30;
        private const int MaxTimeoutSeconds = 120;
        private const string DefaultMpCmdRunPath = @"C:\Program Files\Windows Defender\MpCmdRun.exe";

        public string ScannerName => "Windows Defender";

        /// <summary>
        /// Initializes a new instance of the <see cref="WindowsDefenderScanService"/> class.
        /// Logs scanner availability at startup but does not cache the result —
        /// availability is rechecked at scan time to handle Defender installs,
        /// updates, or transient unavailability without requiring an app restart.
        /// </summary>
        public WindowsDefenderScanService(
            ILogger<WindowsDefenderScanService> logger,
            IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;

            // Load configuration with defaults
            _mpCmdRunPath = _configuration["VirusScan:WindowsDefender:MpCmdRunPath"]
                ?? DefaultMpCmdRunPath;

            _tempScanPath = _configuration["VirusScan:WindowsDefender:TempScanPath"]
                ?? Path.Combine(Path.GetTempPath(), "SecureUploadVirusScan");

            var configuredTimeout = _configuration.GetValue<int>(
                "VirusScan:WindowsDefender:TimeoutSeconds", DefaultTimeoutSeconds);
            _timeoutSeconds = Math.Min(configuredTimeout, MaxTimeoutSeconds);

            // Log startup availability (informational only — not cached)
            if (!File.Exists(_mpCmdRunPath))
            {
                _logger.LogWarning(
                    "Windows Defender scanner NOT available at {Path} at startup. " +
                    "Scans will be rejected until Defender is available. " +
                    "Install Windows Defender or configure ClamAV instead.",
                    _mpCmdRunPath);
            }
            else
            {
                _logger.LogInformation(
                    "Windows Defender scanner configured and available. " +
                    "TempPath: {TempPath}, Timeout: {Timeout}s",
                    _tempScanPath, _timeoutSeconds);
            }

            // Ensure temp scan directory exists
            try
            {
                Directory.CreateDirectory(_tempScanPath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create temp scan directory: {TempPath}", _tempScanPath);
            }
        }

        /// <summary>
        /// Returns true if the scanner binary exists on disk right now.
        /// Checked live at scan time rather than cached at startup, so the
        /// service recovers automatically if Defender is installed or restored
        /// after the application starts.
        /// </summary>
        private bool IsScannerAvailable => File.Exists(_mpCmdRunPath);

        /// <summary>
        /// Scans an uploaded file for viruses/malware.
        /// If the scanner binary is unavailable, returns ScanSuccessful=false.
        /// The calling pipeline accepts that as NotScanned (fail-open on availability).
        /// See ScanStreamAsync and KNOWN-GAPS.md §Gap 9.
        /// </summary>
        public async Task<VirusScanResult> ScanFileAsync(IFormFile file)
        {
            var sw = Stopwatch.StartNew();

            try
            {
                _logger.LogInformation(
                    "Windows Defender: Starting scan of file: {FileName} ({Size} bytes)",
                    file.FileName, file.Length);

                using (var stream = file.OpenReadStream())
                {
                    return await ScanStreamAsync(stream, file.FileName);
                }
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Windows Defender: Error scanning file {FileName}", file.FileName);
                return new VirusScanResult
                {
                    IsClean = false,
                    ScanSuccessful = false,
                    Message = $"Scan error: {ex.Message}",
                    ScannerUsed = ScannerName,
                    ScanDurationMs = sw.ElapsedMilliseconds
                };
            }
        }

        /// <summary>
        /// Scans a file stream for viruses/malware.
        /// If the scanner binary is unavailable, returns ScanSuccessful=false.
        /// Detection fail-closed: infected result → pipeline rejects.
        /// Availability fail-open: ScanSuccessful=false → pipeline accepts as NotScanned
        ///   (never silently relabelled as clean). See KNOWN-GAPS.md §Gap 9.
        ///
        /// The stream must be seekable (CanSeek == true) since its Position is
        /// reset to 0 before reading. IFormFile.OpenReadStream() satisfies this;
        /// callers providing other stream types must ensure seekability.
        /// </summary>
        public async Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName)
        {
            var sw = Stopwatch.StartNew();
            string? tempFilePath = null;

            try
            {
                // Scanner binary is missing — return ScanSuccessful=false.
                // The pipeline will accept this file as NotScanned (fail-open on
                // availability). Checked live so the service recovers if Defender
                // is installed or restored after application startup.
                if (!IsScannerAvailable)
                {
                    sw.Stop();
                    _logger.LogError(
                        "SECURITY_EVENT | SCANNER_UNAVAILABLE | Windows Defender not available - " +
                        "file {FileName} will be accepted as NotScanned by the pipeline. " +
                        "Install Defender or configure ClamAV to restore scanning.",
                        fileName);

                    return new VirusScanResult
                    {
                        IsClean = false,
                        ScanSuccessful = false,
                        Message = "Scanner not available — file accepted as NotScanned by pipeline (see KNOWN-GAPS.md §Gap 9)",
                        ScannerUsed = $"{ScannerName} (unavailable)",
                        ScanDurationMs = sw.ElapsedMilliseconds
                    };
                }

                // Validate stream is seekable before attempting Position reset.
                if (!fileStream.CanSeek)
                {
                    sw.Stop();
                    _logger.LogError(
                        "SECURITY_EVENT | STREAM_NOT_SEEKABLE | Cannot scan {FileName} — " +
                        "stream is not seekable. Caller must provide a seekable stream.",
                        fileName);

                    return new VirusScanResult
                    {
                        IsClean = false,
                        ScanSuccessful = false,
                        Message = "Scan failed: stream is not seekable",
                        ScannerUsed = ScannerName,
                        ScanDurationMs = sw.ElapsedMilliseconds
                    };
                }

                // Create temporary file for scanning (Windows Defender requires disk file)
                var sanitizedFileName = SanitizeFileName(fileName);
                tempFilePath = Path.Combine(_tempScanPath, $"{Guid.NewGuid()}_{sanitizedFileName}");

                _logger.LogDebug("Windows Defender: Writing temp file for scan: {TempPath}", tempFilePath);

                // Write stream to temp file
                fileStream.Position = 0;
                using (var fileStreamWrite = new FileStream(tempFilePath, FileMode.Create, FileAccess.Write))
                {
                    await fileStream.CopyToAsync(fileStreamWrite);
                }

                // Run Windows Defender scan with timeout
                var result = await RunDefenderScanAsync(tempFilePath, fileName);

                sw.Stop();
                result.ScanDurationMs = sw.ElapsedMilliseconds;

                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Windows Defender: Unexpected error scanning {FileName}", fileName);

                return new VirusScanResult
                {
                    IsClean = false,
                    ScanSuccessful = false,
                    Message = $"Scan error: {ex.Message}",
                    ScannerUsed = ScannerName,
                    ScanDurationMs = sw.ElapsedMilliseconds
                };
            }
            finally
            {
                // Clean up temp file — zero content before deletion so patron
                // document data (IDs, utility bills) doesn't linger on disk
                // in freed sectors. Consistent with the memory-zeroing
                // discipline in FileUploadService and FileContentValidator.
                if (tempFilePath != null)
                    SecureDeleteTempFile(tempFilePath);
            }
        }

        /// <summary>
        /// Checks if Windows Defender scanner is available and operational.
        /// Uses -ValidateMapsConnection to verify connectivity without side effects.
        /// Previous implementation used -SignatureUpdate which actually performed
        /// an update — a health check should not mutate state.
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                if (!File.Exists(_mpCmdRunPath))
                {
                    _logger.LogWarning(
                        "Windows Defender health check: MpCmdRun.exe not found at {Path}",
                        _mpCmdRunPath);
                    return false;
                }

                // Read-only health check: validate MAPS connectivity.
                // Does not trigger signature downloads or any state mutation.
                var startInfo = new ProcessStartInfo
                {
                    FileName = _mpCmdRunPath,
                    Arguments = "-ValidateMapsConnection",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = new Process { StartInfo = startInfo };
                process.Start();

                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try
                {
                    await process.WaitForExitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    // Timeout — kill the process rather than leaving it orphaned.
                    TryKillProcess(process);

                    _logger.LogWarning(
                        "Windows Defender health check: Timeout after 5s — process killed");
                    return false;
                }

                var isHealthy = process.ExitCode == 0;

                _logger.LogInformation(
                    "Windows Defender health check: {Status} (exit code {ExitCode})",
                    isHealthy ? "HEALTHY" : "UNHEALTHY", process.ExitCode);

                return isHealthy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Windows Defender health check failed");
                return false;
            }
        }

        // ── Private helpers ──────────────────────────────────────────────

        /// <summary>
        /// Runs Windows Defender scan on a file with proper timeout handling.
        /// Uses CancellationToken for clean timeout behavior (30 seconds default).
        /// </summary>
        private async Task<VirusScanResult> RunDefenderScanAsync(string filePath, string originalFileName)
        {
            try
            {
                // Run MpCmdRun.exe -Scan -ScanType 3 -File "filepath"
                // -ScanType 3 = Custom scan (specific file)
                var startInfo = new ProcessStartInfo
                {
                    FileName = _mpCmdRunPath,
                    Arguments = $"-Scan -ScanType 3 -File \"{filePath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                _logger.LogDebug("Windows Defender: Running command: {FileName} {Arguments}",
                    startInfo.FileName, startInfo.Arguments);

                using var process = new Process { StartInfo = startInfo };
                process.Start();

                // Read output asynchronously — must be started before WaitForExitAsync
                // to avoid deadlocks when output buffers fill.
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();

                // Wait for completion with proper timeout using CancellationToken
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));
                try
                {
                    await process.WaitForExitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    // Timeout occurred — kill process and drain output tasks
                    // so they don't linger as orphaned fire-and-forget tasks.
                    TryKillProcess(process);
                    await DrainOutputTasksAsync(outputTask, errorTask);

                    _logger.LogWarning(
                        "Windows Defender: Scan timeout for {FileName} after {Timeout}s",
                        originalFileName, _timeoutSeconds);

                    return new VirusScanResult
                    {
                        IsClean = false,
                        ScanSuccessful = false,
                        Message = $"Scan timeout after {_timeoutSeconds} seconds",
                        ScannerUsed = ScannerName
                    };
                }

                // Get results
                var output = await outputTask;
                var error = await errorTask;
                var exitCode = process.ExitCode;

                _logger.LogDebug(
                    "Windows Defender: Exit code: {ExitCode}, Output length: {OutputLength} chars",
                    exitCode, output.Length);

                // Parse exit code
                // 0 = No threats found
                // 2 = Threats found and removed/quarantined
                // Other = Error or threat found but not removed

                if (exitCode == 0)
                {
                    _logger.LogInformation("Windows Defender: File {FileName} is CLEAN",
                        originalFileName);

                    return new VirusScanResult
                    {
                        IsClean = true,
                        ScanSuccessful = true,
                        Message = "No threats detected",
                        ScannerUsed = ScannerName,
                        ScanDetails = output
                    };
                }
                else if (exitCode == 2)
                {
                    // Threats found — log FULL output for audit trail
                    var threatName = ExtractThreatName(output);

                    _logger.LogWarning(
                        "SECURITY: Windows Defender THREAT DETECTED in file {FileName}. " +
                        "Threat: {Threat}, ExitCode: {ExitCode}\n" +
                        "Full scan output:\n{Output}",
                        originalFileName, threatName, exitCode, output);

                    return new VirusScanResult
                    {
                        IsClean = false,
                        ThreatName = threatName,
                        ScanSuccessful = true,
                        Message = $"Threat detected: {threatName}",
                        ScannerUsed = ScannerName,
                        ScanDetails = output
                    };
                }
                else
                {
                    // Error or other condition
                    _logger.LogError(
                        "Windows Defender: Scan error for {FileName}. " +
                        "Exit code: {ExitCode}, StdOut: {Output}, StdErr: {Error}",
                        originalFileName, exitCode, output, error);

                    return new VirusScanResult
                    {
                        IsClean = false,
                        ScanSuccessful = false,
                        Message = $"Scan failed with exit code {exitCode}: {error}",
                        ScannerUsed = ScannerName,
                        ScanDetails = $"Output: {output}\nError: {error}"
                    };
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Windows Defender: Failed to run scan for {FileName}", originalFileName);

                return new VirusScanResult
                {
                    IsClean = false,
                    ScanSuccessful = false,
                    Message = $"Failed to execute scan: {ex.Message}",
                    ScannerUsed = ScannerName
                };
            }
        }

        /// <summary>
        /// Kills a process and its entire process tree. Swallows exceptions
        /// since the process may have already exited between our check and kill.
        /// </summary>
        private static void TryKillProcess(Process process)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Process may have exited between HasExited check and Kill call.
            }
        }

        /// <summary>
        /// Awaits output/error reader tasks after a process has been killed,
        /// so they don't linger as orphaned fire-and-forget tasks. Swallows
        /// any exceptions since the process is already dead.
        /// </summary>
        private static async Task DrainOutputTasksAsync(Task<string> outputTask, Task<string> errorTask)
        {
            try { await outputTask; } catch { /* Process is dead — output stream closed. */ }
            try { await errorTask; }  catch { /* Process is dead — error stream closed. */ }
        }

        /// <summary>
        /// Extracts threat name from Windows Defender output.
        /// Example output line: "Threat: Virus:DOS/EICAR_Test_File"
        /// </summary>
        private string ExtractThreatName(string output)
        {
            try
            {
                if (output.Contains("Threat:"))
                {
                    var lines = output.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains("Threat:"))
                        {
                            var threat = line.Substring(line.IndexOf("Threat:") + 7).Trim();
                            if (!string.IsNullOrWhiteSpace(threat))
                            {
                                return threat;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to extract threat name from output");
            }

            return "Malware detected (see scan details)";
        }

        /// <summary>
        /// Sanitizes filename for safe temp file creation.
        /// </summary>
        private static string SanitizeFileName(string fileName)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = string.Join("_", fileName.Split(invalidChars));

            if (sanitized.Length > 100)
                sanitized = sanitized.Substring(0, 100);

            return sanitized;
        }

        /// <summary>
        /// Overwrites a temp file with zeros before deleting it, so patron
        /// document content (IDs, utility bills) doesn't persist in freed
        /// disk sectors. Consistent with the memory-zeroing discipline in
        /// FileUploadService and FileContentValidator.
        ///
        /// Not a guarantee on all file systems (copy-on-write, SSD wear-leveling,
        /// journaled FS) but reduces the exposure window on conventional storage.
        /// </summary>
        private void SecureDeleteTempFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                    return;

                // Overwrite file content with zeros before deleting.
                var fileInfo = new FileInfo(filePath);
                long length = fileInfo.Length;

                if (length > 0)
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write);
                    // Use a stack-allocated or small buffer — temp files are bounded
                    // by the 10 MB upload limit so this completes quickly.
                    var zeroBuffer = new byte[Math.Min(81_920, length)];
                    long remaining = length;
                    while (remaining > 0)
                    {
                        int toWrite = (int)Math.Min(zeroBuffer.Length, remaining);
                        fs.Write(zeroBuffer, 0, toWrite);
                        remaining -= toWrite;
                    }
                    fs.Flush(flushToDisk: true);
                }

                File.Delete(filePath);
                _logger.LogDebug("Windows Defender: Securely deleted temp file: {TempPath}", filePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Windows Defender: Failed to securely delete temp file: {TempPath}. " +
                    "Attempting plain delete as fallback.", filePath);

                // Fallback: at least try to remove the file even if zeroing failed.
                try { File.Delete(filePath); } catch { /* Best effort. */ }
            }
        }
    }
}