using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// ClamAV virus scanner implementation (Gap 6 mitigation).
    ///
    /// Talks directly to a clamd daemon over TCP using the documented INSTREAM
    /// command, so no temp file is written and the patron's plaintext bytes
    /// never touch disk. clamd replies with either "stream: OK" or
    /// "stream: &lt;SignatureName&gt; FOUND".
    ///
    /// Cross-platform alternative to <see cref="WindowsDefenderScanService"/>:
    ///   • Linux / macOS / containers
    ///   • Free, signature updates via freshclam
    ///   • Stateless TCP — easy to scale horizontally (one clamd cluster)
    ///
    /// Configuration (all under "VirusScan:ClamAv:..."):
    ///   Host                 (default "localhost")
    ///   Port                 (default 3310)
    ///   TimeoutSeconds       (default 30, max 120)
    ///   MaxStreamBytes       (default 26214400 == 25 MiB; must match clamd's
    ///                         StreamMaxLength setting in clamd.conf)
    ///
    /// Detection fail-closed: a clean/infected verdict from clamd is always honoured —
    /// infected → pipeline rejects.
    /// Availability fail-open: if clamd is unreachable, times out, or returns an
    /// unrecognised response, this service sets ScanSuccessful=false. The calling
    /// pipeline (FileUploadService.RunVirusScanAsync) then accepts the file as
    /// NotScanned — counted in FileUploadResult.ScanNotScannedCount and logged as
    /// VIRUS_SCAN_OPERATIONAL_FAILURE, never silently relabelled as clean.
    /// See KNOWN-GAPS.md §Gap 9 for the architectural rationale.
    /// </summary>
    public class ClamAvScanService : IVirusScanService
    {
        private readonly ILogger<ClamAvScanService> _logger;
        private readonly string _host;
        private readonly int _port;
        private readonly int _timeoutSeconds;
        private readonly int _maxStreamBytes;

        private const int DefaultPort = 3310;
        private const int DefaultTimeoutSeconds = 30;
        private const int MaxTimeoutSeconds = 120;
        private const int DefaultMaxStreamBytes = 25 * 1024 * 1024;
        private const int InstreamChunkSize = 64 * 1024;

        public string ScannerName => "ClamAV";

        public ClamAvScanService(
            ILogger<ClamAvScanService> logger,
            IConfiguration configuration)
        {
            _logger = logger;

            _host = configuration["VirusScan:ClamAv:Host"] ?? "localhost";
            _port = configuration.GetValue<int>("VirusScan:ClamAv:Port", DefaultPort);

            var configuredTimeout = configuration.GetValue<int>(
                "VirusScan:ClamAv:TimeoutSeconds", DefaultTimeoutSeconds);
            _timeoutSeconds = Math.Clamp(configuredTimeout, 1, MaxTimeoutSeconds);

            _maxStreamBytes = configuration.GetValue<int>(
                "VirusScan:ClamAv:MaxStreamBytes", DefaultMaxStreamBytes);

            _logger.LogInformation(
                "ClamAV scanner configured. Host: {Host}:{Port}, Timeout: {Timeout}s, MaxStream: {MaxStream} bytes",
                _host, _port, _timeoutSeconds, _maxStreamBytes);
        }

        public async Task<VirusScanResult> ScanFileAsync(IFormFile file)
        {
            using var stream = file.OpenReadStream();
            return await ScanStreamAsync(stream, file.FileName);
        }

        public async Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName)
        {
            var sw = Stopwatch.StartNew();

            if (fileStream is null)
            {
                sw.Stop();
                return Failed(sw, "Stream was null.");
            }

            if (fileStream.CanSeek)
            {
                if (fileStream.Length > _maxStreamBytes)
                {
                    sw.Stop();
                    _logger.LogWarning(
                        "SECURITY_EVENT | CLAMAV_STREAM_TOO_LARGE | FileName: {FileName} | Size: {Size} | Limit: {Limit}",
                        fileName, fileStream.Length, _maxStreamBytes);
                    return Failed(sw, $"File exceeds ClamAV stream limit ({_maxStreamBytes} bytes).");
                }
                fileStream.Position = 0;
            }

            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_timeoutSeconds));
                using var tcp = new TcpClient { NoDelay = true };

                _logger.LogDebug("ClamAV: connecting to {Host}:{Port} for {FileName}", _host, _port, fileName);
                await tcp.ConnectAsync(_host, _port, cts.Token);

                using var net = tcp.GetStream();

                // Use the null-terminated zINSTREAM command per clamd protocol
                // (the leading 'z' switches to null-terminated responses, which
                // is friendlier to parse than newline-terminated nINSTREAM).
                byte[] cmd = Encoding.ASCII.GetBytes("zINSTREAM\0");
                await net.WriteAsync(cmd, cts.Token);

                int totalSent = 0;
                byte[] buf = new byte[InstreamChunkSize];
                byte[] lenPrefix = new byte[4];

                while (true)
                {
                    int budget = _maxStreamBytes - totalSent;
                    if (budget <= 0)
                    {
                        sw.Stop();
                        _logger.LogWarning(
                            "SECURITY_EVENT | CLAMAV_STREAM_TOO_LARGE | FileName: {FileName} | Limit: {Limit}",
                            fileName, _maxStreamBytes);
                        return Failed(sw, $"File exceeds ClamAV stream limit ({_maxStreamBytes} bytes).");
                    }

                    int toRead = Math.Min(buf.Length, budget);
                    int read = await fileStream.ReadAsync(buf.AsMemory(0, toRead), cts.Token);
                    if (read <= 0) break;

                    BinaryPrimitives.WriteUInt32BigEndian(lenPrefix, (uint)read);
                    await net.WriteAsync(lenPrefix, cts.Token);
                    await net.WriteAsync(buf.AsMemory(0, read), cts.Token);
                    totalSent += read;
                }

                // Zero-length chunk signals end of stream.
                BinaryPrimitives.WriteUInt32BigEndian(lenPrefix, 0u);
                await net.WriteAsync(lenPrefix, cts.Token);

                // Read response (terminated by NUL because we used zINSTREAM).
                using var responseBuffer = new MemoryStream();
                byte[] rbuf = new byte[1024];
                while (true)
                {
                    int r = await net.ReadAsync(rbuf.AsMemory(), cts.Token);
                    if (r <= 0) break;
                    responseBuffer.Write(rbuf, 0, r);
                    if (Array.IndexOf(rbuf, (byte)0, 0, r) >= 0) break;
                }

                string response = Encoding.ASCII
                    .GetString(responseBuffer.ToArray())
                    .TrimEnd('\0', '\n', '\r', ' ');

                sw.Stop();
                return ParseResponse(response, fileName, sw.ElapsedMilliseconds, totalSent);
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                _logger.LogError(
                    "SECURITY_EVENT | CLAMAV_TIMEOUT | FileName: {FileName} | After: {Ms}ms",
                    fileName, sw.ElapsedMilliseconds);
                return Failed(sw, $"ClamAV scan timed out after {_timeoutSeconds}s.");
            }
            catch (SocketException ex)
            {
                sw.Stop();
                _logger.LogError(ex,
                    "SECURITY_EVENT | CLAMAV_UNAVAILABLE | clamd unreachable at {Host}:{Port} — file {FileName} REJECTED (fail-closed)",
                    _host, _port, fileName);
                return Failed(sw, $"ClamAV daemon unreachable: {ex.Message}");
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "ClamAV: unexpected error scanning {FileName}", fileName);
                return Failed(sw, $"Scan error: {ex.Message}");
            }
        }

        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var tcp = new TcpClient { NoDelay = true };
                await tcp.ConnectAsync(_host, _port, cts.Token);
                using var net = tcp.GetStream();

                // PING is documented to return "PONG" with newline framing.
                await net.WriteAsync("nPING\n"u8.ToArray(), cts.Token);

                byte[] buf = new byte[16];
                int read = await net.ReadAsync(buf.AsMemory(), cts.Token);
                string response = Encoding.ASCII.GetString(buf, 0, read).Trim();

                bool ok = response.Equals("PONG", StringComparison.OrdinalIgnoreCase);
                _logger.LogInformation(
                    "ClamAV health check: {Status} (response: '{Response}')",
                    ok ? "HEALTHY" : "UNHEALTHY", response);
                return ok;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "ClamAV health check failed for {Host}:{Port}", _host, _port);
                return false;
            }
        }

        private VirusScanResult ParseResponse(string response, string fileName, long elapsedMs, int bytesSent)
        {
            // Expected formats:
            //   "stream: OK"
            //   "stream: <SignatureName> FOUND"
            //   "<error text> ERROR"
            if (response.EndsWith(" FOUND", StringComparison.Ordinal))
            {
                int colon = response.IndexOf(':');
                int found = response.LastIndexOf(" FOUND", StringComparison.Ordinal);
                string threat = (colon >= 0 && found > colon)
                    ? response.Substring(colon + 1, found - colon - 1).Trim()
                    : "Unknown";

                _logger.LogWarning(
                    "SECURITY_EVENT | THREAT_DETECTED | Scanner: ClamAV | FileName: {FileName} | Threat: {Threat} | Response: {Response}",
                    fileName, threat, response);

                return new VirusScanResult
                {
                    IsClean = false,
                    ScanSuccessful = true,
                    ThreatName = threat,
                    Message = $"Threat detected: {threat}",
                    ScannerUsed = ScannerName,
                    ScanDurationMs = elapsedMs,
                    ScanDetails = response
                };
            }

            if (response.EndsWith(" ERROR", StringComparison.Ordinal))
            {
                _logger.LogError(
                    "ClamAV reported scan error for {FileName}: {Response}", fileName, response);
                return new VirusScanResult
                {
                    IsClean = false,
                    ScanSuccessful = false,
                    Message = $"ClamAV error: {response}",
                    ScannerUsed = ScannerName,
                    ScanDurationMs = elapsedMs,
                    ScanDetails = response
                };
            }

            if (response.EndsWith("OK", StringComparison.Ordinal))
            {
                _logger.LogInformation(
                    "ClamAV: {FileName} CLEAN ({Bytes} bytes, {Ms}ms)",
                    fileName, bytesSent, elapsedMs);
                return new VirusScanResult
                {
                    IsClean = true,
                    ScanSuccessful = true,
                    Message = "No threats detected.",
                    ScannerUsed = ScannerName,
                    ScanDurationMs = elapsedMs,
                    ScanDetails = response
                };
            }

            _logger.LogWarning(
                "ClamAV returned unrecognised response for {FileName}: {Response}", fileName, response);
            return new VirusScanResult
            {
                IsClean = false,
                ScanSuccessful = false,
                Message = $"Unrecognised ClamAV response: {response}",
                ScannerUsed = ScannerName,
                ScanDurationMs = elapsedMs,
                ScanDetails = response
            };
        }

        private VirusScanResult Failed(Stopwatch sw, string message) => new()
        {
            IsClean = false,
            ScanSuccessful = false,
            Message = message,
            ScannerUsed = ScannerName,
            ScanDurationMs = sw.ElapsedMilliseconds
        };
    }
}
