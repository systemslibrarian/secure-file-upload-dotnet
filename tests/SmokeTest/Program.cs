// Runtime smoke test for SecureFileUpload.Core 1.0.0-preview.2.
//
// Validates:
//   1. Argon2id KEK derivation produces a 32-byte key in a reasonable time.
//   2. AES-256-GCM round-trips arbitrary plaintext under that key.
//   3. FileUploadService writes a v2 envelope file with the Argon2id KEK
//      and reads it back through GetDecryptedFileStreamAsync.
//   4. A v2 envelope file written under a *legacy* PBKDF2 KEK (simulating
//      a file on disk from a pre-Argon2id version of the library) decrypts
//      correctly through the LegacyKekFallback path.
//   5. With LegacyKekFallback=false, the legacy PBKDF2-wrapped file fails
//      to decrypt (proving the fallback gate actually gates).
//
// This is not a unit-test suite — it's a self-contained executable that
// exits non-zero if any assertion fails. Run before publishing.

using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureFileUpload.Services;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

int failures = 0;
int passes = 0;

void Check(string name, bool condition, string? detail = null)
{
    if (condition)
    {
        Console.WriteLine($"  PASS  {name}");
        passes++;
    }
    else
    {
        Console.WriteLine($"  FAIL  {name}{(detail is null ? "" : $" — {detail}")}");
        failures++;
    }
}

void Section(string title)
{
    Console.WriteLine();
    Console.WriteLine($"━━ {title} ━━");
}

// ──────────────────────────────────────────────────────────────────────
// Test 1 — Argon2id KEK derivation + AES-GCM round-trip
// ──────────────────────────────────────────────────────────────────────
Section("Argon2id + AES-256-GCM round-trip (direct)");

byte[] DeriveArgon2id(string secret, byte[] salt, int memoryKiB, int iterations, int parallelism, int outLen)
{
    using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(secret))
    {
        Salt = salt,
        DegreeOfParallelism = parallelism,
        MemorySize = memoryKiB,
        Iterations = iterations,
    };
    return argon2.GetBytes(outLen);
}

var salt = Encoding.UTF8.GetBytes("SecureFileUpload.kdf.argon2id.v1");
var sw = System.Diagnostics.Stopwatch.StartNew();
var kek = DeriveArgon2id("smoke-test-secret-must-be-at-least-32-chars-long", salt, 65536, 3, 4, 32);
sw.Stop();
Check("Argon2id KEK is 32 bytes", kek.Length == 32);
Check("Argon2id derivation completes under 5 s", sw.ElapsedMilliseconds < 5000, $"took {sw.ElapsedMilliseconds} ms");
Console.WriteLine($"        (Argon2id m=64MiB t=3 p=4 derived in {sw.ElapsedMilliseconds} ms)");

// Re-derive — should be deterministic for the same inputs.
var kek2 = DeriveArgon2id("smoke-test-secret-must-be-at-least-32-chars-long", salt, 65536, 3, 4, 32);
Check("Argon2id derivation is deterministic for identical inputs", kek.SequenceEqual(kek2));

// Different secret → different key.
var kekOther = DeriveArgon2id("a-different-secret-with-more-than-32-chars-too!!", salt, 65536, 3, 4, 32);
Check("Different secret yields different key", !kek.SequenceEqual(kekOther));

// AES-GCM round-trip with the Argon2id-derived KEK.
var plaintext = Encoding.UTF8.GetBytes("Hello from the smoke test — this is the plaintext payload.");
var nonce = RandomNumberGenerator.GetBytes(12);
var ciphertext = new byte[plaintext.Length];
var tag = new byte[16];
using (var gcm = new AesGcm(kek, 16))
    gcm.Encrypt(nonce, plaintext, ciphertext, tag);

var roundtrip = new byte[plaintext.Length];
using (var gcm = new AesGcm(kek, 16))
    gcm.Decrypt(nonce, ciphertext, tag, roundtrip);

Check("AES-256-GCM round-trip under Argon2id KEK", plaintext.SequenceEqual(roundtrip));

// ──────────────────────────────────────────────────────────────────────
// Test 2 — FileUploadService v2 envelope round-trip (Argon2id primary)
// ──────────────────────────────────────────────────────────────────────
Section("FileUploadService v2 envelope round-trip (Argon2id primary)");

var workRoot = Path.Combine(Path.GetTempPath(), "sfu-smoke-" + Guid.NewGuid().ToString("N").Substring(0, 8));
var contentRoot = Path.Combine(workRoot, "content");
var webRoot = Path.Combine(contentRoot, "wwwroot");
var storageRoot = Path.Combine(workRoot, "uploads");
Directory.CreateDirectory(contentRoot);
Directory.CreateDirectory(webRoot);
Directory.CreateDirectory(storageRoot);

try
{
    var configValues = new Dictionary<string, string?>
    {
        ["FileUpload:StorageRoot"] = storageRoot,
        ["FileUpload:EncryptionEnabled"] = "true",
        ["FileUpload:EncryptionSecret"] = "smoke-test-secret-must-be-at-least-32-chars-long",
        ["FileUpload:KeyDerivation:Algorithm"] = "Argon2id",
        ["FileUpload:KeyDerivation:Argon2id:MemoryKiB"] = "65536",
        ["FileUpload:KeyDerivation:Argon2id:Iterations"] = "3",
        ["FileUpload:KeyDerivation:Argon2id:Parallelism"] = "4",
        ["FileUpload:KeyDerivation:LegacyKekFallback"] = "true",
        ["FileUpload:RecompressImages"] = "false",
        ["VirusScan:Enabled"] = "false",
    };

    var config = new ConfigurationBuilder()
        .AddInMemoryCollection(configValues)
        .Build();

    var env = new StubWebHostEnvironment(contentRoot, webRoot);
    var loggerFactory = NullLoggerFactory.Instance;
    var contentValidator = new FileContentValidator(
        loggerFactory.CreateLogger<FileContentValidator>(),
        Microsoft.Extensions.Options.Options.Create(new FileContentValidatorOptions()));
    var scanner = new DummyVirusScanService();

    var svc = new FileUploadService(
        loggerFactory.CreateLogger<FileUploadService>(),
        config,
        env,
        contentValidator,
        scanner);

    // Use reflection to access the internal envelope writer + V2 decryptor —
    // simulates what FileUploadService.WriteFileToDiskAsync does, without
    // needing a full IFormFile + multi-layer validation pipeline.
    var t = typeof(FileUploadService);
    var encKeyField = t.GetField("_encryptionKey", BindingFlags.Instance | BindingFlags.NonPublic)!;
    var primaryKek = (byte[]?)encKeyField.GetValue(svc);
    Check("Primary KEK is populated after construction", primaryKek is not null && primaryKek.Length == 32);

    var legacyField = t.GetField("_legacyEncryptionKeys", BindingFlags.Instance | BindingFlags.NonPublic)!;
    var legacyKeks = (System.Collections.IList)legacyField.GetValue(svc)!;
    Check("Legacy KEK fallback list has 2 entries (PBKDF2 600k + 210k)", legacyKeks.Count == 2);

    var writeMethod = t.GetMethod("WriteEnvelopeEncryptedAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;

    var payload = Encoding.UTF8.GetBytes("Plaintext for round-trip test — Argon2id primary KEK path.\n");
    var encryptedPath = Path.Combine(storageRoot, "argon2id.bin");

    var task = (Task)writeMethod.Invoke(svc, new object?[] { payload, encryptedPath, primaryKek })!;
    task.GetAwaiter().GetResult();

    Check("Encrypted file written to disk", File.Exists(encryptedPath));
    var encryptedBytes = File.ReadAllBytes(encryptedPath);
    Check("Encrypted file starts with ENCGCM\\0\\x02 marker (v2 envelope)",
        encryptedBytes.Length >= 8 &&
        encryptedBytes[0] == 0x45 && encryptedBytes[1] == 0x4E && encryptedBytes[2] == 0x43 &&
        encryptedBytes[3] == 0x47 && encryptedBytes[4] == 0x43 && encryptedBytes[5] == 0x4D &&
        encryptedBytes[6] == 0x00 && encryptedBytes[7] == 0x02);

    // Now read it back via the public surface.
    var readBack = svc.GetDecryptedFileStreamAsync(encryptedPath).GetAwaiter().GetResult();
    Check("GetDecryptedFileStreamAsync returns a non-null stream", readBack.Stream is not null);

    using (var ms = new MemoryStream())
    {
        readBack.Stream!.CopyTo(ms);
        var decrypted = ms.ToArray();
        Check("Decrypted bytes match original payload (Argon2id path)", payload.SequenceEqual(decrypted));
    }
    readBack.Stream?.Dispose();

    // ──────────────────────────────────────────────────────────────────
    // Test 3 — Legacy PBKDF2-wrapped v2 envelope decrypts via fallback
    // ──────────────────────────────────────────────────────────────────
    Section("Legacy PBKDF2-wrapped v2 envelope decrypts via fallback");

    // Build a v2-envelope file using the legacy PBKDF2 KEK (the first legacy entry).
    var legacyKek0 = (byte[])legacyKeks[0]!;
    var legacyPath = Path.Combine(storageRoot, "legacy_pbkdf2.bin");
    WriteV2Envelope(legacyPath, payload, legacyKek0);

    var readLegacy = svc.GetDecryptedFileStreamAsync(legacyPath).GetAwaiter().GetResult();
    Check("Legacy file decrypts when LegacyKekFallback=true", readLegacy.Stream is not null);

    if (readLegacy.Stream is not null)
    {
        using var ms = new MemoryStream();
        readLegacy.Stream.CopyTo(ms);
        Check("Legacy file decrypts to the correct plaintext", payload.SequenceEqual(ms.ToArray()));
        readLegacy.Stream.Dispose();
    }

    // ──────────────────────────────────────────────────────────────────
    // Test 4 — LegacyKekFallback=false actually gates the fallback
    // ──────────────────────────────────────────────────────────────────
    Section("LegacyKekFallback=false blocks legacy decryption");

    var configValuesNoFallback = new Dictionary<string, string?>(configValues!)
    {
        ["FileUpload:KeyDerivation:LegacyKekFallback"] = "false",
    };
    var configNoFallback = new ConfigurationBuilder().AddInMemoryCollection(configValuesNoFallback).Build();

    var svcNoFallback = new FileUploadService(
        loggerFactory.CreateLogger<FileUploadService>(),
        configNoFallback,
        env,
        contentValidator,
        scanner);

    var legacyKeksAfter = (System.Collections.IList)legacyField.GetValue(svcNoFallback)!;
    Check("Legacy KEK list is empty when fallback disabled", legacyKeksAfter.Count == 0);

    var readBlocked = svcNoFallback.GetDecryptedFileStreamAsync(legacyPath).GetAwaiter().GetResult();
    Check("Legacy file FAILS to decrypt when LegacyKekFallback=false (gate works)",
        readBlocked.Stream is null);
    readBlocked.Stream?.Dispose();

    // ──────────────────────────────────────────────────────────────────
    // Test 5 — Pbkdf2 algorithm path still works end-to-end
    // ──────────────────────────────────────────────────────────────────
    Section("Algorithm=Pbkdf2 path round-trip");

    var pbkdf2Config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>(configValues!)
    {
        ["FileUpload:KeyDerivation:Algorithm"] = "Pbkdf2",
        ["FileUpload:KeyDerivation:Pbkdf2:Iterations"] = "600000",
    }).Build();

    var svcPbkdf2 = new FileUploadService(
        loggerFactory.CreateLogger<FileUploadService>(),
        pbkdf2Config,
        env,
        contentValidator,
        scanner);

    var pbkdfKek = (byte[]?)encKeyField.GetValue(svcPbkdf2);
    var pbkdfPath = Path.Combine(storageRoot, "pbkdf2_path.bin");
    var pbkdfTask = (Task)writeMethod.Invoke(svcPbkdf2, new object?[] { payload, pbkdfPath, pbkdfKek })!;
    pbkdfTask.GetAwaiter().GetResult();

    var pbkdfRead = svcPbkdf2.GetDecryptedFileStreamAsync(pbkdfPath).GetAwaiter().GetResult();
    Check("Pbkdf2 algorithm: round-trip succeeds", pbkdfRead.Stream is not null);
    if (pbkdfRead.Stream is not null)
    {
        using var ms = new MemoryStream();
        pbkdfRead.Stream.CopyTo(ms);
        Check("Pbkdf2 algorithm: decrypted bytes match", payload.SequenceEqual(ms.ToArray()));
        pbkdfRead.Stream.Dispose();
    }

    // ──────────────────────────────────────────────────────────────────
    // Test 6 — Misconfiguration guard still throws
    // ──────────────────────────────────────────────────────────────────
    Section("Misconfiguration guard");

    var badConfig = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["FileUpload:StorageRoot"] = storageRoot,
        ["FileUpload:EncryptionEnabled"] = "true",
        ["FileUpload:EncryptionSecret"] = "CHANGE_THIS_TO_A_REAL_SECRET",
    }).Build();

    bool threw = false;
    try
    {
        _ = new FileUploadService(
            loggerFactory.CreateLogger<FileUploadService>(),
            badConfig, env, contentValidator, scanner);
    }
    catch (InvalidOperationException)
    {
        threw = true;
    }
    Check("Placeholder secret causes startup to fail", threw);
}
finally
{
    try { Directory.Delete(workRoot, recursive: true); } catch { /* best-effort */ }
}

// ──────────────────────────────────────────────────────────────────────
Console.WriteLine();
Console.WriteLine($"━━ Summary: {passes} pass, {failures} fail ━━");
return failures == 0 ? 0 : 1;


// ── helpers ──────────────────────────────────────────────────────────

static void WriteV2Envelope(string path, byte[] payload, byte[] kek)
{
    var marker = Encoding.ASCII.GetBytes("ENCGCM\0\x02");
    var dek = RandomNumberGenerator.GetBytes(32);
    var dekNonce = RandomNumberGenerator.GetBytes(12);
    var fileNonce = RandomNumberGenerator.GetBytes(12);
    var wrappedDek = new byte[32];
    var dekTag = new byte[16];
    var fileTag = new byte[16];
    var ciphertext = new byte[payload.Length];

    using (var fileGcm = new AesGcm(dek, 16))
        fileGcm.Encrypt(fileNonce, payload, ciphertext, fileTag);

    using (var kekGcm = new AesGcm(kek, 16))
        kekGcm.Encrypt(dekNonce, dek, wrappedDek, dekTag);

    using var fs = File.Create(path);
    fs.Write(marker);
    fs.Write(dekNonce);
    fs.Write(dekTag);
    fs.Write(wrappedDek);
    fs.Write(fileNonce);
    fs.Write(fileTag);
    fs.Write(ciphertext);
}

sealed class StubWebHostEnvironment : IWebHostEnvironment
{
    public StubWebHostEnvironment(string contentRoot, string webRoot)
    {
        ContentRootPath = contentRoot;
        WebRootPath = webRoot;
        ContentRootFileProvider = new PhysicalFileProvider(contentRoot);
        WebRootFileProvider = new PhysicalFileProvider(webRoot);
    }
    public string EnvironmentName { get; set; } = "Smoke";
    public string ApplicationName { get; set; } = "SmokeTest";
    public string WebRootPath { get; set; }
    public IFileProvider WebRootFileProvider { get; set; }
    public string ContentRootPath { get; set; }
    public IFileProvider ContentRootFileProvider { get; set; }
}

sealed class DummyVirusScanService : IVirusScanService
{
    public string ScannerName => "smoke-test-noop";
    public Task<VirusScanResult> ScanFileAsync(IFormFile file) =>
        Task.FromResult(new VirusScanResult { ScanSuccessful = true, IsClean = true, ScannerUsed = ScannerName });
    public Task<VirusScanResult> ScanStreamAsync(Stream fileStream, string fileName) =>
        Task.FromResult(new VirusScanResult { ScanSuccessful = true, IsClean = true, ScannerUsed = ScannerName });
    public Task<bool> IsHealthyAsync() => Task.FromResult(true);
}
