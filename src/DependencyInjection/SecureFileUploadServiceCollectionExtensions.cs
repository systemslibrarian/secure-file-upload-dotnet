using Microsoft.Extensions.DependencyInjection;
using System;

namespace SecureFileUpload.Services
{
    /// <summary>
    /// Extension methods for registering the secure file upload pipeline
    /// with the ASP.NET Core dependency-injection container.
    /// </summary>
    public static class SecureFileUploadServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the full 8-layer upload pipeline into the service container:
        /// <list type="bullet">
        ///   <item><see cref="FileContentValidator"/> (Layer 6 — deep content validation)</item>
        ///   <item><see cref="IVirusScanService"/> — implementation chosen by platform:
        ///     <see cref="WindowsDefenderScanService"/> on Windows,
        ///     <see cref="ClamAvScanService"/> on Linux / macOS / containers.</item>
        ///   <item><see cref="IFileUploadService"/> / <see cref="FileUploadService"/>
        ///     (pipeline orchestrator, Layers 1–8)</item>
        /// </list>
        ///
        /// All services are registered as singletons. The scanner choice can be
        /// overridden after the call by re-registering <see cref="IVirusScanService"/>
        /// (last registration wins in ASP.NET Core DI).
        ///
        /// Call <see cref="AddSecureFileUpload(IServiceCollection, Action{FileContentValidatorOptions}?)"/>
        /// in <c>Program.cs</c> / <c>Startup.ConfigureServices</c>, and ensure
        /// <c>IConfiguration</c> and <c>IWebHostEnvironment</c> are already registered
        /// (they are by default in <c>WebApplication.CreateBuilder</c>).
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <param name="configureValidator">
        ///   Optional callback to configure <see cref="FileContentValidatorOptions"/>
        ///   (deep-scan limits, PDF policy, image size caps, etc.).
        ///   When omitted, appsettings values under <c>"FileContent"</c> are used.
        /// </param>
        /// <returns>The same <see cref="IServiceCollection"/> for fluent chaining.</returns>
        public static IServiceCollection AddSecureFileUpload(
            this IServiceCollection services,
            Action<FileContentValidatorOptions>? configureValidator = null)
        {
            // Validator options — honour appsettings by default; allow inline override.
            if (configureValidator != null)
                services.Configure(configureValidator);
            else
                services.AddOptions<FileContentValidatorOptions>()
                        .BindConfiguration("FileContent");

            // Layer 6 — deep content validation
            services.AddSingleton<FileContentValidator>();

            // Layer 7 — platform-appropriate virus scanner
            if (OperatingSystem.IsWindows())
                services.AddSingleton<IVirusScanService, WindowsDefenderScanService>();
            else
                services.AddSingleton<IVirusScanService, ClamAvScanService>();

            // Layers 1–8 orchestrator
            services.AddSingleton<IFileUploadService, FileUploadService>();

            return services;
        }
    }
}
