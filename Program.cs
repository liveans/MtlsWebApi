using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Authorization;
using MtlsWebApi;

var builder = WebApplication.CreateBuilder(args);

// Create shared logger factory for static usage (will be disposed when app shuts down)
var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));

// Create shared CertificateChainManager instance for certificate validation
var sharedChainManagerOptions = new CertificateChainManagerOptions
{
    HttpTimeout = TimeSpan.FromSeconds(30),
    BypassSslValidation = true,
    EnableCaching = true,
    CertificateCacheDuration = TimeSpan.FromHours(24),
    CrlCacheDuration = TimeSpan.FromHours(6),
    MaxCacheSize = 1000,
    DefaultCrlStore = StoreName.CertificateAuthority,
    RevocationFlag = X509RevocationFlag.EndCertificateOnly,
    MaxDownloadSize = 1 * 1024 * 1024,
};

var sharedChainManager = new CertificateChainManager(
    options: sharedChainManagerOptions,
    logger: loggerFactory.CreateLogger<CertificateChainManager>()
);


// Add services
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configure CertificateChainManager as a singleton service (for API endpoints)
builder.Services.AddSingleton(sp => sharedChainManagerOptions);
builder.Services.AddSingleton(sp => sharedChainManager);


// Configure certificate authentication
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.RevocationMode = X509RevocationMode.Online;
        options.ValidateCertificateUse = true;
        options.ValidateValidityPeriod = true;

        options.Events = new CertificateAuthenticationEvents
        {
            OnAuthenticationFailed = async context =>
            {
                // Attempt to recover using CertificateChainManager
                await sharedChainManager.HandleAuthenticationFailedAsync(context);
            }
        };
    });

builder.Services.AddAuthorization();

// Configure Kestrel for HTTPS with required client certificates
var certsPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "certs");
var serverCertPath = Path.Combine(certsPath, "server-openssl.p12");
var rootCaPath = Path.Combine(certsPath, "root-ca-openssl.crt");

// Load root CA for trust store
var rootCa = X509CertificateLoader.LoadCertificateFromFile(rootCaPath);

builder.Services.Configure<KestrelServerOptions>(options =>
{
    options.ConfigureHttpsDefaults(httpsOptions =>
    {
        httpsOptions.ServerCertificate = X509CertificateLoader.LoadPkcs12FromFile(serverCertPath, "password123");
        httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        httpsOptions.CheckCertificateRevocation = true;

        // Simple one-line certificate validation using CertificateChainManager
        httpsOptions.ClientCertificateValidation = sharedChainManager.ValidateClientCertificate;
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

// Protected API endpoints that require valid client certificates
app.MapGet("/api/secure", [Authorize] (HttpContext context) =>
{
    var clientCert = context.Connection.ClientCertificate;
    return Results.Ok(new
    {
        Message = "Successfully authenticated with client certificate",
        ClientCertificate = new
        {
            Subject = clientCert?.Subject,
            Issuer = clientCert?.Issuer,
            Thumbprint = clientCert?.Thumbprint,
            ValidFrom = clientCert?.NotBefore,
            ValidTo = clientCert?.NotAfter
        },
        Timestamp = DateTime.UtcNow
    });
})
.WithName("SecureEndpoint")
.WithOpenApi();

// Development/testing endpoint to clear CRL cache
app.MapPost("/api/clear-crl-cache", (CertificateChainManager chainManager) =>
{
    var clearedCount = chainManager.ClearCrlCache();
    return Results.Ok(new
    {
        Message = "CRL cache cleared successfully",
        ClearedCount = clearedCount,
        Timestamp = DateTime.UtcNow
    });
})
.WithName("ClearCrlCache")
.WithOpenApi();

// Ensure proper cleanup
var appLifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
appLifetime.ApplicationStopping.Register(() =>
{
    sharedChainManager?.Dispose();
    loggerFactory?.Dispose();
});

app.Run();