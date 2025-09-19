using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace MtlsWebApi;

/// <summary>
/// Result of CRL validation with expiration information.
/// </summary>
internal class CrlValidationResult
{
    public bool IsValid { get; set; }
    public byte[] DerData { get; set; } = Array.Empty<byte>();
    public DateTime? NextUpdate { get; set; }
}

/// <summary>
/// Utility methods for cryptographic operations using Windows Crypto API.
/// </summary>
internal static class CryptoUtilities
{
    /// <summary>
    /// Validates CRL data and extracts its expiration information.
    /// </summary>
    /// <param name="crlData">The DER-encoded CRL data</param>
    /// <returns>Validation result with expiration time</returns>
    internal static CrlValidationResult ValidateAndExtractInfo(byte[] crlData)
    {
        using var crlContext = SafeCrlContext.Create(crlData);
        if (crlContext.IsInvalid)
        {
            return new CrlValidationResult { IsValid = false };
        }

        var nextUpdate = crlContext.GetNextUpdateTime();
        return new CrlValidationResult
        {
            IsValid = true,
            DerData = crlData,
            NextUpdate = nextUpdate
        };
    }
}

/// <summary>
/// Extension methods for X509Store to add CRL-related functionality.
/// Only extends meaningful domain types, not primitives.
/// </summary>
internal static class X509StoreExtensions
{
    /// <summary>
    /// Adds a CRL context to an already-opened certificate store.
    /// </summary>
    /// <param name="store">The opened certificate store</param>
    /// <param name="crlContext">The safe CRL context to add</param>
    /// <returns>True if successful, false otherwise</returns>
    internal static bool AddCrl(this X509Store store, SafeCrlContext crlContext)
    {
        if (crlContext.IsInvalid || store.StoreHandle == IntPtr.Zero)
            return false;

        return CryptoInterop.CertAddCRLContextToStore(
            store.StoreHandle,
            crlContext,
            CryptoInterop.CERT_STORE_ADD_REPLACE_EXISTING,
            IntPtr.Zero);
    }

    /// <summary>
    /// Flushes/resyncs a certificate store to ensure changes are persisted.
    /// </summary>
    /// <param name="store">The certificate store to flush</param>
    /// <returns>True if successful, false otherwise</returns>
    internal static bool Flush(this X509Store store)
    {
        if (store.StoreHandle == IntPtr.Zero)
            return false;

        return CryptoInterop.CertControlStore(
            store.StoreHandle,
            0,
            CryptoInterop.CERT_STORE_CTRL_RESYNC,
            IntPtr.Zero);
    }

    /// <summary>
    /// Validates and caches CRL data directly to the store in one operation.
    /// </summary>
    /// <param name="store">The opened certificate store</param>
    /// <param name="crlData">The DER-encoded CRL data</param>
    /// <returns>True if validation and caching succeeded, false otherwise</returns>
    internal static bool AddCrlData(this X509Store store, byte[] crlData)
    {
        using var crlContext = SafeCrlContext.Create(crlData);
        if (crlContext.IsInvalid)
            return false;

        return store.AddCrl(crlContext);
    }
}