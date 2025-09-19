using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace MtlsWebApi;

/// <summary>
/// A SafeHandle wrapper for Windows CRL context handles.
/// Provides automatic resource cleanup and type safety.
/// </summary>
internal sealed class SafeCrlContext : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeCrlContext() : base(true)
    {
    }

    /// <summary>
    /// Creates a SafeCrlContext from DER-encoded CRL data.
    /// </summary>
    /// <param name="crlData">The DER-encoded CRL data</param>
    /// <returns>A SafeCrlContext, or an invalid handle if creation failed</returns>
    internal static SafeCrlContext Create(byte[] crlData)
    {
        var handle = CryptoInterop.CertCreateCRLContext(
            CryptoInterop.X509_ASN_ENCODING | CryptoInterop.PKCS_7_ASN_ENCODING,
            crlData,
            (uint)crlData.Length);

        var safeCrlContext = new SafeCrlContext();
        safeCrlContext.SetHandle(handle);
        return safeCrlContext;
    }

    /// <summary>
    /// Extracts the NextUpdate time from this CRL context.
    /// </summary>
    /// <returns>The NextUpdate time, or null if not available</returns>
    internal DateTime? GetNextUpdateTime()
    {
        if (IsInvalid)
            return null;

        try
        {
            var context = Marshal.PtrToStructure<CryptoInterop.CRL_CONTEXT>(handle);
            if (context.pCrlInfo == IntPtr.Zero)
                return null;

            var crlInfo = Marshal.PtrToStructure<CryptoInterop.CRL_INFO>(context.pCrlInfo);

            // Convert FILETIME to DateTime (NextUpdate is optional, both values = 0 means not present)
            if (crlInfo.NextUpdate.dwHighDateTime == 0 && crlInfo.NextUpdate.dwLowDateTime == 0)
                return null;

            long fileTime = ((long)crlInfo.NextUpdate.dwHighDateTime << 32) | crlInfo.NextUpdate.dwLowDateTime;
            return DateTime.FromFileTimeUtc(fileTime);
        }
        catch
        {
            return null;
        }
    }

    protected override bool ReleaseHandle()
    {
        return CryptoInterop.CertFreeCRLContext(handle);
    }
}