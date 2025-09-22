using System.Runtime.InteropServices;

namespace MtlsWebApi;

/// <summary>
/// P/Invoke declarations for Windows Crypto API functions.
/// </summary>
internal static partial class CryptoInterop
{
    #region Constants

    internal const uint X509_ASN_ENCODING = 0x00000001;
    internal const uint PKCS_7_ASN_ENCODING = 0x00010000;
    internal const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
    internal const uint CERT_STORE_CTRL_RESYNC = 1;

    // CryptVerifyCertificateSignatureEx constants
    internal const uint CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL = 3;
    internal const uint CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT = 2;

    #endregion

    #region Structures

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRL_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCrlEncoded;
        public uint cbCrlEncoded;
        public IntPtr pCrlInfo;
        public IntPtr hCertStore;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRL_INFO
    {
        public uint dwVersion;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CERT_NAME_BLOB Issuer;
        public FILETIME ThisUpdate;
        public FILETIME NextUpdate;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_ALGORITHM_IDENTIFIER
    {
        public IntPtr pszObjId;
        public CRYPT_OBJID_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CRYPT_OBJID_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CERT_NAME_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILETIME
    {
        public uint dwLowDateTime;
        public uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CERT_CONTEXT
    {
        public uint dwCertEncodingType;
        public IntPtr pbCertEncoded;
        public uint cbCertEncoded;
        public IntPtr pCertInfo;
        public IntPtr hCertStore;
    }

    #endregion

    #region P/Invoke Methods

    [LibraryImport("crypt32.dll", SetLastError = true)]
    internal static partial IntPtr CertCreateCRLContext(
        uint dwCertEncodingType,
        [In] byte[] pbCrlEncoded,
        uint cbCrlEncoded);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertAddCRLContextToStore(
        IntPtr hCertStore,
        SafeCrlContext pCrlContext,
        uint dwAddDisposition,
        IntPtr ppStoreContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertFreeCRLContext(IntPtr pCrlContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertControlStore(
        IntPtr hCertStore,
        uint dwFlags,
        uint dwCtrlType,
        IntPtr pvCtrlPara);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    internal static partial IntPtr CertEnumCRLsInStore(
        IntPtr hCertStore,
        IntPtr pPrevCrlContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CertDeleteCRLFromStore(IntPtr pCrlContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    internal static partial IntPtr CertDuplicateCRLContext(IntPtr pCrlContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CryptVerifyCertificateSignatureEx(
        IntPtr hCryptProv,
        uint dwCertEncodingType,
        uint dwSubjectType,
        IntPtr pvSubject,
        uint dwIssuerType,
        IntPtr pvIssuer,
        uint dwFlags,
        IntPtr pvReserved);

    #endregion
}