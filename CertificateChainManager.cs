// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace MtlsWebApi
{
    /// <summary>
    /// Configuration options for the Certificate Chain Manager.
    /// </summary>
    public class CertificateChainManagerOptions
    {

        /// <summary>
        /// HTTP timeout for certificate and CRL fetching operations.
        /// </summary>
        public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Whether to bypass SSL validation when fetching certificates and CRLs. (testing only)
        /// </summary>
        public bool BypassSslValidation { get; set; } = false;

        /// <summary>
        /// Cache duration for fetched intermediate certificates.
        /// </summary>
        public TimeSpan CertificateCacheDuration { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Cache duration for CRL validation results.
        /// </summary>
        public TimeSpan CrlCacheDuration { get; set; } = TimeSpan.FromHours(6);

        /// <summary>
        /// Maximum download size for certificates and CRLs (default: 100MB).
        /// </summary>
        public long MaxDownloadSize { get; set; } = 100 * 1024 * 1024;

        /// <summary>
        /// Whether to enable aggressive caching of results.
        /// </summary>
        public bool EnableCaching { get; set; } = true;

        /// <summary>
        /// Maximum cache size for certificates and CRLs.
        /// </summary>
        public int MaxCacheSize { get; set; } = 1000;

        /// <summary>
        /// Default Windows certificate store for CRL caching.
        /// </summary>
        public StoreName DefaultCrlStore { get; set; } = StoreName.CertificateAuthority;

        /// <summary>
        /// Revocation flag to use for certificate chain validation.
        /// When null, no specific revocation flag is set (uses default behavior).
        /// </summary>
        public X509RevocationFlag? RevocationFlag { get; set; } = null;
    }

    /// <summary>
    /// Result of a certificate chain enhancement operation.
    /// </summary>
    public class ChainEnhancementResult
    {
        public bool Success { get; set; }
        public X509Chain? EnhancedChain { get; set; }
        public List<X509Certificate2> FetchedIntermediates { get; set; } = new();
        public List<string> CrlUrls { get; set; } = new();
        public bool CrlCacheSuccess { get; set; }
        public List<string> Errors { get; set; } = new();
        public TimeSpan Duration { get; set; }
    }

    /// <summary>
    /// Cached certificate entry with expiration.
    /// </summary>
    internal class CachedCertificate
    {
        public X509Certificate2 Certificate { get; set; }
        public DateTime ExpiryTime { get; set; }

        public CachedCertificate(X509Certificate2 certificate, DateTime expiryTime)
        {
            Certificate = certificate;
            ExpiryTime = expiryTime;
        }
    }

    /// <summary>
    /// Cached CRL validation result with expiration.
    /// </summary>
    internal class CachedCrlResult
    {
        public bool IsValid { get; set; }
        public byte[] DerData { get; set; }
        public DateTime ExpiryTime { get; set; }

        public CachedCrlResult(bool isValid, byte[] derData, DateTime expiryTime)
        {
            IsValid = isValid;
            DerData = derData;
            ExpiryTime = expiryTime;
        }
    }

    /// <summary>
    /// Certificate chain manager that combines AIA (Authority Information Access)
    /// and CRL (Certificate Revocation List) functionality for certificate chain validation.
    ///
    /// This class provides:
    /// - Fetching of intermediate certificates via AIA
    /// - CRL downloading, validation, and caching
    /// - Enhanced certificate chain building
    /// - Thread-safe operations with caching
    /// - Error handling and logging
    /// </summary>
    public class CertificateChainManager : IDisposable
    {
        private readonly CertificateChainManagerOptions _options;
        private readonly ILogger<CertificateChainManager> _logger;
        private readonly HttpClient _httpClient;

        // Thread-safe caches
        private readonly ConcurrentDictionary<string, CachedCertificate> _certificateCache;
        private readonly ConcurrentDictionary<string, CachedCrlResult> _crlCache;

        // Timer for cache cleanup
        private readonly Timer _cacheCleanupTimer;

        private bool _disposed = false;

        public CertificateChainManager(
            CertificateChainManagerOptions? options = null,
            ILogger<CertificateChainManager>? logger = null)
        {
            _options = options ?? new CertificateChainManagerOptions();
            _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<CertificateChainManager>.Instance;

            _certificateCache = new ConcurrentDictionary<string, CachedCertificate>();
            _crlCache = new ConcurrentDictionary<string, CachedCrlResult>();

            var handler = new SocketsHttpHandler
            {
                PooledConnectionIdleTimeout = TimeSpan.FromSeconds(15),
                MaxAutomaticRedirections = 10,
                AllowAutoRedirect = true
            };

#if DEBUG
            if (_options.BypassSslValidation)
            {
                handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
            }
#endif

            _httpClient = new HttpClient(handler)
            {
                Timeout = _options.HttpTimeout,
                MaxResponseContentBufferSize = _options.MaxDownloadSize
            };

            _cacheCleanupTimer = new Timer(CleanupExpiredCache, null, TimeSpan.FromHours(1), TimeSpan.FromHours(1));

        }

        /// <summary>
        /// Enhances a certificate chain by fetching missing intermediate certificates via AIA
        /// and optionally caching CRLs for offline revocation checking.
        /// </summary>
        /// <param name="certificate">The end-entity certificate to enhance</param>
        /// <param name="fetchCrls">Whether to also fetch and cache CRLs</param>
        /// <param name="useOfflineRevocation">Whether to use offline revocation checking</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Enhancement result with the enhanced chain and operation details</returns>
        public async Task<ChainEnhancementResult> EnhanceCertificateChainAsync(
            X509Certificate2 certificate,
            bool fetchCrls = true,
            bool useOfflineRevocation = false,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            var startTime = DateTime.UtcNow;
            var result = new ChainEnhancementResult();

            try
            {
                _logger.LogDebug("Enhancing chain for: {Subject}", certificate.Subject);

                var intermediateCerts = await FetchIntermediateCertificatesAsync(certificate, cancellationToken);
                result.FetchedIntermediates = intermediateCerts;

                if (fetchCrls)
                {
                    List<X509Certificate2> allCerts = [certificate, .. intermediateCerts];

                    List<string> allCrlUrls = [];
                    foreach (var cert in allCerts)
                    {
                        const string crlDistributionPointsOid = "2.5.29.31";
                        var crlExtension = cert.Extensions[crlDistributionPointsOid];

                        if (crlExtension != null)
                        {
                            var urls = ParseCrlDistributionPointsExtension(crlExtension.RawData);
                            allCrlUrls.AddRange(urls);
                        }
                    }

                    result.CrlUrls = allCrlUrls.Distinct().ToList();

                    if (result.CrlUrls.Count > 0)
                    {
                        result.CrlCacheSuccess = await CacheCrlsAsync(result.CrlUrls, cancellationToken);
                    }
                }

                if (intermediateCerts.Count > 0 || fetchCrls)
                {
                    result.EnhancedChain = BuildEnhancedChain(certificate, intermediateCerts, useOfflineRevocation);
                    result.Success = result.EnhancedChain != null;
                }

                result.Duration = DateTime.UtcNow - startTime;

                if (result.Success)
                {
                    _logger.LogInformation("Chain enhanced: +{Intermediates} certs, {Duration}ms",
                        result.FetchedIntermediates.Count, (int)result.Duration.TotalMilliseconds);
                }
                else if (result.Errors.Count > 0)
                {
                    _logger.LogWarning("Chain enhancement failed: {Errors}", string.Join("; ", result.Errors));
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Errors.Add($"Chain enhancement failed: {ex.Message}");
                result.Duration = DateTime.UtcNow - startTime;

                _logger.LogError(ex, "Chain enhancement failed for: {Subject}", certificate.Subject);
                return result;
            }
        }

        /// <summary>
        /// Fetches intermediate certificates for the given certificate using AIA extension.
        /// </summary>
        /// <param name="certificate">The certificate to fetch intermediates for</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of fetched intermediate certificates</returns>
        public async Task<List<X509Certificate2>> FetchIntermediateCertificatesAsync(
            X509Certificate2 certificate,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(certificate);

            List<X509Certificate2> certificates = [];
            List<string> aiaUrls = [];
            foreach (var extension in certificate.Extensions)
            {
                if (extension is X509AuthorityInformationAccessExtension aiaExt)
                {
                    foreach (var uri in aiaExt.EnumerateCAIssuersUris())
                    {
                        if (!string.IsNullOrEmpty(uri))
                        {
                            aiaUrls.Add(uri);
                        }
                    }
                    break;
                }
            }

            if (aiaUrls.Count == 0)
            {
                _logger.LogDebug("No AIA URLs found for: {Subject}", certificate.Subject);
                return certificates;
            }

            foreach (var url in aiaUrls)
            {
                try
                {
                    if (_options.EnableCaching && _certificateCache.TryGetValue(url, out var cached))
                    {
                        if (cached.ExpiryTime > DateTime.UtcNow)
                        {
                            certificates.Add(cached.Certificate);
                            break; // Success, stop trying other URLs
                        }
                        else
                        {
                            _certificateCache.TryRemove(url, out _);
                        }
                    }

                    using var response = await _httpClient.GetAsync(url, cancellationToken);

                    if (response.IsSuccessStatusCode)
                    {
                        var certData = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                        if (certData.Length > 0)
                        {
                            var intermediateCert = X509CertificateLoader.LoadCertificate(certData);

                            if (_options.EnableCaching)
                            {
                                var expiry = DateTime.UtcNow.Add(_options.CertificateCacheDuration);
                                _certificateCache.TryAdd(url, new CachedCertificate(intermediateCert, expiry));
                            }

                            certificates.Add(intermediateCert);
                            break; // Success, stop trying other URLs
                        }
                    }
                    else
                    {
                        _logger.LogWarning("HTTP {StatusCode} fetching certificate from {Url}", response.StatusCode, url);
                        continue;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to fetch certificate from {Url}: {Error}", url, ex.Message);
                    continue;
                }
            }


            return certificates;
        }

        /// <summary>
        /// Caches CRLs for the provided URLs in the Windows certificate store.
        /// </summary>
        /// <param name="crlUrls">List of CRL URLs to fetch and cache</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if at least one CRL was successfully cached</returns>
        public async Task<bool> CacheCrlsAsync(List<string> crlUrls, CancellationToken cancellationToken = default)
        {
            if (crlUrls.Count == 0)
                return false;

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.LogWarning("CRL caching only supported on Windows");
                return false;
            }

            bool anySuccess = false;
            var cacheTasks = crlUrls.Select(async url =>
            {
                try
                {
                    if (_options.EnableCaching && _crlCache.TryGetValue(url, out var cached))
                    {
                        if (cached.ExpiryTime > DateTime.UtcNow)
                        {
                            return cached.IsValid ? cached.DerData : null;
                        }
                        else
                        {
                            _crlCache.TryRemove(url, out _);
                        }
                    }

                    using var response = await _httpClient.GetAsync(url, cancellationToken);

                    if (response.IsSuccessStatusCode)
                    {
                        var crlData = await response.Content.ReadAsByteArrayAsync(cancellationToken);
                        if (crlData.Length > 0)
                        {
                            var validationResult = ValidateCrlData(crlData);

                            if (_options.EnableCaching)
                            {
                                var expiry = validationResult.NextUpdate ?? DateTime.UtcNow.Add(_options.CrlCacheDuration);
                                _crlCache.TryAdd(url, new CachedCrlResult(validationResult.IsValid, validationResult.DerData, expiry));
                            }

                            if (validationResult.IsValid)
                            {
                                bool cacheSuccess = CacheCrlInStore(validationResult.DerData, _options.DefaultCrlStore);
                                if (cacheSuccess)
                                {
                                    return validationResult.DerData;
                                }
                            }
                        }
                    }
                    else
                    {
                        _logger.LogWarning("HTTP {StatusCode} fetching CRL from {Url}", response.StatusCode, url);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning("Failed to fetch CRL from {Url}: {Error}", url, ex.Message);
                }

                return null;
            });

            var cacheResults = await Task.WhenAll(cacheTasks);
            anySuccess = cacheResults.Any(result => result != null);

            return anySuccess;
        }



        /// <summary>
        /// Parses CRL Distribution Points extension using ASN.1 reader.
        /// </summary>
        /// <param name="extensionData">The raw extension data</param>
        /// <returns>List of CRL URLs</returns>
        private List<string> ParseCrlDistributionPointsExtension(byte[] extensionData)
        {
            List<string> urls = [];

            try
            {
                var reader = new AsnReader(extensionData, AsnEncodingRules.DER);
                var sequenceReader = reader.ReadSequence();

                while (sequenceReader.HasData)
                {
                    ParseDistributionPoint(sequenceReader.ReadSequence(), urls);
                }
            }
            catch (CryptographicException ex)
            {
                _logger.LogDebug(ex, "Cryptographic error parsing CRL distribution points extension");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to parse CRL distribution points extension");
            }

            return urls;
        }

        private void ParseDistributionPoint(AsnReader distributionPointReader, List<string> urls)
        {
            while (distributionPointReader.HasData)
            {
                var tag = distributionPointReader.PeekTag();

                if (IsDistributionPointNameTag(tag))
                {
                    var dpReader = distributionPointReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    ParseDistributionPointName(dpReader, urls);
                }
                else
                {
                    distributionPointReader.ReadEncodedValue();
                }
            }
        }

        private void ParseDistributionPointName(AsnReader dpReader, List<string> urls)
        {
            while (dpReader.HasData)
            {
                var dpTag = dpReader.PeekTag();

                if (IsFullNameTag(dpTag))
                {
                    var fullNameReader = dpReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    ParseGeneralNames(fullNameReader, urls);
                }
                else
                {
                    dpReader.ReadEncodedValue();
                }
            }
        }

        private void ParseGeneralNames(AsnReader fullNameReader, List<string> urls)
        {
            while (fullNameReader.HasData)
            {
                var nameTag = fullNameReader.PeekTag();

                if (IsUriTag(nameTag))
                {
                    var uri = fullNameReader.ReadCharacterString(UniversalTagNumber.IA5String,
                        new Asn1Tag(TagClass.ContextSpecific, 6));

                    if (IsValidHttpUri(uri))
                    {
                        urls.Add(uri);
                        _logger.LogDebug("Parsed CRL URL via ASN.1: {Url}", uri);
                    }
                }
                else
                {
                    fullNameReader.ReadEncodedValue();
                }
            }
        }

        private static bool IsDistributionPointNameTag(Asn1Tag tag) =>
            tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0;

        private static bool IsFullNameTag(Asn1Tag tag) =>
            tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 0;

        private static bool IsUriTag(Asn1Tag tag) =>
            tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6;

        private static bool IsValidHttpUri(string uri) =>
            !string.IsNullOrEmpty(uri) &&
            Uri.TryCreate(uri, UriKind.Absolute, out var validatedUri) &&
            (validatedUri.Scheme == Uri.UriSchemeHttp || validatedUri.Scheme == Uri.UriSchemeHttps);

        /// <summary>
        /// Builds an enhanced certificate chain with the provided intermediate certificates.
        /// </summary>
        /// <param name="certificate">The end-entity certificate</param>
        /// <param name="intermediateCerts">List of intermediate certificates to include</param>
        /// <param name="useOfflineRevocation">Whether to use offline revocation checking</param>
        /// <returns>Enhanced X509Chain or null if building fails</returns>
        private X509Chain? BuildEnhancedChain(
            X509Certificate2 certificate,
            List<X509Certificate2> intermediateCerts,
            bool useOfflineRevocation)
        {
            try
            {
                var enhancedChain = new X509Chain();
                enhancedChain.ChainPolicy.RevocationMode = useOfflineRevocation ? X509RevocationMode.Offline : X509RevocationMode.Online;

                // Set revocation flag if specified in options
                if (_options.RevocationFlag.HasValue)
                {
                    enhancedChain.ChainPolicy.RevocationFlag = _options.RevocationFlag.Value;
                }

                foreach (var intermediateCert in intermediateCerts)
                {
                    enhancedChain.ChainPolicy.ExtraStore.Add(intermediateCert);
                }

                bool chainBuilt = enhancedChain.Build(certificate);

                return chainBuilt ? enhancedChain : null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to build enhanced chain for: {Subject}", certificate.Subject);
                return null;
            }
        }

        /// <summary>
        /// Cache cleanup method that removes expired entries.
        /// </summary>
        private void CleanupExpiredCache(object? state)
        {
            try
            {
                var now = DateTime.UtcNow;
                var expiredCerts = _certificateCache.Where(kvp => kvp.Value.ExpiryTime <= now).ToList();
                var expiredCrls = _crlCache.Where(kvp => kvp.Value.ExpiryTime <= now).ToList();

                foreach (var expired in expiredCerts)
                {
                    _certificateCache.TryRemove(expired.Key, out _);
                }

                foreach (var expired in expiredCrls)
                {
                    _crlCache.TryRemove(expired.Key, out _);
                }


                // Also enforce max cache size
                if (_certificateCache.Count > _options.MaxCacheSize)
                {
                    var toRemove = _certificateCache.OrderBy(kvp => kvp.Value.ExpiryTime).Take(_certificateCache.Count - _options.MaxCacheSize);
                    foreach (var item in toRemove)
                    {
                        _certificateCache.TryRemove(item.Key, out _);
                    }
                }

                if (_crlCache.Count > _options.MaxCacheSize)
                {
                    var toRemove = _crlCache.OrderBy(kvp => kvp.Value.ExpiryTime).Take(_crlCache.Count - _options.MaxCacheSize);
                    foreach (var item in toRemove)
                    {
                        _crlCache.TryRemove(item.Key, out _);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Cache cleanup failed");
            }
        }

        #region CRL Validation and Windows Store Operations


        private CrlValidationResult ValidateCrlData(byte[] crlData)
        {
            try
            {
                if (crlData == null || crlData.Length == 0)
                {
                    _logger.LogWarning("CRL validation failed: data is null or empty");
                    return new CrlValidationResult { IsValid = false };
                }

                byte[] derCrlData;
                var isPemFormat = crlData.Length > 10 &&
                    System.Text.Encoding.ASCII.GetString(crlData[..11]).StartsWith("-----BEGIN");

                if (isPemFormat)
                {
                    _logger.LogDebug("Converting PEM CRL to DER format");
                    var convertedData = ConvertPemToDer(crlData);
                    if (convertedData == null)
                    {
                        _logger.LogWarning("PEM to DER conversion failed");
                        return new CrlValidationResult { IsValid = false };
                    }
                    derCrlData = convertedData;
                }
                else
                {
                    derCrlData = crlData;
                }

                var result = CryptoUtilities.ValidateAndExtractInfo(derCrlData);
                if (result.IsValid)
                {
                    _logger.LogDebug("CRL validation successful, nextUpdate: {NextUpdate}", result.NextUpdate);
                }
                else
                {
                    _logger.LogWarning("CRL validation failed: Cannot create CRL context");
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during CRL validation");
                return new CrlValidationResult { IsValid = false };
            }
        }

        private byte[]? ConvertPemToDer(byte[] pemData)
        {
            try
            {
                if (PemEncoding.TryFindUtf8(pemData, out var pemFields))
                {
                    if (pemData.AsSpan()[pemFields.Label].SequenceEqual("X509 CRL"u8))
                    {
                        return Convert.FromBase64String(System.Text.Encoding.UTF8.GetString(pemData.AsSpan()[pemFields.Base64Data]));
                    }
                }

                _logger.LogWarning("PEM conversion failed: Invalid PEM format or unsupported label");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during PEM to DER conversion");
                return null;
            }
        }

        private bool CacheCrlInStore(byte[] crlData, StoreName storeName)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || crlData == null || crlData.Length == 0)
                return false;

            try
            {
                using var store = new X509Store(storeName, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);

                bool success = store.AddCrlData(crlData);
                if (success)
                {
                    _logger.LogDebug("Successfully cached CRL in {StoreName} store", storeName);
                    store.Flush();
                }
                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to cache CRL in {StoreName} store", storeName);
                return false;
            }
        }

        /// <summary>
        /// Clears all CRLs from the Windows certificate store.
        /// </summary>
        /// <param name="storeName">The certificate store to clear CRLs from</param>
        /// <returns>Number of CRLs removed</returns>
        public int ClearCrlCache(StoreName storeName = StoreName.CertificateAuthority)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.LogWarning("CRL cache clearing only supported on Windows");
                return 0;
            }

            try
            {
                using var store = new X509Store(storeName, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);

                int removedCount = 0;
                var storeHandle = store.StoreHandle;

                if (storeHandle != IntPtr.Zero)
                {
                    // First, collect all CRL contexts (don't delete during enumeration)
                    var crlContexts = new List<IntPtr>();
                    IntPtr crlContext = IntPtr.Zero;
                    while ((crlContext = CryptoInterop.CertEnumCRLsInStore(storeHandle, crlContext)) != IntPtr.Zero)
                    {
                        // Duplicate the context so we can safely delete it later
                        var duplicatedContext = CryptoInterop.CertDuplicateCRLContext(crlContext);
                        if (duplicatedContext != IntPtr.Zero)
                        {
                            crlContexts.Add(duplicatedContext);
                        }
                    }

                    // Now delete all collected CRL contexts
                    foreach (var context in crlContexts)
                    {
                        if (CryptoInterop.CertDeleteCRLFromStore(context))
                        {
                            removedCount++;
                        }
                    }

                    store.Flush();
                }

                // Also clear in-memory caches
                _crlCache.Clear();
                _certificateCache.Clear();

                _logger.LogInformation("Cleared {Count} CRLs from {StoreName} store and in-memory caches", removedCount, storeName);
                return removedCount;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to clear CRL cache from {StoreName} store", storeName);
                return 0;
            }
        }

        #endregion


        #region IDisposable Implementation

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _cacheCleanupTimer?.Dispose();
                _httpClient?.Dispose();

                // Dispose cached certificates
                foreach (var cached in _certificateCache.Values)
                {
                    cached.Certificate?.Dispose();
                }
                _certificateCache.Clear();
                _crlCache.Clear();

                _disposed = true;
            }
        }

        #endregion

        /// <summary>
        /// Simple certificate validation callback for use in ClientCertificateValidation.
        /// Validates the certificate with enhanced chain building and CRL checking.
        /// </summary>
        /// <param name="certificate">The client certificate to validate</param>
        /// <param name="chain">The certificate chain (may be null)</param>
        /// <param name="policyErrors">SSL policy errors</param>
        /// <returns>True if the certificate is valid, false otherwise</returns>
        public bool ValidateClientCertificate(X509Certificate2 certificate, X509Chain? chain, System.Net.Security.SslPolicyErrors policyErrors)
        {
            try
            {

                bool hasProblematicChain = false;
                if (chain != null)
                {
                    var hasRevocationUnknown = chain.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown));
                    var hasPartialChain = chain.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.PartialChain));
                    hasProblematicChain = hasRevocationUnknown || hasPartialChain;

                }

                // If we have problematic chain issues, try to enhance the chain
                if (hasProblematicChain)
                {

                    try
                    {
                        var enhancementTask = EnhanceCertificateChainAsync(certificate, fetchCrls: true, useOfflineRevocation: true);
                        var enhancementResult = enhancementTask.ConfigureAwait(false).GetAwaiter().GetResult();


                        if (enhancementResult.Success && enhancementResult.EnhancedChain != null)
                        {
#if DEBUG
                            var acceptableStatuses = new[] { X509ChainStatusFlags.NoError, X509ChainStatusFlags.UntrustedRoot };
#else
                            var acceptableStatuses = new[] { X509ChainStatusFlags.NoError };
#endif
                            var hasAcceptableErrors = enhancementResult.EnhancedChain.ChainStatus.All(s => acceptableStatuses.Contains(s.Status));

                            if (hasAcceptableErrors)
                            {
                                _logger.LogInformation("Certificate validation succeeded via chain enhancement");
                                return true;
                            }
                            else
                            {
                                _logger.LogWarning("Enhanced chain still has errors: {Errors}",
                                    string.Join(", ", enhancementResult.EnhancedChain.ChainStatus.Select(s => s.Status.ToString())));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Enhanced validation failed, using standard validation");
                    }
                }

                // Fall back to standard validation
                return policyErrors == System.Net.Security.SslPolicyErrors.None;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate validation failed for: {Subject}", certificate.Subject);
                return false;
            }
        }

        /// <summary>
        /// Certificate authentication failed callback that attempts to recover from authentication failures.
        /// Use this in CertificateAuthenticationEvents.OnAuthenticationFailed to rescue rejected certificates.
        /// </summary>
        /// <param name="context">The certificate authentication failed context</param>
        /// <returns>Task representing the async operation</returns>
        public async Task HandleAuthenticationFailedAsync(Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationFailedContext context)
        {
            try
            {
                // Get certificate from HttpContext connection
                var certificate = context.HttpContext.Connection.ClientCertificate;
                if (certificate == null)
                {
                    _logger.LogDebug("No client certificate to recover");
                    return;
                }

                var enhancementResult = await EnhanceCertificateChainAsync(
                    certificate: certificate,
                    fetchCrls: true,
                    useOfflineRevocation: true
                );

                if (enhancementResult.Success && enhancementResult.EnhancedChain != null)
                {
#if DEBUG
                    var acceptableStatuses = new[] { X509ChainStatusFlags.NoError, X509ChainStatusFlags.UntrustedRoot };
#else
                    var acceptableStatuses = new[] { X509ChainStatusFlags.NoError };
#endif
                    var hasAcceptableErrors = enhancementResult.EnhancedChain.ChainStatus.All(s => acceptableStatuses.Contains(s.Status));

                    if (hasAcceptableErrors)
                    {
                        _logger.LogInformation("Authentication recovered via chain enhancement (+{Count} certs)",
                            enhancementResult.FetchedIntermediates.Count);

                        // Create a successful authentication result
                        var claims = new[]
                        {
                            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.NameIdentifier, certificate.Subject),
                            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, certificate.GetNameInfo(X509NameType.SimpleName, false) ?? certificate.Subject),
                            new System.Security.Claims.Claim("certificate-thumbprint", certificate.Thumbprint),
                            new System.Security.Claims.Claim("certificate-enhanced", "true")
                        };

                        var identity = new System.Security.Claims.ClaimsIdentity(claims, Microsoft.AspNetCore.Authentication.Certificate.CertificateAuthenticationDefaults.AuthenticationScheme);
                        var principal = new System.Security.Claims.ClaimsPrincipal(identity);

                        // Set principal first, then signal success
                        context.Principal = principal;
                        context.Success();

                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate recovery failed for: {Subject}", context.HttpContext.Connection.ClientCertificate?.Subject);
            }
        }
    }
}