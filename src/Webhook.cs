using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.WebhookSignature;

/// <summary>
/// Supported HMAC hash algorithms for webhook signing and verification.
/// </summary>
public enum HashAlgorithm
{
    /// <summary>
    /// HMAC-SHA256 (default). Produces a 256-bit hash.
    /// </summary>
    SHA256,

    /// <summary>
    /// HMAC-SHA384. Produces a 384-bit hash.
    /// </summary>
    SHA384,

    /// <summary>
    /// HMAC-SHA512. Produces a 512-bit hash.
    /// </summary>
    SHA512
}

/// <summary>
/// Static methods for HMAC webhook signing and verification.
/// </summary>
public static class Webhook
{
    /// <summary>
    /// Signs a payload with the specified HMAC algorithm and returns a signature string.
    /// Format: {timestamp}.{hex-signature}
    /// </summary>
    public static string Sign(string payload, string secret, long? timestamp = null, HashAlgorithm algorithm = HashAlgorithm.SHA256)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var ts = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedPayload = $"{ts}.{payload}";
        var hash = ComputeHmac(signedPayload, secret, algorithm);
        return $"{ts}.{hash}";
    }

    /// <summary>
    /// Verifies a webhook signature against the payload and secret.
    /// </summary>
    public static bool Verify(string payload, string signature, string secret, int toleranceSeconds = 300, HashAlgorithm algorithm = HashAlgorithm.SHA256)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);
        ArgumentException.ThrowIfNullOrEmpty(signature);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var parts = signature.Split('.', 2);
        if (parts.Length != 2) return false;

        if (!long.TryParse(parts[0], out var timestamp)) return false;

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (Math.Abs(now - timestamp) > toleranceSeconds) return false;

        var signedPayload = $"{timestamp}.{payload}";
        var expected = ComputeHmac(signedPayload, secret, algorithm);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(parts[1]),
            Encoding.UTF8.GetBytes(expected));
    }

    /// <summary>
    /// Extracts a webhook signature from a header dictionary.
    /// Returns null if the header is not found. Case-insensitive header matching.
    /// </summary>
    public static string? ExtractFromHeaders(IDictionary<string, string> headers, string headerName = "X-Webhook-Signature")
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentException.ThrowIfNullOrEmpty(headerName);

        foreach (var kvp in headers)
        {
            if (string.Equals(kvp.Key, headerName, StringComparison.OrdinalIgnoreCase))
                return kvp.Value;
        }

        return null;
    }

    /// <summary>
    /// Verifies a webhook signature by trying each secret in order.
    /// Returns true if any secret produces a valid signature. Useful for key rotation.
    /// </summary>
    public static bool VerifyWithKeyRotation(string payload, string signature, IEnumerable<string> secrets, int toleranceSeconds = 300, HashAlgorithm algorithm = HashAlgorithm.SHA256)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);
        ArgumentException.ThrowIfNullOrEmpty(signature);
        ArgumentNullException.ThrowIfNull(secrets);

        foreach (var secret in secrets)
        {
            if (string.IsNullOrEmpty(secret)) continue;

            if (Verify(payload, signature, secret, toleranceSeconds, algorithm))
                return true;
        }

        return false;
    }

    private static string ComputeHmac(string data, string secret, HashAlgorithm algorithm)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var dataBytes = Encoding.UTF8.GetBytes(data);

        var hash = algorithm switch
        {
            HashAlgorithm.SHA256 => HMACSHA256.HashData(keyBytes, dataBytes),
            HashAlgorithm.SHA384 => HMACSHA384.HashData(keyBytes, dataBytes),
            HashAlgorithm.SHA512 => HMACSHA512.HashData(keyBytes, dataBytes),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
        };

        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

/// <summary>
/// Stateful webhook verifier for dependency injection scenarios.
/// </summary>
public sealed class WebhookVerifier
{
    private readonly string _secret;
    private readonly int _toleranceSeconds;
    private readonly HashAlgorithm _algorithm;

    /// <summary>
    /// Initializes a new instance of the <see cref="WebhookVerifier"/> class with the specified secret, tolerance, and algorithm.
    /// </summary>
    public WebhookVerifier(string secret, int toleranceSeconds = 300, HashAlgorithm algorithm = HashAlgorithm.SHA256)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        _secret = secret;
        _toleranceSeconds = toleranceSeconds;
        _algorithm = algorithm;
    }

    /// <summary>
    /// Verifies a webhook signature against the payload.
    /// </summary>
    public bool Verify(string payload, string signature) =>
        Webhook.Verify(payload, signature, _secret, _toleranceSeconds, _algorithm);
}
