using System.Security.Cryptography;
using System.Text;

namespace Philiprehberger.WebhookSignature;

/// <summary>
/// Static methods for HMAC-SHA256 webhook signing and verification.
/// </summary>
public static class Webhook
{
    /// <summary>
    /// Signs a payload with HMAC-SHA256 and returns a signature string.
    /// Format: {timestamp}.{hex-signature}
    /// </summary>
    public static string Sign(string payload, string secret, long? timestamp = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(payload);
        ArgumentException.ThrowIfNullOrEmpty(secret);

        var ts = timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var signedPayload = $"{ts}.{payload}";
        var hash = ComputeHmac(signedPayload, secret);
        return $"{ts}.{hash}";
    }

    /// <summary>
    /// Verifies a webhook signature against the payload and secret.
    /// </summary>
    public static bool Verify(string payload, string signature, string secret, int toleranceSeconds = 300)
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
        var expected = ComputeHmac(signedPayload, secret);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(parts[1]),
            Encoding.UTF8.GetBytes(expected));
    }

    private static string ComputeHmac(string data, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var dataBytes = Encoding.UTF8.GetBytes(data);
        var hash = HMACSHA256.HashData(keyBytes, dataBytes);
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

    public WebhookVerifier(string secret, int toleranceSeconds = 300)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        _secret = secret;
        _toleranceSeconds = toleranceSeconds;
    }

    /// <summary>
    /// Verifies a webhook signature against the payload.
    /// </summary>
    public bool Verify(string payload, string signature) =>
        Webhook.Verify(payload, signature, _secret, _toleranceSeconds);
}
