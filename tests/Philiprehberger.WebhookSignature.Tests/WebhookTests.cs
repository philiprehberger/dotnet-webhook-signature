using Xunit;
namespace Philiprehberger.WebhookSignature.Tests;

public class WebhookTests
{
    private const string TestPayload = """{"event":"test"}""";
    private const string TestSecret = "my-secret-key";

    [Fact]
    public void Sign_ValidInputs_ReturnsTimestampDotSignature()
    {
        var result = Webhook.Sign(TestPayload, TestSecret, timestamp: 1000000);

        Assert.Contains(".", result);
        var parts = result.Split('.', 2);
        Assert.Equal("1000000", parts[0]);
        Assert.NotEmpty(parts[1]);
    }

    [Fact]
    public void Sign_SameInputs_ProducesSameSignature()
    {
        var sig1 = Webhook.Sign(TestPayload, TestSecret, timestamp: 1000000);
        var sig2 = Webhook.Sign(TestPayload, TestSecret, timestamp: 1000000);

        Assert.Equal(sig1, sig2);
    }

    [Fact]
    public void Verify_ValidSignature_ReturnsTrue()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);

        var result = Webhook.Verify(TestPayload, signature, TestSecret);

        Assert.True(result);
    }

    [Fact]
    public void Verify_WrongSecret_ReturnsFalse()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);

        var result = Webhook.Verify(TestPayload, signature, "wrong-secret");

        Assert.False(result);
    }

    [Fact]
    public void Verify_TamperedPayload_ReturnsFalse()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);

        var result = Webhook.Verify("tampered", signature, TestSecret);

        Assert.False(result);
    }

    [Fact]
    public void Verify_ExpiredTimestamp_ReturnsFalse()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret, timestamp: 1000000);

        var result = Webhook.Verify(TestPayload, signature, TestSecret, toleranceSeconds: 300);

        Assert.False(result);
    }

    [Fact]
    public void Verify_InvalidSignatureFormat_ReturnsFalse()
    {
        var result = Webhook.Verify(TestPayload, "invalid-signature", TestSecret);

        Assert.False(result);
    }

    [Theory]
    [InlineData(HashAlgorithm.SHA256)]
    [InlineData(HashAlgorithm.SHA384)]
    [InlineData(HashAlgorithm.SHA512)]
    public void Sign_DifferentAlgorithms_ProducesVerifiableSignatures(HashAlgorithm algorithm)
    {
        var signature = Webhook.Sign(TestPayload, TestSecret, algorithm: algorithm);

        var result = Webhook.Verify(TestPayload, signature, TestSecret, algorithm: algorithm);

        Assert.True(result);
    }

    [Fact]
    public void Sign_EmptyPayload_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Webhook.Sign("", TestSecret));
    }

    [Fact]
    public void Sign_EmptySecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Webhook.Sign(TestPayload, ""));
    }

    [Fact]
    public void ExtractFromHeaders_ExistingHeader_ReturnsValue()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Webhook-Signature"] = "123.abc"
        };

        var result = Webhook.ExtractFromHeaders(headers);

        Assert.Equal("123.abc", result);
    }

    [Fact]
    public void ExtractFromHeaders_CaseInsensitive_ReturnsValue()
    {
        var headers = new Dictionary<string, string>
        {
            ["x-webhook-signature"] = "123.abc"
        };

        var result = Webhook.ExtractFromHeaders(headers);

        Assert.Equal("123.abc", result);
    }

    [Fact]
    public void ExtractFromHeaders_MissingHeader_ReturnsNull()
    {
        var headers = new Dictionary<string, string>();

        var result = Webhook.ExtractFromHeaders(headers);

        Assert.Null(result);
    }

    [Fact]
    public void ExtractFromHeaders_CustomHeaderName_ReturnsValue()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Custom-Sig"] = "456.def"
        };

        var result = Webhook.ExtractFromHeaders(headers, "X-Custom-Sig");

        Assert.Equal("456.def", result);
    }

    [Fact]
    public void VerifyWithKeyRotation_MatchingSecret_ReturnsTrue()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);
        var secrets = new[] { "old-secret", TestSecret, "new-secret" };

        var result = Webhook.VerifyWithKeyRotation(TestPayload, signature, secrets);

        Assert.True(result);
    }

    [Fact]
    public void VerifyWithKeyRotation_NoMatchingSecret_ReturnsFalse()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);
        var secrets = new[] { "wrong1", "wrong2" };

        var result = Webhook.VerifyWithKeyRotation(TestPayload, signature, secrets);

        Assert.False(result);
    }

    [Fact]
    public void VerifyWithKeyRotation_EmptySecrets_ReturnsFalse()
    {
        var signature = Webhook.Sign(TestPayload, TestSecret);

        var result = Webhook.VerifyWithKeyRotation(TestPayload, signature, Array.Empty<string>());

        Assert.False(result);
    }
}
