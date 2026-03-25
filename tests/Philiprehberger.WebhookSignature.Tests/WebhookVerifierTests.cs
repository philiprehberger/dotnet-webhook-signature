using Xunit;
namespace Philiprehberger.WebhookSignature.Tests;

public class WebhookVerifierTests
{
    private const string TestPayload = """{"event":"test"}""";
    private const string TestSecret = "my-secret-key";

    [Fact]
    public void Verify_ValidSignature_ReturnsTrue()
    {
        var verifier = new WebhookVerifier(TestSecret);
        var signature = Webhook.Sign(TestPayload, TestSecret);

        var result = verifier.Verify(TestPayload, signature);

        Assert.True(result);
    }

    [Fact]
    public void Verify_InvalidSignature_ReturnsFalse()
    {
        var verifier = new WebhookVerifier(TestSecret);
        var signature = Webhook.Sign(TestPayload, "different-secret");

        var result = verifier.Verify(TestPayload, signature);

        Assert.False(result);
    }

    [Fact]
    public void Constructor_EmptySecret_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new WebhookVerifier(""));
    }

    [Fact]
    public void Constructor_CustomAlgorithm_UsesAlgorithmForVerification()
    {
        var verifier = new WebhookVerifier(TestSecret, algorithm: HashAlgorithm.SHA512);
        var signature = Webhook.Sign(TestPayload, TestSecret, algorithm: HashAlgorithm.SHA512);

        var result = verifier.Verify(TestPayload, signature);

        Assert.True(result);
    }
}
