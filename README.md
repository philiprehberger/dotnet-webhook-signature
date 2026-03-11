# Philiprehberger.WebhookSignature

HMAC-SHA256 webhook signing and verification with replay prevention.

## Install

```bash
dotnet add package Philiprehberger.WebhookSignature
```

## Usage

```csharp
using Philiprehberger.WebhookSignature;

// Sign a payload
var signature = Webhook.Sign(payload, "your-secret");

// Verify a signature
bool valid = Webhook.Verify(payload, signature, "your-secret");

// With custom replay tolerance (default: 300 seconds)
bool valid = Webhook.Verify(payload, signature, "your-secret", toleranceSeconds: 60);
```

### Dependency Injection

```csharp
var verifier = new WebhookVerifier("your-secret", toleranceSeconds: 300);
bool valid = verifier.Verify(payload, signature);
```

### ASP.NET Controller

```csharp
[HttpPost("webhook")]
public IActionResult HandleWebhook(
    [FromBody] string payload,
    [FromHeader(Name = "X-Signature")] string signature)
{
    if (!Webhook.Verify(payload, signature, _secret))
        return Unauthorized();

    // Process webhook...
    return Ok();
}
```

## API

| Method | Description |
|--------|-------------|
| `Webhook.Sign(payload, secret, timestamp?)` | Sign a payload, returns `{timestamp}.{hex-hmac}` |
| `Webhook.Verify(payload, signature, secret, toleranceSeconds?)` | Verify signature with replay prevention |
| `WebhookVerifier.Verify(payload, signature)` | Instance method for DI scenarios |

## Signature Format

Signatures use the format `{unix-timestamp}.{hex-encoded-hmac-sha256}`. The timestamp is included in the HMAC input to prevent replay attacks.

## License

MIT
