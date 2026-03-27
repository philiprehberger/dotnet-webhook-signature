# Philiprehberger.WebhookSignature

[![CI](https://github.com/philiprehberger/dotnet-webhook-signature/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/dotnet-webhook-signature/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Philiprehberger.WebhookSignature.svg)](https://www.nuget.org/packages/Philiprehberger.WebhookSignature)
[![License](https://img.shields.io/github/license/philiprehberger/dotnet-webhook-signature)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

HMAC webhook signing and verification with replay prevention — supports SHA-256, SHA-384, and SHA-512.

## Installation

```bash
dotnet add package Philiprehberger.WebhookSignature
```

## Usage

```csharp
using Philiprehberger.WebhookSignature;

// Sign a payload (defaults to HMAC-SHA256)
var signature = Webhook.Sign(payload, "your-secret");

// Verify a signature
bool valid = Webhook.Verify(payload, signature, "your-secret");

// With custom replay tolerance (default: 300 seconds)
bool valid = Webhook.Verify(payload, signature, "your-secret", toleranceSeconds: 60);
```

### Algorithm Selection

Choose between SHA-256, SHA-384, and SHA-512:

```csharp
// Sign with SHA-512
var signature = Webhook.Sign(payload, "your-secret", algorithm: HashAlgorithm.SHA512);

// Verify with SHA-512
bool valid = Webhook.Verify(payload, signature, "your-secret", algorithm: HashAlgorithm.SHA512);
```

### Header Extraction

Extract signatures from HTTP header dictionaries with case-insensitive matching:

```csharp
var headers = new Dictionary<string, string>
{
    ["X-Webhook-Signature"] = signature
};

// Uses "X-Webhook-Signature" by default
string? sig = Webhook.ExtractFromHeaders(headers);

// Or specify a custom header name
string? sig = Webhook.ExtractFromHeaders(headers, "X-Custom-Sig");
```

### Key Rotation

Verify against multiple secrets during key rotation:

```csharp
var secrets = new[] { "new-secret", "old-secret" };
bool valid = Webhook.VerifyWithKeyRotation(payload, signature, secrets);

// With custom tolerance and algorithm
bool valid = Webhook.VerifyWithKeyRotation(
    payload, signature, secrets,
    toleranceSeconds: 60,
    algorithm: HashAlgorithm.SHA512);
```

### Dependency Injection

```csharp
var verifier = new WebhookVerifier("your-secret", toleranceSeconds: 300);
bool valid = verifier.Verify(payload, signature);

// With a specific algorithm
var verifier = new WebhookVerifier("your-secret", algorithm: HashAlgorithm.SHA384);
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
| `Webhook.Sign(payload, secret, timestamp?, algorithm?)` | Sign a payload, returns `{timestamp}.{hex-hmac}` |
| `Webhook.Verify(payload, signature, secret, toleranceSeconds?, algorithm?)` | Verify signature with replay prevention |
| `Webhook.ExtractFromHeaders(headers, headerName?)` | Extract signature from header dictionary (case-insensitive) |
| `Webhook.VerifyWithKeyRotation(payload, signature, secrets, toleranceSeconds?, algorithm?)` | Verify against multiple secrets for key rotation |
| `WebhookVerifier.Verify(payload, signature)` | Instance method for DI scenarios |

### Signature Format

Signatures use the format `{unix-timestamp}.{hex-encoded-hmac}`. The timestamp is included in the HMAC input to prevent replay attacks.

## Development

```bash
dotnet build src/Philiprehberger.WebhookSignature.csproj --configuration Release
```

## License

MIT
