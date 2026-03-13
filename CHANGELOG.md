# Changelog

## 0.2.0 (2026-03-13)

### Added

- Support for HMAC-SHA384 and HMAC-SHA512 algorithms via `HashAlgorithm` enum
- `ExtractFromHeaders` method for parsing signatures from HTTP headers
- `VerifyWithKeyRotation` method for verifying against multiple secrets

## 0.1.1 (2026-03-10)

- Fix README path in csproj so README displays on nuget.org

## 0.1.0 (2026-03-10)

- Initial release
- `Webhook.Sign()` — HMAC-SHA256 payload signing with timestamp
- `Webhook.Verify()` — signature verification with replay prevention
- `WebhookVerifier` class for DI scenarios
- Constant-time signature comparison
