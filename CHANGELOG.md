# Changelog

## 0.1.0 (2026-03-10)

- Initial release
- `Webhook.Sign()` — HMAC-SHA256 payload signing with timestamp
- `Webhook.Verify()` — signature verification with replay prevention
- `WebhookVerifier` class for DI scenarios
- Constant-time signature comparison
