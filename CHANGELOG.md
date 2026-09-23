# Changelog

## 0.1.0 - 2026-09-23

- Add typed ACME directory, order, authorization, challenge, and problem models.
- Add deterministic JWS construction, replay-nonce tracking, and bounded
  `badNonce` retry planning.
- Add HTTP-01 and DNS-01 helpers, PKCS#10 CSR creation, and externally owned
  signing keys.
- Add lifecycle request planning, resource-state actions, renewal scheduling,
  and certificate revocation requests.
- Add challenge helper CLI, 31 protocol tests, and four-target CI.
