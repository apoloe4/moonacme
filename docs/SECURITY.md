# Security model

MoonACME handles public protocol data and signing inputs. It never generates,
stores, logs, or serializes a private key. Applications should keep account and
certificate keys in their existing keystore or HSM and expose only a signing
operation.

The host is responsible for TLS verification when contacting the ACME server,
protecting DNS-provider credentials, setting filesystem permissions on issued
certificates, and removing challenge material after validation. Treat directory
URLs and resource URLs as untrusted network input and restrict outbound access
if the transport follows redirects.

Challenge tokens are checked for the RFC 8555 base64url alphabet and minimum
length. Replay nonces are single-use. Retry planning is bounded to avoid an
unlimited loop. JSON decoders reject missing fields and unexpected types while
preserving server extension strings where forward compatibility is safe.

The CSR builder accepts a caller-supplied DER SubjectPublicKeyInfo. The caller
must verify that it belongs to the private certificate key and must sign the
returned CertificationRequestInfo with ECDSA P-256/SHA-256 before calling
`finish_ecdsa_sha256`.

Report vulnerabilities privately to the repository owner through GitHub's
security-advisory interface. Do not include private keys, account URLs, DNS
credentials, or active challenge tokens in a report.
