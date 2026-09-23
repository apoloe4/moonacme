# Roadmap

## 0.1 acceptance target

- Typed RFC 8555 resource models and strict JSON codecs.
- Replay-Nonce tracking and `badNonce` retry planning.
- Flattened JSON Web Signature request construction through an injected signer.
- Account, order, authorization, challenge, finalization, download, and
  revocation request planning.
- HTTP-01 and DNS-01 key authorization helpers.
- PKCS#10 CSR construction for P-256 keys.
- Framework-neutral HTTP transport and challenge-provider contracts.
- Deterministic scripted conformance tests and malformed-input tests.
- Native command-line inspection and challenge helper commands.

## Later releases

- Ready-made asynchronous HTTP transport.
- DNS provider packages maintained independently from the protocol core.
- ACME Renewal Information support after the RFC surface stabilizes.
