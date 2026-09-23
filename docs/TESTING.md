# Testing MoonACME

The test suite focuses on protocol behavior that can be verified without a
network: deterministic JSON and JWS construction, one-time nonce consumption,
`badNonce` retry decisions, HTTP-01 and DNS-01 challenge values, strict resource
decoding, lifecycle request planning, renewal boundaries, PKCS#10 assembly and
state-machine transitions.

Run the same strict checks used by CI:

```sh
moon update
moon check --deny-warn --target wasm
moon test --deny-warn --target wasm
```

CI repeats the check and test suite for `wasm`, `wasm-gc`, `js`, and `native`.
The transport-neutral core has no target-specific branches.

The current suite is deterministic and does not contact a certificate
authority. End-to-end interoperability with Pebble is planned before 1.0 and
is deliberately not claimed by the 0.1 release.
