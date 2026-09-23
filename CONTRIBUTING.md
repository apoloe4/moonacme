# Contributing

Issues and focused pull requests are welcome. Before changing protocol behavior,
link the relevant RFC section and add a black-box test that demonstrates the
observable result.

Run these checks before opening a pull request:

```sh
moon update
moon info
moon fmt
moon check --deny-warn --target wasm
moon test --deny-warn --target wasm
```

Keep network, filesystem, clock, and secret-key operations outside the root
package. New provider or transport integrations should live in separate
packages so the core remains portable and deterministic.

Use concise commit subjects such as `feat: decode account resources` or
`test: cover malformed authorization response`. Do not commit private keys,
live challenge tokens, account URLs, or DNS credentials.
