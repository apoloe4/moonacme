# Project boundaries

MoonACME implements ACME protocol behavior. It does not implement a certificate
authority, TLS stack, web server, DNS server, or general-purpose cryptographic
library. Those capabilities enter through small interfaces or established
MoonBit packages.

The portable core never reads the system clock, opens a socket, mutates DNS, or
writes a private key. Callers provide those effects. This keeps protocol tests
deterministic and lets native services, CI workers, and WebAssembly hosts reuse
the same state machine.

The library treats account and certificate private keys as caller-owned. It
accepts signing and CSR callbacks instead of serializing secret material into
diagnostic values.
