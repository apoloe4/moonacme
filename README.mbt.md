# MoonACME

MoonACME is a transport-neutral implementation of the Automatic Certificate
Management Environment protocol (RFC 8555) for MoonBit. It models ACME
directories, accounts, orders, authorizations, challenges, nonces, signed
requests, renewal decisions, and certificate lifecycle operations without
binding the protocol core to a particular HTTP client, DNS provider, web
framework, clock, or filesystem.

The initial release is under active development. See `docs/ROADMAP.md` for the
acceptance plan and `docs/BOUNDARIES.md` for explicit scope.
