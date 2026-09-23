# Protocol guide

MoonACME separates pure protocol decisions from effects. A host supplies an
HTTP adapter and two signers: an account key signs ACME JWS requests, while a
certificate key signs the PKCS#10 request. They may be the same key, but the API
does not require that choice.

## Lifecycle

1. Fetch the CA directory and decode it with `Directory::decode`.
2. Fetch a replay nonce, create `AcmeSession`, and call `offer_nonce`.
3. Prepare and sign `newAccount`; bind the returned account URL with
   `bind_account`.
4. Prepare `newOrder`, decode the response, then follow `Order::next_action`.
5. For each authorization, select a pending HTTP-01 or DNS-01 challenge,
   provision the returned value, acknowledge the challenge, and poll.
6. Build `CsrDraft`, sign its `signing_input`, and call
   `finish_ecdsa_sha256`.
7. Prepare finalization, poll while processing, and download the PEM chain when
   the order becomes valid.
8. Schedule the next run with `plan_renewal`.

Every response should be passed to `observe_headers` before the next request.
This captures the server's `Replay-Nonce` without coupling MoonACME to an HTTP
library. A `badNonce` problem can be evaluated with `RetryPolicy`; the returned
decision says whether to retry immediately, fetch a fresh nonce, or stop.

## Transport contract

`PreparedRequest::finish` produces a complete `HttpRequest` with method, URL,
headers, and JWS body. The host sends it and retains response status, headers,
and raw bytes. JSON resources are decoded by their corresponding types;
certificate downloads stay as PEM bytes owned by the host.

No background task is hidden in the library. Provisioning and cleanup remain
explicit, which makes failure recovery and audit logs application-specific.
