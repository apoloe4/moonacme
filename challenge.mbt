///|
fn base64url(input : BytesView) -> String {
  @base64.encode(input, kind=Url, padding=false)
}

///|
fn token_char_allowed(c : Char) -> Bool {
  (c >= 'A' && c <= 'Z') ||
  (c >= 'a' && c <= 'z') ||
  (c >= '0' && c <= '9') ||
  c == '-' ||
  c == '_'
}

///|
/// Check the lexical requirements for an ACME challenge token. The protocol
/// requires at least 128 bits of entropy; 22 base64url characters are the
/// shortest representation that can carry that many bits.
pub fn validate_challenge_token(token : String) -> Bool {
  if token.length() < 22 {
    return false
  }
  for c in token {
    if !token_char_allowed(c) {
      return false
    }
  }
  true
}

///|
/// RFC 8555 key authorization: token + "." + account-key JWK thumbprint.
pub fn key_authorization(
  token : String,
  account_thumbprint : String,
) -> String raise AcmeError {
  if !validate_challenge_token(token) {
    raise malformed("challenge", "invalid challenge token")
  }
  if account_thumbprint.length() == 0 {
    raise malformed("challenge", "empty account-key thumbprint")
  }
  token + "." + account_thumbprint
}

///|
/// URL path provisioned by an HTTP-01 responder.
pub fn http01_path(token : String) -> String raise AcmeError {
  if !validate_challenge_token(token) {
    raise malformed("http-01", "invalid challenge token")
  }
  "/.well-known/acme-challenge/" + token
}

///|
/// DNS TXT value for `_acme-challenge.<domain>`.
pub fn dns01_txt_value(
  token : String,
  account_thumbprint : String,
) -> String raise AcmeError {
  let authorization = key_authorization(token, account_thumbprint)
  base64url(@sha2.hash(@utf8.encode(authorization[:])[:])[:])
}

///|
/// RFC 7638 thumbprint of a caller-supplied canonical public JWK. Callers that
/// use P-256 should prefer `p256_jwk_thumbprint` below.
pub fn jwk_thumbprint(canonical_public_jwk : String) -> String {
  base64url(@sha2.hash(@utf8.encode(canonical_public_jwk[:])[:])[:])
}

///|
/// Canonical public JWK for an uncompressed P-256 key. Coordinates are the
/// 32-byte unsigned big-endian x and y values, not a DER SubjectPublicKeyInfo.
pub fn canonical_p256_jwk(
  x : BytesView,
  y : BytesView,
) -> String raise AcmeError {
  if x.length() != 32 || y.length() != 32 {
    raise malformed("jwk", "P-256 coordinates must each contain 32 bytes")
  }
  @json.dumps(
    Json::object({
      "crv": Json::string("P-256"),
      "kty": Json::string("EC"),
      "x": Json::string(base64url(x)),
      "y": Json::string(base64url(y)),
    }),
    sort=true,
  )
}

///|
pub fn p256_jwk_thumbprint(
  x : BytesView,
  y : BytesView,
) -> String raise AcmeError {
  jwk_thumbprint(canonical_p256_jwk(x, y))
}

///|
/// A framework-neutral HTTP-01 resource that can be installed in a router,
/// static-file adapter, or test server.
pub(all) struct Http01Resource {
  path : String
  body : String
  content_type : String
} derive(Eq, Debug)

///|
pub fn Http01Resource::new(
  token : String,
  account_thumbprint : String,
) -> Http01Resource raise AcmeError {
  {
    path: http01_path(token),
    body: key_authorization(token, account_thumbprint),
    content_type: "application/octet-stream",
  }
}

///|
/// Normalize a DNS identifier into the owner name used by DNS-01. A leading
/// wildcard label is removed as required by RFC 8555.
pub fn dns01_record_name(identifier : String) -> String raise AcmeError {
  let name = if identifier.has_prefix("*.") {
    identifier[2:].to_owned()
  } else {
    identifier
  }
  if name.length() == 0 {
    raise malformed("dns-01", "empty DNS identifier")
  }
  "_acme-challenge." + name
}
