///|
/// A signed request before its signature is attached.
pub(all) struct PreparedRequest {
  verb : String
  url : String
  draft : JwsDraft
  accept : String
} derive(Eq, Debug)

///|
/// Transport-neutral HTTP request. Native, JavaScript and test transports only
/// need to send this value and return status, headers and bytes.
pub(all) struct HttpRequest {
  verb : String
  url : String
  headers : Array[Header]
  body : String
} derive(Eq, Debug)

///|
pub fn PreparedRequest::finish(
  self : PreparedRequest,
  signature : BytesView,
) -> HttpRequest raise AcmeError {
  {
    verb: self.verb,
    url: self.url,
    headers: [
      { name: "content-type", value: "application/jose+json", },
      { name: "accept", value: self.accept, },
      { name: "user-agent", value: "moonacme/0.1", },
    ],
    body: self.draft.finish(signature),
  }
}

///|
/// Protocol session state. The directory, account identity and replay nonces
/// live together so a request cannot accidentally use a nonce twice or send a
/// KID request before account creation.
pub struct AcmeSession {
  directory : Directory
  algorithm : String
  public_jwk : String
  mut kid : String?
  nonces : NoncePool
}

///|
pub fn AcmeSession::new(
  directory~ : Directory,
  algorithm~ : String,
  public_jwk~ : String,
) -> AcmeSession raise AcmeError {
  match parse_json(public_jwk, "session.jwk") {
    Object(_) => ()
    _ => raise malformed("session.jwk", "public JWK must be a JSON object")
  }
  if algorithm.length() == 0 {
    raise malformed("session", "empty signing algorithm")
  }
  { directory, algorithm, public_jwk, kid: None, nonces: NoncePool::new(), }
}

///|
pub fn AcmeSession::account_url(self : AcmeSession) -> String? {
  self.kid
}

///|
pub fn AcmeSession::bind_account(
  self : AcmeSession,
  kid : String,
) -> Unit raise AcmeError {
  if kid.length() == 0 {
    raise malformed("account", "empty account URL")
  }
  self.kid = Some(kid)
}

///|
pub fn AcmeSession::offer_nonce(self : AcmeSession, nonce : String) -> Bool {
  self.nonces.offer(nonce)
}

///|
pub fn AcmeSession::observe_headers(
  self : AcmeSession,
  headers : Array[Header],
) -> Bool {
  match replay_nonce(headers) {
    Some(nonce) => self.offer_nonce(nonce)
    None => false
  }
}

///|
fn AcmeSession::binding(self : AcmeSession) -> AccountBinding raise AcmeError {
  match self.kid {
    Some(kid) => AccountBinding::KeyId(kid)
    None =>
      raise AcmeError::InvalidState(
        expected="registered account URL",
        actual="unregistered account",
      )
  }
}

///|
fn AcmeSession::prepare(
  self : AcmeSession,
  url : String,
  payload : String,
  binding : AccountBinding,
  accept : String,
) -> PreparedRequest raise AcmeError {
  let nonce = match self.nonces.take() {
    Some(value) => value
    None => raise AcmeError::MissingNonce
  }
  {
    verb: "POST",
    url,
    draft: JwsDraft::new(
      algorithm=self.algorithm,
      nonce~,
      url~,
      payload~,
      binding~,
    ),
    accept,
  }
}

///|
pub fn AcmeSession::prepare_new_account(
  self : AcmeSession,
  contacts : Array[String],
  terms_agreed : Bool,
) -> PreparedRequest raise AcmeError {
  self.prepare(
    self.directory.new_account,
    encode_new_account(contacts, terms_agreed),
    AccountBinding::PublicJwk(self.public_jwk),
    "application/json",
  )
}

///|
pub fn AcmeSession::prepare_new_order(
  self : AcmeSession,
  identifiers : Array[Identifier],
) -> PreparedRequest raise AcmeError {
  if identifiers.length() == 0 {
    raise malformed("new-order", "at least one identifier is required")
  }
  self.prepare(
    self.directory.new_order,
    encode_new_order(identifiers),
    self.binding(),
    "application/json",
  )
}

///|
pub fn AcmeSession::prepare_post_as_get(
  self : AcmeSession,
  url : String,
  accept? : String = "application/json",
) -> PreparedRequest raise AcmeError {
  self.prepare(url, "", self.binding(), accept)
}

///|
pub fn AcmeSession::prepare_challenge_ack(
  self : AcmeSession,
  challenge_url : String,
) -> PreparedRequest raise AcmeError {
  self.prepare(challenge_url, "{}", self.binding(), "application/json")
}

///|
pub fn AcmeSession::prepare_finalize(
  self : AcmeSession,
  finalize_url : String,
  csr_der : BytesView,
) -> PreparedRequest raise AcmeError {
  if csr_der.length() == 0 {
    raise malformed("finalize", "empty PKCS#10 CSR")
  }
  let payload = @json.dumps(
    Json::object({ "csr": Json::string(base64url(csr_der)) }),
    sort=true,
  )
  self.prepare(finalize_url, payload, self.binding(), "application/json")
}

///|
pub fn AcmeSession::prepare_download(
  self : AcmeSession,
  certificate_url : String,
) -> PreparedRequest raise AcmeError {
  self.prepare_post_as_get(
    certificate_url,
    accept="application/pem-certificate-chain",
  )
}

///|
pub fn AcmeSession::prepare_revoke(
  self : AcmeSession,
  certificate_der : BytesView,
) -> PreparedRequest raise AcmeError {
  if certificate_der.length() == 0 {
    raise malformed("revoke", "empty certificate")
  }
  let payload = @json.dumps(
    Json::object({ "certificate": Json::string(base64url(certificate_der)) }),
    sort=true,
  )
  self.prepare(
    self.directory.revoke_cert,
    payload,
    self.binding(),
    "application/json",
  )
}
