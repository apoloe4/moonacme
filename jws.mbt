///|
/// How an ACME request identifies its account key. Account creation uses the
/// full public JWK; later requests use the account URL (`kid`).
pub(all) enum AccountBinding {
  PublicJwk(String)
  KeyId(String)
} derive(Eq, Debug)

///|
/// A flattened-JWS request before the cryptographic signature is attached.
/// `signing_input` is the exact ASCII byte sequence passed to an ES256/RS256
/// signer. Keeping signing outside the protocol core prevents private keys
/// from entering diagnostic values or portable state.
pub(all) struct JwsDraft {
  protected_b64 : String
  payload_b64 : String
  signing_input : String
} derive(Eq, Debug)

///|
fn protected_header(
  algorithm : String,
  nonce : String,
  url : String,
  binding : AccountBinding,
) -> String raise AcmeError {
  if algorithm.length() == 0 {
    raise malformed("jws", "empty signing algorithm")
  }
  if nonce.length() == 0 {
    raise AcmeError::MissingNonce
  }
  if url.length() == 0 {
    raise malformed("jws", "empty request URL")
  }
  let common : Map[String, Json] = {
    "alg": Json::string(algorithm),
    "nonce": Json::string(nonce),
    "url": Json::string(url),
  }
  match binding {
    KeyId(kid) => {
      if kid.length() == 0 {
        raise malformed("jws", "empty account key id")
      }
      common["kid"] = Json::string(kid)
    }
    PublicJwk(jwk_text) => {
      let jwk = parse_json(jwk_text, "jws.jwk")
      match jwk {
        Object(_) => common["jwk"] = jwk
        _ => raise malformed("jws.jwk", "public JWK must be a JSON object")
      }
    }
  }
  @json.dumps(Json::object(common), sort=true)
}

///|
pub fn JwsDraft::new(
  algorithm~ : String,
  nonce~ : String,
  url~ : String,
  payload~ : String,
  binding~ : AccountBinding,
) -> JwsDraft raise AcmeError {
  let header_text = protected_header(algorithm, nonce, url, binding)
  let protected_b64 = base64url(@utf8.encode(header_text[:])[:])
  let payload_b64 = base64url(@utf8.encode(payload[:])[:])
  {
    protected_b64,
    payload_b64,
    signing_input: protected_b64 + "." + payload_b64,
  }
}

///|
/// Finish a flattened JWS object with the raw signature bytes returned by the
/// configured algorithm. ES256 adapters must supply the RFC 7515 `R || S`
/// representation, not an ASN.1 DER ECDSA signature.
pub fn JwsDraft::finish(
  self : JwsDraft,
  signature : BytesView,
) -> String raise AcmeError {
  if signature.length() == 0 {
    raise malformed("jws", "empty signature")
  }
  @json.dumps(
    Json::object({
      "payload": Json::string(self.payload_b64),
      "protected": Json::string(self.protected_b64),
      "signature": Json::string(base64url(signature)),
    }),
    sort=true,
  )
}

///|
/// ACME POST-as-GET is a signed request with an empty payload, distinct from a
/// JSON `null` payload.
pub fn JwsDraft::post_as_get(
  algorithm~ : String,
  nonce~ : String,
  url~ : String,
  kid~ : String,
) -> JwsDraft raise AcmeError {
  JwsDraft::new(
    algorithm~,
    nonce~,
    url~,
    payload="",
    binding=AccountBinding::KeyId(kid),
  )
}
