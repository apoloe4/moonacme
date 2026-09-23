///|
fn malformed(stage : String, detail : String) -> AcmeError {
  AcmeError::Malformed(stage~, detail~)
}

///|
fn object_at(value : Json, stage : String) -> Map[String, Json] raise AcmeError {
  match value {
    Object(fields) => fields
    _ => raise malformed(stage, "expected a JSON object")
  }
}

///|
fn required_string(
  fields : Map[String, Json],
  name : String,
  stage : String,
) -> String raise AcmeError {
  match fields.get(name) {
    Some(String(value)) => value
    Some(_) => raise malformed(stage, "field `\{name}` must be a string")
    None => raise malformed(stage, "missing string field `\{name}`")
  }
}

///|
fn optional_string(
  fields : Map[String, Json],
  name : String,
  stage : String,
) -> String? raise AcmeError {
  match fields.get(name) {
    Some(String(value)) => Some(value)
    Some(Null) | None => None
    Some(_) => raise malformed(stage, "field `\{name}` must be a string")
  }
}

///|
fn optional_bool(
  fields : Map[String, Json],
  name : String,
  stage : String,
  fallback : Bool,
) -> Bool raise AcmeError {
  match fields.get(name) {
    Some(True) => true
    Some(False) => false
    Some(Null) | None => fallback
    Some(_) => raise malformed(stage, "field `\{name}` must be a boolean")
  }
}

///|
fn string_array(
  fields : Map[String, Json],
  name : String,
  stage : String,
) -> Array[String] raise AcmeError {
  match fields.get(name) {
    Some(Array(values)) => {
      let out : Array[String] = []
      for value in values {
        match value {
          String(text) => out.push(text)
          _ => raise malformed(stage, "field `\{name}` must contain strings")
        }
      }
      out
    }
    Some(_) => raise malformed(stage, "field `\{name}` must be an array")
    None => raise malformed(stage, "missing array field `\{name}`")
  }
}

///|
fn parse_json(input : String, stage : String) -> Json raise AcmeError {
  @json.loads(input[:]) catch {
    _ => raise malformed(stage, "invalid JSON")
  }
}

///|
/// Decode an ACME directory document and its commonly used metadata.
pub fn Directory::decode(input : String) -> Directory raise AcmeError {
  let fields = object_at(parse_json(input, "directory"), "directory")
  let meta = match fields.get("meta") {
    Some(value) => object_at(value, "directory.meta")
    None => Map([])
  }
  Directory::{
    new_nonce: required_string(fields, "newNonce", "directory"),
    new_account: required_string(fields, "newAccount", "directory"),
    new_order: required_string(fields, "newOrder", "directory"),
    revoke_cert: required_string(fields, "revokeCert", "directory"),
    key_change: required_string(fields, "keyChange", "directory"),
    renewal_info: optional_string(fields, "renewalInfo", "directory"),
    terms_of_service: optional_string(meta, "termsOfService", "directory.meta"),
    website: optional_string(meta, "website", "directory.meta"),
    external_account_required: optional_bool(
      meta, "externalAccountRequired", "directory.meta", false,
    ),
  }
}

///|
fn decode_identifier(
  value : Json,
  stage : String,
) -> Identifier raise AcmeError {
  let fields = object_at(value, stage)
  Identifier::{
    kind: required_string(fields, "type", stage),
    value: required_string(fields, "value", stage),
  }
}

///|
fn identifier_array(
  fields : Map[String, Json],
  name : String,
  stage : String,
) -> Array[Identifier] raise AcmeError {
  match fields.get(name) {
    Some(Array(values)) => {
      let out : Array[Identifier] = []
      for value in values {
        out.push(decode_identifier(value, "\{stage}.\{name}"))
      }
      out
    }
    Some(_) => raise malformed(stage, "field `\{name}` must be an array")
    None => raise malformed(stage, "missing array field `\{name}`")
  }
}

///|
/// Decode an order body. The resource URL comes from the response Location
/// header and is supplied separately.
pub fn Order::decode(input : String, url~ : String) -> Order raise AcmeError {
  let fields = object_at(parse_json(input, "order"), "order")
  Order::{
    url,
    status: ResourceStatus::parse(required_string(fields, "status", "order")),
    identifiers: identifier_array(fields, "identifiers", "order"),
    authorization_urls: string_array(fields, "authorizations", "order"),
    finalize_url: required_string(fields, "finalize", "order"),
    certificate_url: optional_string(fields, "certificate", "order"),
    expires: optional_string(fields, "expires", "order"),
    problem: None,
  }
}

///|
/// Encode the RFC 8555 new-order payload in deterministic key order.
pub fn encode_new_order(identifiers : Array[Identifier]) -> String {
  let values : Array[Json] = []
  for identifier in identifiers {
    values.push(
      Json::object({
        "type": Json::string(identifier.kind),
        "value": Json::string(identifier.value),
      }),
    )
  }
  @json.dumps(Json::object({ "identifiers": Json::array(values) }), sort=true)
}

///|
/// Encode a new-account payload. An empty contacts array is valid.
pub fn encode_new_account(
  contacts : Array[String],
  terms_agreed : Bool,
) -> String {
  let values : Array[Json] = []
  for contact in contacts {
    values.push(Json::string(contact))
  }
  @json.dumps(
    Json::object({
      "contact": Json::array(values),
      "termsOfServiceAgreed": Json::boolean(terms_agreed),
    }),
    sort=true,
  )
}
