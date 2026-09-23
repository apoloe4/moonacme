///|
/// A domain name or another identifier requested from an ACME server.
pub(all) struct Identifier {
  kind : String
  value : String
} derive(Eq, Debug)

///|
/// Status values shared by ACME account, order, authorization and challenge
/// resources. Unknown values are retained for forward compatibility.
pub(all) enum ResourceStatus {
  Pending
  Ready
  Processing
  Valid
  Invalid
  Deactivated
  Revoked
  Expired
  Unknown(String)
} derive(Eq, Debug)

///|
pub fn ResourceStatus::parse(text : String) -> ResourceStatus {
  match text {
    "pending" => Pending
    "ready" => Ready
    "processing" => Processing
    "valid" => Valid
    "invalid" => Invalid
    "deactivated" => Deactivated
    "revoked" => Revoked
    "expired" => Expired
    other => Unknown(other)
  }
}

///|
pub fn ResourceStatus::text(self : ResourceStatus) -> String {
  match self {
    Pending => "pending"
    Ready => "ready"
    Processing => "processing"
    Valid => "valid"
    Invalid => "invalid"
    Deactivated => "deactivated"
    Revoked => "revoked"
    Expired => "expired"
    Unknown(value) => value
  }
}

///|
pub(all) enum ChallengeKind {
  Http01
  Dns01
  TlsAlpn01
  Other(String)
} derive(Eq, Debug)

///|
pub fn ChallengeKind::parse(text : String) -> ChallengeKind {
  match text {
    "http-01" => Http01
    "dns-01" => Dns01
    "tls-alpn-01" => TlsAlpn01
    other => Other(other)
  }
}

///|
pub fn ChallengeKind::text(self : ChallengeKind) -> String {
  match self {
    Http01 => "http-01"
    Dns01 => "dns-01"
    TlsAlpn01 => "tls-alpn-01"
    Other(value) => value
  }
}

///|
pub(all) struct Challenge {
  kind : ChallengeKind
  url : String
  status : ResourceStatus
  token : String
  validated : String?
  problem : AcmeProblem?
} derive(Eq, Debug)

///|
pub(all) struct Authorization {
  url : String
  identifier : Identifier
  status : ResourceStatus
  expires : String?
  wildcard : Bool
  challenges : Array[Challenge]
} derive(Eq, Debug)

///|
pub(all) struct Order {
  url : String
  status : ResourceStatus
  identifiers : Array[Identifier]
  authorization_urls : Array[String]
  finalize_url : String
  certificate_url : String?
  expires : String?
  problem : AcmeProblem?
} derive(Eq, Debug)

///|
pub(all) struct Directory {
  new_nonce : String
  new_account : String
  new_order : String
  revoke_cert : String
  key_change : String
  renewal_info : String?
  terms_of_service : String?
  website : String?
  external_account_required : Bool
} derive(Eq, Debug)
