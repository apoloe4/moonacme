///|
/// RFC 8555 uses problem documents for protocol failures. Subproblems preserve
/// per-identifier diagnostics without flattening them into one message.
pub(all) struct AcmeSubproblem {
  kind : String
  detail : String
  identifier : Identifier?
} derive(Eq, Debug)

///|
pub(all) struct AcmeProblem {
  kind : String
  title : String?
  detail : String
  status : Int?
  instance : String?
  subproblems : Array[AcmeSubproblem]
} derive(Eq, Debug)

///|
pub(all) suberror AcmeError {
  Malformed(stage~ : String, detail~ : String)
  Protocol(problem~ : AcmeProblem)
  MissingNonce
  RetryExhausted(attempts~ : Int)
  InvalidState(expected~ : String, actual~ : String)
  Unsupported(feature~ : String)
} derive(Eq, Debug)

///|
/// Stable human-readable text for logs and command-line adapters.
pub fn AcmeError::message(self : AcmeError) -> String {
  match self {
    Malformed(stage~, detail~) => stage + ": " + detail
    Protocol(problem~) => problem.detail
    MissingNonce => "no replay nonce is available"
    RetryExhausted(attempts~) =>
      "retry limit reached after \{attempts} attempts"
    InvalidState(expected~, actual~) =>
      "expected " + expected + ", got " + actual
    Unsupported(feature~) => "unsupported: " + feature
  }
}
