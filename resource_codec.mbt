///|
fn problem_from_json(
  value : Json,
  stage : String,
) -> AcmeProblem raise AcmeError {
  let fields = object_at(value, stage)
  let subproblems : Array[AcmeSubproblem] = []
  match fields.get("subproblems") {
    Some(Array(values)) =>
      for item in values {
        let sub = object_at(item, "\{stage}.subproblems")
        let identifier = match sub.get("identifier") {
          Some(value) => Some(decode_identifier(value, "\{stage}.identifier"))
          None => None
        }
        subproblems.push({
          kind: required_string(sub, "type", "\{stage}.subproblem"),
          detail: match optional_string(sub, "detail", "\{stage}.subproblem") {
            Some(text) => text
            None => ""
          },
          identifier,
        })
      }
    Some(_) => raise malformed(stage, "field `subproblems` must be an array")
    None => ()
  }
  let status = match fields.get("status") {
    Some(Number(number, ..)) => Some(number.to_int())
    Some(Null) | None => None
    Some(_) => raise malformed(stage, "field `status` must be a number")
  }
  AcmeProblem::{
    kind: required_string(fields, "type", stage),
    title: optional_string(fields, "title", stage),
    detail: match optional_string(fields, "detail", stage) {
      Some(text) => text
      None => ""
    },
    status,
    instance: optional_string(fields, "instance", stage),
    subproblems,
  }
}

///|
pub fn AcmeProblem::decode(input : String) -> AcmeProblem raise AcmeError {
  problem_from_json(parse_json(input, "problem"), "problem")
}

///|
fn optional_problem(
  fields : Map[String, Json],
  name : String,
  stage : String,
) -> AcmeProblem? raise AcmeError {
  match fields.get(name) {
    Some(Null) | None => None
    Some(value) => Some(problem_from_json(value, "\{stage}.\{name}"))
  }
}

///|
fn challenge_from_json(
  value : Json,
  stage : String,
) -> Challenge raise AcmeError {
  let fields = object_at(value, stage)
  Challenge::{
    kind: ChallengeKind::parse(required_string(fields, "type", stage)),
    url: required_string(fields, "url", stage),
    status: ResourceStatus::parse(required_string(fields, "status", stage)),
    token: required_string(fields, "token", stage),
    validated: optional_string(fields, "validated", stage),
    problem: optional_problem(fields, "error", stage),
  }
}

///|
pub fn Challenge::decode(input : String) -> Challenge raise AcmeError {
  challenge_from_json(parse_json(input, "challenge"), "challenge")
}

///|
pub fn Authorization::decode(
  input : String,
  url~ : String,
) -> Authorization raise AcmeError {
  let fields = object_at(parse_json(input, "authorization"), "authorization")
  let challenges : Array[Challenge] = []
  match fields.get("challenges") {
    Some(Array(values)) =>
      for value in values {
        challenges.push(challenge_from_json(value, "authorization.challenges"))
      }
    Some(_) =>
      raise malformed("authorization", "field `challenges` must be an array")
    None => raise malformed("authorization", "missing array field `challenges`")
  }
  Authorization::{
    url,
    identifier: match fields.get("identifier") {
      Some(value) => decode_identifier(value, "authorization.identifier")
      None => raise malformed("authorization", "missing `identifier`")
    },
    status: ResourceStatus::parse(
      required_string(fields, "status", "authorization"),
    ),
    expires: optional_string(fields, "expires", "authorization"),
    wildcard: optional_bool(fields, "wildcard", "authorization", false),
    challenges,
  }
}

///|
pub fn Authorization::find_challenge(
  self : Authorization,
  kind : ChallengeKind,
) -> Challenge? {
  for challenge in self.challenges {
    if challenge.kind == kind {
      return Some(challenge)
    }
  }
  None
}
