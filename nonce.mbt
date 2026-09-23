///|
/// A small in-memory pool of replay nonces. Nonces are consumed exactly once;
/// duplicates from repeated header processing are ignored.
pub struct NoncePool {
  values : Array[String]
}

///|
pub fn NoncePool::new() -> NoncePool {
  { values: [], }
}

///|
pub fn NoncePool::length(self : NoncePool) -> Int {
  self.values.length()
}

///|
pub fn NoncePool::offer(self : NoncePool, nonce : String) -> Bool {
  if nonce.length() == 0 {
    return false
  }
  for existing in self.values {
    if existing == nonce {
      return false
    }
  }
  self.values.push(nonce)
  true
}

///|
pub fn NoncePool::take(self : NoncePool) -> String? {
  self.values.pop()
}

///|
pub fn NoncePool::clear(self : NoncePool) -> Unit {
  self.values.clear()
}

///|
pub(all) struct Header {
  name : String
  value : String
} derive(Eq, Debug)

///|
/// Header names are case-insensitive. The final Replay-Nonce wins if a broken
/// intermediary duplicates it, matching the way most HTTP clients expose
/// repeated scalar headers.
pub fn replay_nonce(headers : Array[Header]) -> String? {
  let mut found : String? = None
  for header in headers {
    if header.name.to_lower() == "replay-nonce" && header.value.length() > 0 {
      found = Some(header.value)
    }
  }
  found
}

///|
pub(all) struct RetryPolicy {
  max_bad_nonce_retries : Int
  base_delay_ms : Int
  max_delay_ms : Int
} derive(Eq, Debug)

///|
pub fn RetryPolicy::default() -> RetryPolicy {
  { max_bad_nonce_retries: 3, base_delay_ms: 100, max_delay_ms: 2000, }
}

///|
pub(all) enum RetryDecision {
  RetryNow(String)
  FetchFreshNonce
  Stop(AcmeError)
} derive(Eq, Debug)

///|
pub fn is_bad_nonce(problem : AcmeProblem) -> Bool {
  problem.kind == "urn:ietf:params:acme:error:badNonce" ||
  problem.kind == "badNonce"
}

///|
/// Decide what to do after a failed signed request. The attempt number is
/// zero-based and counts earlier badNonce retries, not the initial request.
pub fn decide_bad_nonce_retry(
  problem : AcmeProblem,
  response_nonce : String?,
  attempt : Int,
  policy : RetryPolicy,
) -> RetryDecision {
  if !is_bad_nonce(problem) {
    return Stop(AcmeError::Protocol(problem~))
  }
  if attempt >= policy.max_bad_nonce_retries {
    return Stop(AcmeError::RetryExhausted(attempts=attempt))
  }
  match response_nonce {
    Some(nonce) if nonce.length() > 0 => RetryNow(nonce)
    _ => FetchFreshNonce
  }
}

///|
/// Bounded exponential backoff for polling order and authorization resources.
pub fn retry_delay_ms(attempt : Int, policy : RetryPolicy) -> Int {
  if attempt <= 0 {
    return policy.base_delay_ms
  }
  let mut delay = policy.base_delay_ms
  for _ in 0..<attempt {
    if delay >= policy.max_delay_ms || delay > policy.max_delay_ms / 2 {
      return policy.max_delay_ms
    }
    delay = delay * 2
  }
  delay
}
