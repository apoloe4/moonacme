///|
test "resource status retains unknown values" {
  let known = @moonacme.ResourceStatus::parse("ready")
  let future = @moonacme.ResourceStatus::parse("paused")
  assert_eq(known.text(), "ready")
  assert_eq(future.text(), "paused")
}

///|
test "challenge type retains extensions" {
  let http = @moonacme.ChallengeKind::parse("http-01")
  let custom = @moonacme.ChallengeKind::parse("device-attest-01")
  assert_eq(http.text(), "http-01")
  assert_eq(custom.text(), "device-attest-01")
}

///|
test "directory decoder reads endpoints and metadata" {
  let directory = @moonacme.Directory::decode(
    (
      #|{
      #|  "newNonce":"https://ca.test/nonce",
      #|  "newAccount":"https://ca.test/account",
      #|  "newOrder":"https://ca.test/order",
      #|  "revokeCert":"https://ca.test/revoke",
      #|  "keyChange":"https://ca.test/key-change",
      #|  "meta":{"termsOfService":"https://ca.test/terms","externalAccountRequired":true}
      #|}
    ),
  )
  assert_eq(directory.new_order, "https://ca.test/order")
  assert_eq(directory.external_account_required, true)
  assert_eq(directory.terms_of_service, Some("https://ca.test/terms"))
}

///|
test "new order encoding is deterministic" {
  let body = @moonacme.encode_new_order([
    { kind: "dns", value: "example.com", },
    { kind: "dns", value: "www.example.com", },
  ])
  assert_eq(
    body, "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.com\"},{\"type\":\"dns\",\"value\":\"www.example.com\"}]}",
  )
}

///|
test "order decoder keeps server resource URL" {
  let order = @moonacme.Order::decode(
    (
      #|{"status":"pending","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":["https://ca.test/authz/1"],"finalize":"https://ca.test/order/1/finalize"}
    ),
    url="https://ca.test/order/1",
  )
  assert_eq(order.url, "https://ca.test/order/1")
  assert_eq(order.authorization_urls.length(), 1)
  assert_eq(order.identifiers[0].value, "example.com")
}

///|
test "malformed directory is rejected" {
  try @moonacme.Directory::decode("{\"newNonce\":7}") |> ignore catch {
    @moonacme.AcmeError::Malformed(..) => ()
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected malformed directory")
  }
}

///|
test "HTTP-01 resource uses the well-known path" {
  let token = "LoqXcYV8q5ONbR2H3wq5wg"
  let resource = @moonacme.Http01Resource::new(token, "thumbprint")
  assert_eq(resource.path, "/.well-known/acme-challenge/" + token)
  assert_eq(resource.body, token + ".thumbprint")
}

///|
test "DNS-01 vector hashes key authorization" {
  let value = @moonacme.dns01_txt_value("LoqXcYV8q5ONbR2H3wq5wg", "thumbprint")
  assert_eq(value, "DgIXTOEwHQ4sMRiB-TPIe2UYP5rbdQEs1wvRjoHZVZU")
}

///|
test "DNS-01 removes wildcard label from owner name" {
  assert_eq(
    @moonacme.dns01_record_name("*.example.com"),
    "_acme-challenge.example.com",
  )
}

///|
test "challenge token rejects padding and short values" {
  assert_eq(@moonacme.validate_challenge_token("short"), false)
  assert_eq(
    @moonacme.validate_challenge_token("LoqXcYV8q5ONbR2H3wq5wg="),
    false,
  )
}

///|
test "JWS draft exposes exact signing input" {
  let draft = @moonacme.JwsDraft::new(
    algorithm="ES256",
    nonce="nonce-1",
    url="https://ca.test/new-account",
    payload="{\"termsOfServiceAgreed\":true}",
    binding=@moonacme.AccountBinding::PublicJwk(
      "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"x\",\"y\":\"y\"}",
    ),
  )
  assert_eq(draft.signing_input, draft.protected_b64 + "." + draft.payload_b64)
  assert_true(draft.payload_b64.length() > 0)
}

///|
test "POST-as-GET has an empty encoded payload" {
  let draft = @moonacme.JwsDraft::post_as_get(
    algorithm="ES256",
    nonce="nonce-2",
    url="https://ca.test/order/1",
    kid="https://ca.test/account/7",
  )
  assert_eq(draft.payload_b64, "")
  assert_true(draft.signing_input.has_suffix("."))
}

///|
test "JWS body encodes raw signature without padding" {
  let draft = @moonacme.JwsDraft::post_as_get(
    algorithm="ES256",
    nonce="nonce-3",
    url="https://ca.test/order/1",
    kid="https://ca.test/account/7",
  )
  let body = draft.finish(b"abc"[:])
  assert_true(body.contains("\"signature\":\"YWJj\""))
}

///|
test "JWS rejects a missing nonce" {
  try
    @moonacme.JwsDraft::post_as_get(
      algorithm="ES256",
      nonce="",
      url="https://ca.test/order/1",
      kid="https://ca.test/account/7",
    )
    |> ignore
  catch {
    @moonacme.AcmeError::MissingNonce => ()
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected missing nonce")
  }
}

///|
test "nonce pool consumes each nonce once" {
  let pool = @moonacme.NoncePool::new()
  assert_eq(pool.offer("n-1"), true)
  assert_eq(pool.offer("n-1"), false)
  assert_eq(pool.offer("n-2"), true)
  assert_eq(pool.take(), Some("n-2"))
  assert_eq(pool.take(), Some("n-1"))
  assert_eq(pool.take(), None)
}

///|
test "Replay-Nonce header lookup is case insensitive" {
  let nonce = @moonacme.replay_nonce([
    { name: "content-type", value: "application/json", },
    { name: "Replay-Nonce", value: "fresh-1", },
  ])
  assert_eq(nonce, Some("fresh-1"))
}

///|
test "badNonce uses response nonce when present" {
  let problem : @moonacme.AcmeProblem = {
    kind: "urn:ietf:params:acme:error:badNonce",
    title: None,
    detail: "retry",
    status: Some(400),
    instance: None,
    subproblems: [],
  }
  let decision = @moonacme.decide_bad_nonce_retry(
    problem,
    Some("fresh-2"),
    0,
    @moonacme.RetryPolicy::default(),
  )
  assert_true(decision is @moonacme.RetryDecision::RetryNow("fresh-2"))
}

///|
test "retry delay is exponential and bounded" {
  let policy : @moonacme.RetryPolicy = {
    max_bad_nonce_retries: 3,
    base_delay_ms: 100,
    max_delay_ms: 750,
  }
  assert_eq(@moonacme.retry_delay_ms(0, policy), 100)
  assert_eq(@moonacme.retry_delay_ms(2, policy), 400)
  assert_eq(@moonacme.retry_delay_ms(8, policy), 750)
}

///|
fn test_directory() -> @moonacme.Directory {
  {
    new_nonce: "https://ca.test/nonce",
    new_account: "https://ca.test/account",
    new_order: "https://ca.test/order",
    revoke_cert: "https://ca.test/revoke",
    key_change: "https://ca.test/key-change",
    renewal_info: None,
    terms_of_service: None,
    website: None,
    external_account_required: false,
  }
}

///|
test "session plans account then order with distinct nonces" {
  let session = @moonacme.AcmeSession::new(
    directory=test_directory(),
    algorithm="ES256",
    public_jwk="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"x\",\"y\":\"y\"}",
  )
  assert_eq(session.offer_nonce("nonce-account"), true)
  let account = session.prepare_new_account(["mailto:admin@example.com"], true)
  assert_eq(account.url, "https://ca.test/account")
  session.bind_account("https://ca.test/account/1")
  assert_eq(session.offer_nonce("nonce-order"), true)
  let order = session.prepare_new_order([{ kind: "dns", value: "example.com", }])
  assert_eq(order.url, "https://ca.test/order")
  assert_eq(session.account_url(), Some("https://ca.test/account/1"))
}

///|
test "session refuses KID operation before registration" {
  let session = @moonacme.AcmeSession::new(
    directory=test_directory(),
    algorithm="ES256",
    public_jwk="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"x\",\"y\":\"y\"}",
  )
  session.offer_nonce("nonce-order") |> ignore
  try
    session.prepare_new_order([{ kind: "dns", value: "example.com", }])
    |> ignore
  catch {
    @moonacme.AcmeError::InvalidState(..) => ()
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid state")
  }
}

///|
test "finished request has ACME content type" {
  let session = @moonacme.AcmeSession::new(
    directory=test_directory(),
    algorithm="ES256",
    public_jwk="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"x\",\"y\":\"y\"}",
  )
  session.offer_nonce("nonce-account") |> ignore
  let request = session.prepare_new_account([], true).finish(b"signature"[:])
  assert_eq(request.verb, "POST")
  assert_eq(request.headers[0].value, "application/jose+json")
}

///|
test "authorization decoder selects HTTP challenge" {
  let authorization = @moonacme.Authorization::decode(
    (
      #|{"identifier":{"type":"dns","value":"example.com"},"status":"pending","wildcard":false,"challenges":[{"type":"http-01","url":"https://ca.test/challenge/1","status":"pending","token":"LoqXcYV8q5ONbR2H3wq5wg"},{"type":"dns-01","url":"https://ca.test/challenge/2","status":"pending","token":"LoqXcYV8q5ONbR2H3wq5wg"}]}
    ),
    url="https://ca.test/authz/1",
  )
  let challenge = authorization.find_challenge(@moonacme.ChallengeKind::Http01)
  assert_true(challenge is Some(_))
  assert_eq(challenge.unwrap().url, "https://ca.test/challenge/1")
}

///|
test "problem decoder preserves identifier subproblems" {
  let problem = @moonacme.AcmeProblem::decode(
    (
      #|{"type":"urn:ietf:params:acme:error:malformed","detail":"one identifier failed","status":400,"subproblems":[{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"not allowed","identifier":{"type":"dns","value":"bad.example"}}]}
    ),
  )
  assert_eq(problem.status, Some(400))
  assert_eq(problem.subproblems.length(), 1)
  assert_eq(problem.subproblems[0].identifier.unwrap().value, "bad.example")
}

///|
test "renewal planner schedules thirty days before expiry" {
  let day = 24L * 60L * 60L
  let decision = @moonacme.plan_renewal(
    10L * day,
    0L,
    90L * day,
    @moonacme.RenewalPolicy::default(),
  )
  assert_eq(decision, @moonacme.RenewalDecision::ScheduleAt(60L * day))
}

///|
test "renewal planner honors server suggested window" {
  let decision = @moonacme.plan_renewal(
    700L,
    0L,
    1000L,
    { renew_before_seconds: 300L, minimum_lifetime_seconds: 1L, },
    suggested={ start: 600L, end: 800L, },
  )
  assert_eq(
    decision,
    @moonacme.RenewalDecision::RenewNow(
      "inside server suggested renewal window",
    ),
  )
}

///|
test "renewal planner rejects inverted certificate window" {
  assert_eq(
    @moonacme.plan_renewal(10L, 20L, 10L, @moonacme.RenewalPolicy::default()),
    @moonacme.RenewalDecision::InvalidCertificateWindow,
  )
}
