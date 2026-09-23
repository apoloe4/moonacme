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
