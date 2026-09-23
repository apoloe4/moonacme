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
