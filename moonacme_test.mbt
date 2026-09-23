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
