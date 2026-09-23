///|
fn usage() -> Unit {
  println(
    (
      #|MoonACME helper
      #|
      #|Usage:
      #|  moon run cmd/main -- http01-path <token>
      #|  moon run cmd/main -- http01-body <token> <account-thumbprint>
      #|  moon run cmd/main -- dns01-name <domain>
      #|  moon run cmd/main -- dns01-value <token> <account-thumbprint>
      #|
      #|The library remains transport-neutral; these commands print values that
      #|can be copied into a web server or DNS provider.
    ),
  )
}

///|
fn run(args : Array[String]) -> Unit raise @moonacme.AcmeError {
  match args {
    [_, "http01-path", token] => println(@moonacme.http01_path(token))
    [_, "http01-body", token, thumbprint] =>
      println(@moonacme.key_authorization(token, thumbprint))
    [_, "dns01-name", domain] => println(@moonacme.dns01_record_name(domain))
    [_, "dns01-value", token, thumbprint] =>
      println(@moonacme.dns01_txt_value(token, thumbprint))
    _ => usage()
  }
}

///|
fn main {
  run(@env.args()) catch {
    error => println("error: " + error.message())
  }
}
