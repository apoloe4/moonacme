///|
/// The next protocol operation implied by an order resource. Applications can
/// persist this value and resume without duplicating ACME state logic.
pub(all) enum OrderAction {
  FetchAuthorizations(Array[String])
  Finalize(String)
  Poll(String)
  DownloadCertificate(String)
  Stop(AcmeProblem?)
} derive(Eq, Debug)

///|
/// Plan the next operation from the server-owned order status.
pub fn Order::next_action(self : Order) -> OrderAction raise AcmeError {
  match self.status {
    Pending => FetchAuthorizations(self.authorization_urls)
    Ready => {
      if self.finalize_url.length() == 0 {
        raise AcmeError::InvalidState(
          expected="order with finalize URL",
          actual="ready order without finalize URL",
        )
      }
      Finalize(self.finalize_url)
    }
    Processing => Poll(self.url)
    Valid =>
      match self.certificate_url {
        Some(url) => DownloadCertificate(url)
        None => Poll(self.url)
      }
    Invalid | Deactivated | Revoked | Expired => Stop(self.problem)
    Unknown(value) =>
      raise AcmeError::Unsupported(feature="unknown order status: " + value)
  }
}

///|
pub(all) enum AuthorizationAction {
  Provision(Array[Challenge])
  PollAuthorization(String)
  AuthorizationComplete
  AuthorizationStopped(AcmeProblem?)
} derive(Eq, Debug)

///|
/// Plan challenge provisioning or polling for an authorization. Pending
/// authorizations expose only challenges the server has not already rejected.
pub fn Authorization::next_action(
  self : Authorization,
) -> AuthorizationAction raise AcmeError {
  match self.status {
    Pending => {
      let usable = []
      for challenge in self.challenges {
        match challenge.status {
          Pending => usable.push(challenge)
          _ => ()
        }
      }
      if usable.length() == 0 {
        raise AcmeError::InvalidState(
          expected="pending authorization with a pending challenge",
          actual="pending authorization without usable challenges",
        )
      }
      Provision(usable)
    }
    Processing | Ready => PollAuthorization(self.url)
    Valid => AuthorizationComplete
    Invalid | Deactivated | Revoked | Expired => AuthorizationStopped(None)
    Unknown(value) =>
      raise AcmeError::Unsupported(
        feature="unknown authorization status: " + value,
      )
  }
}
