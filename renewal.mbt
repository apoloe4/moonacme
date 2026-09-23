///|
pub(all) struct RenewalPolicy {
  renew_before_seconds : Int64
  minimum_lifetime_seconds : Int64
} derive(Eq, Debug)

///|
pub fn RenewalPolicy::default() -> RenewalPolicy {
  {
    renew_before_seconds: 30L * 24L * 60L * 60L,
    minimum_lifetime_seconds: 60L * 60L,
  }
}

///|
/// Optional renewal window returned by an ACME Renewal Information endpoint.
pub(all) struct RenewalWindow {
  start : Int64
  end : Int64
} derive(Eq, Debug)

///|
pub(all) enum RenewalDecision {
  NotYetValid
  RenewNow(String)
  ScheduleAt(Int64)
  InvalidCertificateWindow
  InvalidRenewalWindow
} derive(Eq, Debug)

///|
/// Plan renewal from caller-provided Unix seconds. The function reads no clock,
/// so applications can test expiry boundaries and inject their own time source.
pub fn plan_renewal(
  now : Int64,
  not_before : Int64,
  not_after : Int64,
  policy : RenewalPolicy,
  suggested? : RenewalWindow,
) -> RenewalDecision {
  if not_after <= not_before ||
    not_after - not_before < policy.minimum_lifetime_seconds {
    return InvalidCertificateWindow
  }
  if now < not_before {
    return NotYetValid
  }
  if now >= not_after {
    return RenewNow("certificate expired")
  }
  match suggested {
    Some(window) => {
      if window.end <= window.start || window.start >= not_after {
        return InvalidRenewalWindow
      }
      if now >= window.start {
        return RenewNow("inside server suggested renewal window")
      }
      ScheduleAt(window.start)
    }
    None => {
      let scheduled = not_after - policy.renew_before_seconds
      if now >= scheduled {
        RenewNow("inside local renewal window")
      } else {
        ScheduleAt(scheduled)
      }
    }
  }
}
