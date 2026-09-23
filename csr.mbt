///|
/// A PKCS#10 certification request prepared for an external signer. Keeping
/// signing outside the protocol package lets applications use an HSM, a
/// platform keystore, or any MoonBit signature implementation.
pub(all) struct CsrDraft {
  request_info_der : Bytes
} derive(Eq, Debug)

///|
fn validate_dns_name(name : String) -> Unit raise AcmeError {
  if name.length() == 0 {
    raise malformed("csr", "DNS names must not be empty")
  }
  for c in name {
    if c.to_int() > 0x7f {
      raise malformed("csr", "DNS names must use ASCII or punycode")
    }
  }
}

///|
fn dns_general_name(name : String) -> Bytes raise AcmeError {
  validate_dns_name(name)
  @asn1.tlv(0x82, @utf8.encode(name[:]))
}

///|
/// Build the DER CertificationRequestInfo for a DNS certificate. The supplied
/// public key is a complete DER SubjectPublicKeyInfo value.
pub fn CsrDraft::new(
  subject_common_name : String,
  dns_names : Array[String],
  subject_public_key_info_der : BytesView,
) -> CsrDraft raise AcmeError {
  validate_dns_name(subject_common_name)
  if dns_names.length() == 0 {
    raise malformed("csr", "at least one DNS name is required")
  }
  if subject_public_key_info_der.length() == 0 {
    raise malformed("csr", "SubjectPublicKeyInfo must not be empty")
  }
  let common_name = @asn1.sequence([
    @asn1.oid([2, 5, 4, 3]),
    @asn1.utf8_string(subject_common_name),
  ])
  let subject = @asn1.sequence([@asn1.set_of([common_name])])
  let general_names = []
  for name in dns_names {
    general_names.push(dns_general_name(name))
  }
  let subject_alt_name = @asn1.sequence([
    @asn1.oid([2, 5, 29, 17]),
    @asn1.octet_string(@asn1.sequence(general_names)),
  ])
  let extensions = @asn1.sequence([subject_alt_name])
  let extension_request = @asn1.sequence([
    @asn1.oid([1, 2, 840, 113549, 1, 9, 14]),
    @asn1.set_of([extensions]),
  ])
  let attributes = @asn1.tlv(0xa0, extension_request)
  {
    request_info_der: @asn1.sequence([
      @asn1.integer(b"\x00"),
      subject,
      subject_public_key_info_der.to_owned(),
      attributes,
    ]),
  }
}

///|
/// Return the exact DER bytes that the certificate key must sign.
pub fn CsrDraft::signing_input(self : CsrDraft) -> BytesView {
  self.request_info_der[:]
}

///|
/// Assemble a complete PKCS#10 request from an ASN.1 DER ECDSA P-256/SHA-256
/// signature returned by the caller's signer.
pub fn CsrDraft::finish_ecdsa_sha256(
  self : CsrDraft,
  signature_der : BytesView,
) -> Bytes raise AcmeError {
  if signature_der.length() == 0 {
    raise malformed("csr", "signature must not be empty")
  }
  @asn1.sequence([
    self.request_info_der,
    @asn1.sequence([@asn1.oid([1, 2, 840, 10045, 4, 3, 2])]),
    @asn1.bit_string(signature_der.to_owned()),
  ])
}
