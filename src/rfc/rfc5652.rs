use asn1::*;

use super::rfc5280::{Certificate, CertificateList, CertificateSerialNumber, Name};

type CMSVersion = i64;

type DigestAlgorithmIdentifiers<'a> = SetOf<'a, DigestAlgorithmIdentifier>;

type CertificateChoices<'a> = Choice1<Certificate<'a>>;

type CertificateSet<'a> = SetOf<'a, CertificateChoices<'a>>;

type RevocationInfoChoices<'a> = SetOf<'a, RevocationInfoChoice<'a>>;

type SubjectKeyIdentifier<'a> = &'a [u8];

type SignerIdentifier<'a> = Choice2<IssuerAndSerialNumber<'a>, SubjectKeyIdentifier<'a>>;

#[derive(Asn1Read, Asn1Write)]
pub struct SOD<'a> {
    pub content_type: ObjectIdentifier,
    #[implicit(0)]
    pub content: Option<OctetStringEncoded<SignedData<'a>>>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct SignedData<'a> {
    pub version: CMSVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers<'a>,
    pub encap_content_info: EncapsulatedContentInfo<'a>,
    #[implicit[0]]
    pub certificates: Option<CertificateSet<'a>>,
    #[implicit[1]]
    pub crls: Option<RevocationInfoChoices<'a>>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct DigestAlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
}

#[derive(Asn1Read, Asn1Write)]
pub struct EncapsulatedContentInfo<'a> {
    pub e_content_type: ObjectIdentifier,
    #[explicit(0)]
    pub e_content: Option<&'a [u8]>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct RevocationInfoChoice<'a> {
    pub crl: CertificateList<'a>,
    #[implicit(1)]
    pub other: Option<OtherRevocationInfoFormat>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct OtherRevocationInfoFormat {
    pub other_rev_info_format: ObjectIdentifier,
}

#[derive(Asn1Read, Asn1Write)]
pub struct SignerInfo<'a> {
    pub version: CMSVersion,
    pub sid: SignerIdentifier<'a>,
    pub digest_algorithm: DigestAlgorithmIdentifier,
}

#[derive(Asn1Read, Asn1Write)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: Name<'a>,
    pub serial_number: CertificateSerialNumber,
}
