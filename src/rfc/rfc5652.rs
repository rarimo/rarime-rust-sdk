use asn1::*;

use super::{
    Any,
    rfc5280::{AlgorithmIdentifier, Certificate, CertificateList, CertificateSerialNumber, Name},
};

type CMSVersion = i64;

type DigestAlgorithmIdentifiers<'a> = SetOf<'a, DigestAlgorithmIdentifier>;

type CertificateChoices<'a> = Choice1<Certificate<'a>>;

type CertificateSet<'a> = SetOf<'a, CertificateChoices<'a>>;

type RevocationInfoChoices<'a> = SetOf<'a, RevocationInfoChoice<'a>>;

type SubjectKeyIdentifier<'a> = &'a [u8];

type SignerIdentifier<'a> = Choice2<IssuerAndSerialNumber<'a>, SubjectKeyIdentifier<'a>>;

type AttributeValue<'a> = Any<'a>;

type SignedAttributes<'a> = SetOf<'a, Attribute<'a>>;

type UnsignedAttributes<'a> = SetOf<'a, Attribute<'a>>;

type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

type SignatureValue<'a> = &'a [u8];

type SignerInfos<'a> = SetOf<'a, SignerInfo<'a>>;

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
    pub signer_infos: SignerInfos<'a>,
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
    #[implicit(0)]
    pub signed_attrs: Option<SignedAttributes<'a>>,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub signature: SignatureValue<'a>,
    #[implicit(1)]
    pub unsigned_attrs: Option<UnsignedAttributes<'a>>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct IssuerAndSerialNumber<'a> {
    pub issuer: Name<'a>,
    pub serial_number: CertificateSerialNumber,
}

#[derive(Asn1Read, Asn1Write)]
pub struct Attribute<'a> {
    attr_type: ObjectIdentifier,
    attr_values: SetOf<'a, AttributeValue<'a>>,
}
