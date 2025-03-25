use asn1::*;

use crate::{RarimeError, rfc};

use super::{ECDSAParameters, RsaPublicKey, TeletexString};

pub type Version = i64;

pub type CertificateSerialNumber = OwnedBigInt;

pub type Name<'a> = Choice1<RDNSequence<'a>>;

pub type RDNSequence<'a> = SequenceOf<'a, RelativeDistinguishedName<'a>>;

pub type RelativeDistinguishedName<'a> = SetOf<'a, AttributeTypeAndValue<'a>>;

pub type Time = Choice2<UtcTime, GeneralizedTime>;

pub type UniqueIdentifier<'a> = BitString<'a>;

pub type Extensions<'a> = SequenceOf<'a, Extension<'a>>;

pub type RevokedCertificatess<'a> = SequenceOf<'a, RevokedCertificate<'a>>;

#[derive(Asn1Read, Asn1Write)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString<'a>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct TBSCertificate<'a> {
    #[default(0)]
    #[explicit(0)]
    pub version: Version,
    pub serial_number: CertificateSerialNumber,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    #[implicit(1)]
    pub issuer_unique_id: Option<UniqueIdentifier<'a>>,
    #[implicit(2)]
    pub subject_unique_id: Option<UniqueIdentifier<'a>>,
    #[explicit(3)]
    pub extensions: Option<Extensions<'a>>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct CertificateList<'a> {
    pub tbs_cert_list: TBSCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: BitString<'a>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct TBSCertList<'a> {
    pub version: Option<Version>,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name<'a>,
    pub this_update: Time,
    pub next_update: Option<Time>,
    pub revoked_certificates: Option<RevokedCertificatess<'a>>,
    #[explicit(0)]
    pub crl_extensions: Option<Extensions<'a>>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct RevokedCertificate<'a> {
    pub user_certificate: CertificateSerialNumber,
    pub revocation_date: Time,
    pub crl_entry_extensions: Option<Extensions<'a>>,
}

#[derive(Asn1Read, Asn1Write, Clone)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
}

impl AlgorithmIdentifier {
    pub fn get_signature_type(&self) -> Option<rfc::SignatureType> {
        match self.algorithm {
            rfc::RSA_WITH_SHA1
            | rfc::RSA_WITH_SHA256
            | rfc::RSA_WITH_SHA384
            | rfc::RSA_WITH_SHA512 => Some(rfc::SignatureType::RSA),
            rfc::ECDSA_WITH_SHA1
            | rfc::ECDSA_WITH_SHA256
            | rfc::ECDSA_WITH_SHA384
            | rfc::ECDSA_WITH_SHA512 => Some(rfc::SignatureType::ECDSA),
            _ => None,
        }
    }
}

#[derive(Asn1Read, Asn1Write)]
pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

#[derive(Asn1Read, Asn1Write, Clone)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: PublicKeyAlgorithmIdentifier<'a>,
    pub subject_public_key: BitString<'a>,
}

impl SubjectPublicKeyInfo<'_> {
    pub fn get_rsa_public_key(&self) -> Result<RsaPublicKey, RarimeError> {
        Ok(parse_single::<RsaPublicKey>(
            self.subject_public_key.clone().as_bytes(),
        )?)
    }
}

#[derive(Asn1Read, Asn1Write)]
pub struct AttributeTypeAndValue<'a> {
    pub attribute_type: ObjectIdentifier,
    pub attribute_value: DirectoryString<'a>,
}

#[derive(Asn1Read, Asn1Write)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    #[default(false)]
    pub pubcritical: bool,
    pub extn_value: &'a [u8],
}

#[derive(Asn1Read, Asn1Write, Clone)]
pub struct PublicKeyAlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub paramethers: Option<PublicKeyAlgorithmParamethers<'a>>,
}

impl PublicKeyAlgorithmIdentifier<'_> {
    pub fn get_signature_type(&self) -> Option<rfc::SignatureType> {
        match self.algorithm {
            rfc::RSA_PUBLIC_KEY_OID => Some(rfc::SignatureType::RSA),
            rfc::ECDSA_PUBLIC_KEY_OID => Some(rfc::SignatureType::ECDSA),
            _ => None,
        }
    }
}

#[derive(Asn1Read, Asn1Write, Clone)]
pub enum PublicKeyAlgorithmParamethers<'a> {
    ECDSAPublicKeyParams(ECDSAParameters<'a>),
}

#[derive(Asn1Read, Asn1Write)]
pub enum DirectoryString<'a> {
    PrintableString(PrintableString<'a>),
    UniversalString(UniversalString<'a>),
    UTF8String(Utf8String<'a>),
    BMPString(BMPString<'a>),
    TeletexString(TeletexString<'a>),
    IA5String(IA5String<'a>),
}
