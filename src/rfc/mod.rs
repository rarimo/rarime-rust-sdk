pub mod rfc5280;
pub mod rfc5652;

use asn1::*;

#[derive(Asn1Read, Asn1Write)]
pub enum Any<'a> {
    OctetString(&'a [u8]),
    ObjectIdentifier(ObjectIdentifier),
    UtcTime(UtcTime),
}

#[derive(Asn1Read, Asn1Write, Debug)]
pub struct RsaPublicKey {
    pub modulus: OwnedBigInt,
    pub exponent: i64,
}

#[derive(Asn1Read, Asn1Write, Clone, Debug)]
pub struct ECDSAParameters<'a> {
    pub version: u64,
    pub field_id: ECDSAFieldID,
    pub curve: ECDSACurve<'a>,
    pub g: &'a [u8],
    pub n: OwnedBigUint,
    pub h: OwnedBigUint,
}

#[derive(Asn1Read, Asn1Write, Clone, Debug)]
pub struct ECDSAFieldID {
    pub field_type: ObjectIdentifier,
    pub data: OwnedBigUint,
}

#[derive(Asn1Read, Asn1Write, Clone, Debug)]
pub struct ECDSACurve<'a> {
    pub a: &'a [u8],
    pub b: &'a [u8],
}
