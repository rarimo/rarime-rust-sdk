pub mod rfc5280;
pub mod rfc5652;

use asn1::*;

#[derive(Asn1Read, Asn1Write)]
pub enum Any<'a> {
    OctetString(&'a [u8]),
    ObjectIdentifier(ObjectIdentifier),
}
