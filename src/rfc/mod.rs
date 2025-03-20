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

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `TeletexString`.  A `TeletexString` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeletexString<'a>(&'a str);

impl<'a> TeletexString<'a> {
    pub fn new(s: &'a str) -> Option<TeletexString<'a>> {
        Some(TeletexString(s))
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<TeletexString<'a>> {
        let string = match core::str::from_utf8(s).ok() {
            Some(string) => string,
            None => return None,
        };

        Some(TeletexString(string))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for TeletexString<'a> {
    const TAG: Tag = Tag::primitive(0x14);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        TeletexString::new_from_bytes(data)
            .ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}

impl SimpleAsn1Writable for TeletexString<'_> {
    const TAG: Tag = Tag::primitive(0x14);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }
}

/// Type for use with `Parser.read_element` and `Writer.write_element` for
/// handling ASN.1 `IA5String`.  A `IA5String` contains an `&str`
/// with only valid characers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IA5String<'a>(&'a str);

impl<'a> IA5String<'a> {
    pub fn new(s: &'a str) -> Option<IA5String<'a>> {
        Some(IA5String(s))
    }

    fn new_from_bytes(s: &'a [u8]) -> Option<IA5String<'a>> {
        let string = match core::str::from_utf8(s).ok() {
            Some(string) => string,
            None => return None,
        };

        Some(IA5String(string))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> SimpleAsn1Readable<'a> for IA5String<'a> {
    const TAG: Tag = Tag::primitive(0x16);
    fn parse_data(data: &'a [u8]) -> ParseResult<Self> {
        IA5String::new_from_bytes(data).ok_or_else(|| ParseError::new(ParseErrorKind::InvalidValue))
    }
}

impl SimpleAsn1Writable for IA5String<'_> {
    const TAG: Tag = Tag::primitive(0x16);
    fn write_data(&self, dest: &mut WriteBuf) -> WriteResult {
        dest.push_slice(self.0.as_bytes())
    }
}
