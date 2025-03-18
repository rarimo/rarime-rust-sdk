pub mod passport;

mod base64;
mod sod;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RarimeError {
    #[error("failed to parse asn1 data")]
    ASN1ParseError(#[from] asn1::ParseError)
}

