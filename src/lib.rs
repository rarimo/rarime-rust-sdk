pub mod masters_certificate_pool;
pub mod passport;
pub mod rfc;

mod base64;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RarimeError {
    #[error("failed to parse asn1 data")]
    ASN1ParseError(#[from] asn1::ParseError),
    #[error("failed to perform RSA operation")]
    RSAError(#[from] rsa::errors::Error),
}
