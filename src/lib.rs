pub mod masters_certificate_pool;
pub mod passport;
pub mod rfc;

mod base64;
mod document;
mod flow;
mod owned_cert;
mod treap_tree;
mod utils;

use ::base64::DecodeError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RarimeError {
    #[error("failed to parse asn1 data")]
    ASN1ParseError(#[from] asn1::ParseError),
    #[error("failed to write asn1 data")]
    ASN1WriteError(#[from] asn1::WriteError),
    #[error("failed to perform RSA operation")]
    RSAError(#[from] rsa::errors::Error),
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("X509 error: {0}")]
    X509Error(String),
    #[error("PEM error: {0}")]
    PemError(String),
    #[error("No certificates found")]
    NoCertificatesFound,
    #[error("UTF-8 error: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),
    #[error("decoding error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("Der error: {0}")]
    DerError(String),
    #[error("Unsupported type of pub key")]
    UnsupportedKey,
    #[error("Parsing DG15 error: {0}")]
    ParseDg15Error(anyhow::Error),
    #[error("Get passport key error: {0}")]
    GetPassportKeyError(anyhow::Error),
}
