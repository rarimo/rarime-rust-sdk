pub mod masters_certificate_pool;
pub mod passport;
pub mod rfc;

mod base64;
mod document;
mod owned_cert;
mod treap_tree;
mod utils;

use ::base64::DecodeError;
use contracts::ContractsError;
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
    #[error("Decoding error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("Der error: {0}")]
    DerError(String),
    #[error("Unsupported type of public key")]
    UnsupportedPassportKey,
    #[error("Parsing DG15 error: {0}")]
    ParseDg15Error(String),
    #[error("Get passport key error: {0}")]
    GetPassportKeyError(String),
    #[error("Generate private key error")]
    GeneratePrivateKeyError,
    #[error("Poseidon error: {0}")]
    PoseidonHashError(String),
    #[error("Contract error: {0}")]
    ContractCallError(#[from] ContractsError),
    #[error("{0}")]
    ASN1RouteError(String),
    #[error("Empty DER data: expected at least one block")]
    EmptyDer,
    #[error("Decoding ASN1 error: {0}")]
    ASN1DecodeError(#[from] simple_asn1::ASN1DecodeErr),
}
