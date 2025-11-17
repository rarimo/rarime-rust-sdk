use api::errors::ApiError;
use base64::DecodeError;
use contracts::errors::ContractsError;
use hex::FromHexError;
use num_bigint::ParseBigIntError;
use proofs::ProofError;
use std::num::ParseIntError;
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
    #[error("ASN1 routing error: {0}")]
    ASN1RouteError(String),
    #[error("Empty DER data: expected at least one block")]
    EmptyDer,
    #[error("Decoding ASN1 error: {0}")]
    ASN1DecodeError(#[from] simple_asn1::ASN1DecodeErr),
    #[error("Encoding ASN1 error: {0}")]
    ASN1EncodeError(#[from] simple_asn1::ASN1EncodeErr),
    #[error(transparent)]
    ContractError(ContractsError),
    #[error("OID operation error: {0}")]
    OIDError(const_oid::Error),
    #[error("Generate proof error: {0}")]
    ProveError(#[from] ProofError),
    #[error("Api call error: {0}")]
    ApiError(#[from] ApiError),
    #[error("Decode hex error: {0}")]
    DecodeHexError(#[from] FromHexError),
    #[error("Profile key error: {0}")]
    ProfileKeyError(String),
    #[error("Setup SDK process error: {0}")]
    SetupSDKError(String),
    #[error("Failed parse bigint error: {0}")]
    ParseBigIntError(#[from] ParseBigIntError),
    #[error("Failed parse int error: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("Failed parse bigint error: {0}")]
    ValidationError(String),
}
