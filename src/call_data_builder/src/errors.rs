use thiserror::Error;

#[derive(Error, Debug)]
pub enum CallDataBuilderError {
    // #[error("failed to parse asn1 data")]
    // ASN1ParseError(#[from] asn1::ParseError),
}
